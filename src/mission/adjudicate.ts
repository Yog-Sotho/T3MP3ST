/**
 * Shared adjudicate + cite-check (Phase-0 #5).
 *
 * The single, PURE home for the two safety primitives the disclosure CLI
 * (scripts/refute-finding.mjs) and the live pack-audit path
 * (src/mission/audit-coordinator.ts, per the pack-hunt design)
 * must SHARE so the two paths can't drift:
 *
 *   1. adjudicate(verdicts)            — deterministic strict-majority tally.
 *   2. guardExistsInSource(guard, src) — deterministic cite-check that a cited
 *                                        killing guard actually appears in source.
 *
 * Both are ported verbatim (in behavior) from scripts/refute-finding.mjs. The
 * ONLY intentional change: guardExistsInSource here takes the SOURCE TEXT as its
 * second argument (injected by the caller) and returns a plain boolean, so this
 * module stays pure — no `fs`, no repo-root, no I/O. The refute CLI reads the file
 * and passes the text in; the live path passes the already-loaded source.
 *
 * Why this matters (the pack-hunt design HT-2): a false REFUTE built on a
 * hallucinated "killing guard" kills a real 0-day AND the dedup guard then
 * permanently blocks re-finding it. So the cite-check is MANDATORY, non-optional:
 * a REFUTED vote whose killing_guard is not in source is downgraded to SURVIVED
 * before the tally (downgradeUnverifiedRefutes()).
 *
 * No engine imports — pure functions only.
 */

// =============================================================================
// TYPES
// =============================================================================

/** The two decisive verdicts a single refuter/auditor can cast. */
export type RefuterVerdict = 'REFUTED' | 'SURVIVED';

/** The adjudicated panel verdict. */
export type PanelVerdict = 'REFUTED' | 'SURVIVED' | 'INCONCLUSIVE';

/**
 * A cited guard the refuter claims dominates the path from untrusted input to the
 * sink (a bounds check, a normalize pre-pass, a CA binding, ...). `quote` is the
 * guard's source text, used by guardExistsInSource() as the cite-check anchor.
 */
export interface KillingGuard {
  file: string;
  line: number;
  quote: string;
}

/**
 * One refuter/auditor vote. A `null` entry (a crashed/timed-out refuter) or a
 * `verdict` outside {REFUTED,SURVIVED} counts as an abstention — it never adds to
 * the refute count and never to the panel size.
 */
export interface RefuterVote {
  verdict: RefuterVerdict | string;
  killing_guard?: KillingGuard | null;
  /** Populated by downgradeUnverifiedRefutes when a REFUTED vote fails the cite-check. */
  original_verdict?: RefuterVerdict;
  guard_check?: 'verified' | 'unverified';
  [k: string]: unknown;
}

/** The deterministic tally result. */
export interface Adjudication {
  verdict: PanelVerdict;
  /** Number of counted REFUTED votes (post-downgrade, if the caller downgraded). */
  refutedCount: number;
  /** Size of the valid (non-abstaining) panel. */
  total: number;
  /** The killing guards from the counted REFUTED votes, nulls dropped. */
  killing_guards: KillingGuard[];
}

// =============================================================================
// ADJUDICATE — deterministic strict-majority tally
// =============================================================================

/**
 * Tally refuter/auditor votes into a single panel verdict.
 *
 * Rules (ported from refute-finding.mjs `adjudicate`):
 *  - A vote is VALID only if verdict === 'REFUTED' || verdict === 'SURVIVED'.
 *    `null`, undefined, and any other verdict string (junk, abstention) are
 *    dropped — they count toward NEITHER the refute count NOR the panel size.
 *  - REFUTED requires a STRICT majority of the valid panel: refuted*2 > total.
 *    A tie (exactly half) does NOT refute — SURVIVED wins ties.
 *  - Empty valid panel (n === 0) → INCONCLUSIVE.
 *  - Otherwise → SURVIVED.
 *
 * NOTE: this is the tally ONLY. To honor the mandatory cite-check
 * (the pack-hunt design HT-2) the caller must first pass the votes through
 * downgradeUnverifiedRefutes() so a REFUTED built on a hallucinated guard has
 * already been turned into SURVIVED before it's counted here.
 */
export function adjudicate(verdicts: ReadonlyArray<RefuterVote | null | undefined>): Adjudication {
  // ⚡ BOLT OPTIMIZATION: Perform single-pass tallying over valid panel votes directly,
  // completely eliminating intermediate `.filter()` and `.map()` array allocations.
  let total = 0;
  let refutedCount = 0;
  const killing_guards: KillingGuard[] = [];

  for (let i = 0; i < verdicts.length; i++) {
    const v = verdicts[i];
    if (v !== null && v !== undefined && (v.verdict === 'REFUTED' || v.verdict === 'SURVIVED')) {
      total++;
      if (v.verdict === 'REFUTED') {
        refutedCount++;
        if (v.killing_guard !== null && v.killing_guard !== undefined) {
          killing_guards.push(v.killing_guard);
        }
      }
    }
  }

  const majorityRefuted = total > 0 && refutedCount * 2 > total; // STRICT majority
  return {
    verdict: total === 0 ? 'INCONCLUSIVE' : majorityRefuted ? 'REFUTED' : 'SURVIVED',
    refutedCount,
    total,
    killing_guards,
  };
}

// =============================================================================
// GUARD CITE-CHECK — deterministic, pure
// =============================================================================

const normalize = (s: string): string => String(s).replace(/\s+/g, '').toLowerCase();

// Strip the wrapping punctuation the operand char-class greedily absorbs — the `(` a comparison
// carries from `if (n > cap)`, and the trailing `)` — so a source operand `(n` / `cap)` compares
// EQUAL to a cited `n` / `cap`. Also strip a LEADING variable sigil (`$`/`@`/`%`, as in shell/Perl/PHP/
// Ruby) so a cited `n > cap` verifies against a source `$n > $cap`. Applied to BOTH cited and source
// operands, so any residue cancels out identically on each side.
const coreToken = (s: string): string => normalize(s).replace(/^[($@%\s]+/, '').replace(/[)\s;,]+$/, '');

// A comparison expression: `a OP b`, OP one of >= <= == != > < . The operand class allows the
// token chars real code uses around a comparison (identifiers, member access `a.b`, pointer
// `a->b`, calls `f()`, array `a[i]`). Pre-compiled global RegExp reused by resetting lastIndex=0.
const COMPARISON_SRC = '([\\w.()\\[\\]>_$@-]+)\\s*(>=|<=|==|!=|>|<)\\s*([\\w.()\\[\\]>_$@-]+)';
const COMPARISON_RE = new RegExp(COMPARISON_SRC);
// ⚡ BOLT OPTIMIZATION: Module-level pre-compiled global RegExp to avoid re-compiling RegExp per source line.
const COMPARISON_G_RE = new RegExp(COMPARISON_SRC, 'g');

// The operator seen when the SAME comparison is written with its operands reversed (`a > b` ≡ `b < a`).
// Used by the structural cite-check so a cited `a OP b` can verify against a source `b MIRROR[OP] a`.
// Equality/inequality are their own mirror; ordering operators flip.
const MIRROR_OP: Record<string, string> = { '>': '<', '<': '>', '>=': '<=', '<=': '>=', '==': '==', '!=': '!=' };

// A quote only counts as a *guard* for the SUBSTRING path (Path 1) if it carries real guard SYNTAX: an
// UNAMBIGUOUS comparison operator (>= <= == !=), a control-flow keyword, or a bounds/validate FUNCTION
// CALL (keyword immediately followed by `(`). This stops Path 1 from "verifying" a hallucinated guard
// that merely quotes one common source token like `length`. NOTE: bare `<` / `>` are DELIBERATELY
// excluded here — a single `<`/`>` is indistinguishable from a generic angle bracket at the substring
// level (a cited `vector < int` would otherwise match `std::vector<int>`), so `a < b` / `a > b` guards
// are verified only by the operand-checked structural path (Path 2), which captures the generic's `>`
// into the operand and rejects it.
const GUARD_SHAPE_RE =
  /(?:>=|<=|==|!=)|\b(?:if|else|return|break|continue|throw|goto)\b|\b(?:assert|clamp|min|max|bound|bounded|validate|sanitize|require|abort|reject|checked?|verify|ensure|limit)\s*\(/i;

/**
 * Per-language lexical traits: which comment + string forms a file uses, and whether it has `/…/`
 * REGEX literals. Distinguishing a JS regex `/…/` from a division `a / b` needs full JS grammar (four
 * hand-rolled scanners each leaked), so codeLinesOf never tries: for a regex-bearing language it just
 * blanks each line past its first `/` (any regex body dies with it — leak-free by construction); a
 * no-regex language keeps divisions verbatim (full fidelity). Comment/string forms ARE lexable per
 * language, so they are stripped precisely. Unknown extensions get the SAFE superset (regex-aware +
 * every common line-comment marker) so a mis-classified file over-blanks (a false-REJECT/SURVIVED)
 * rather than leaking.
 */
interface LangTraits {
  regexAware: boolean; // `/…/` regex literals → blank each line past its first `/`
  slashComment: boolean; // `//` line comment (NOT Python, where `//` is floor division)
  blockComment: boolean; // `/* … */`
  hashComment: boolean; // `#` line comment (Python/Ruby/shell/YAML/…)
  dashComment: boolean; // `--` line comment (SQL/Lua/Haskell/Ada)
  pctComment: boolean; // `%` line comment (MATLAB/Erlang/TeX; also over-blanks Ruby `%q…`/`%r…` literals)
  splice: boolean; // a `//` line comment continues across a trailing `\` (C/C++ line-splicing only)
  pyTriple: boolean; // `"""` / `'''` multi-line strings (Python + Java/Kotlin/Scala/Swift text blocks)
  template: boolean; // JS `` `…` `` template literal with `${…}` interpolation
  rawBacktick: boolean; // Go `` `…` `` raw string (no escapes/interp); also the safe-superset backtick
  cppRaw: boolean; // C++ raw string  R"delim(…)delim"  (+ u8/u/U/L prefixes)
  rustRaw: boolean; // Rust raw string  r#"…"#  (+ b prefix)
  heredoc: 'shell' | 'ruby' | 'php' | false; // `<<WORD` heredocs (php = `<<<WORD` here/nowdoc)
  podDoc: boolean; // Perl POD (`=word … =cut`) doc blocks + `__END__`/`__DATA__` trailer
  perlQuote: boolean; // Perl quote-like operators  q// qq// qw// qr// qx// m// s/// tr/// y///
  dollarQuote: boolean; // PostgreSQL dollar-quoted strings  $$…$$  /  $tag$…$tag$
}

// Ambiguous extensions (.m ObjC/MATLAB, .pl Perl/Prolog, .v Verilog/Coq, .r R/Rebol, .d D/dtrace,
// .rb Ruby, .pm, .ex …) and unknown files fall through to the SAFE SUPERSET: every non-destructive
// comment marker + all string forms + regex-aware, so whatever the file really is it OVER-blanks
// (a false-REJECT/SURVIVED) rather than leaking. `;` and `(* *)` comments are deliberately NOT in the
// superset — they collide with ubiquitous C/JS operators (`;`, `(*ptr`) and would gut the cite-check.
function langTraits(file: string): LangTraits {
  const base: LangTraits = { regexAware: false, slashComment: false, blockComment: false, hashComment: false, dashComment: false, pctComment: false, splice: false, pyTriple: false, template: false, rawBacktick: false, cppRaw: false, rustRaw: false, heredoc: false, podDoc: false, perlQuote: false, dollarQuote: false };
  const set = (o: Partial<LangTraits>): LangTraits => ({ ...base, ...o });
  const ext = (String(file ?? '').toLowerCase().match(/\.([a-z0-9+#]+)$/) ?? [])[1] ?? '';
  if (/^(js|jsx|mjs|cjs|ts|tsx|mts|cts)$/.test(ext)) return set({ regexAware: true, slashComment: true, blockComment: true, template: true });
  if (/^(cpp|cxx|cc|hpp|hh|hxx|c\+\+|ino|cppm|ixx|tpp|ipp)$/.test(ext)) return set({ slashComment: true, blockComment: true, splice: true, cppRaw: true });
  if (/^(c|h)$/.test(ext)) return set({ slashComment: true, blockComment: true, splice: true });
  if (/^go$/.test(ext)) return set({ slashComment: true, blockComment: true, rawBacktick: true });
  if (/^rs$/.test(ext)) return set({ slashComment: true, blockComment: true, rustRaw: true });
  if (/^(java|kt|kts|scala|swift|cs|dart|groovy|gradle)$/.test(ext)) return set({ slashComment: true, blockComment: true, pyTriple: true });
  if (/^(py|pyi|pyw|pyx)$/.test(ext)) return set({ hashComment: true, pyTriple: true });
  if (/^(sh|bash|zsh|ksh)$/.test(ext)) return set({ hashComment: true, heredoc: 'shell' });
  if (/^(fish|yaml|yml|tf|toml|ini|cfg|conf|dockerfile|mk|cmake|jl|nim|coffee|properties|gitignore)$/.test(ext)) return set({ hashComment: true });
  if (/^php\d*$/.test(ext)) return set({ slashComment: true, blockComment: true, hashComment: true, heredoc: 'php' });
  if (/^(sql|hql|psql|pgsql|ddl)$/.test(ext)) return set({ dashComment: true, blockComment: true, dollarQuote: true });
  if (/^(lua|hs|lhs|elm|adb|ads)$/.test(ext)) return set({ dashComment: true });
  if (/^(erl|hrl|tex|latex)$/.test(ext)) return set({ pctComment: true });
  return set({ regexAware: true, slashComment: true, blockComment: true, hashComment: true, dashComment: true, pctComment: true, pyTriple: true, rawBacktick: true, heredoc: 'ruby', podDoc: true, perlQuote: true });
}

/**
 * Reduce source to code-only lines: strip comments and BLANK string / char / template / raw-string /
 * regex literal contents (per the file's LangTraits), so the cite-check never matches a guard that
 * lives only in a comment / string / regex — the HT-2 false-VERIFY hazard. Newlines are preserved so
 * matching stays per-line.
 *
 * Handles, per language: line comments (slash-slash, hash, dash-dash, percent) and slash-star block
 * comments (only slash-slash splices across a trailing backslash, C/C++ only);
 * ' / " strings (line-bounded, LF+CRLF `\`-continuation); Python/JVM `"""`/`'''`; JS `${…}` templates
 * (interpolation-stack aware, so a nested template can't leak); Go `` ` `` raw strings; C++ R"d(…)d" and
 * Rust r#"…"# raw strings; and shell/Ruby `<<WORD` heredocs. A form a language lacks is off (its scanner
 * never runs); ambiguous/unknown files use the SUPERSET, which biases to over-blank.
 */
function codeLinesOf(src: string, t: LangTraits): string[] {
  const n = src.length;
  let masked = '';
  const heredocs: Array<{ w: string; indent: boolean; php?: boolean }> = []; // pending terminators, drained at newline
  const isIdent = (ch: string | undefined): boolean => ch !== undefined && /[A-Za-z0-9_$]/.test(ch);
  const blank = (len: number): void => { if (len > 0) masked += ' '.repeat(len); };
  const emitEsc = (i: number): number => {
    if (src[i + 1] === '\n') { masked += '\n'; return i + 2; } // `\`-LF line continuation
    if (src[i + 1] === '\r' && src[i + 2] === '\n') { masked += '\n'; return i + 3; } // `\`-CRLF
    masked += ' '; return i + 2;
  };
  const skipLineComment = (i: number, splice: boolean): number => {
    for (;;) {
      while (i < n && src[i] !== '\n') i++;
      if (splice) { let k = i - 1; if (src[k] === '\r') k--; if (k >= 0 && src[k] === '\\') { masked += '\n'; i++; continue; } }
      return i;
    }
  };
  const blankToClose = (j: number, close: string): number => {
    while (j < n && src.slice(j, j + close.length) !== close) { masked += src[j] === '\n' ? '\n' : ' '; j++; }
    const end = Math.min(j + close.length, n);
    blank(end - j);
    return end;
  };
  const PERL_PAIR: Record<string, string> = { '(': ')', '{': '}', '[': ']', '<': '>' };
  // Perl quote-like operator (q qq qw qr qx m — 1 body; s tr y — 2 bodies) at position i, or -1.
  const scanPerlQuote = (i: number): number => {
    const m = src.slice(i, i + 3).match(/^(qq|qw|qr|qx|tr|q|m|s|y)(?![A-Za-z0-9_])/);
    if (!m) return -1;
    const op = m[1];
    let j = i + op.length;
    while (src[j] === ' ' || src[j] === '\t') j++;
    const open = src[j];
    // a valid delimiter is a single non-alnum, non-space char that isn't an operator/closer that would
    // make ordinary code (e.g. `s = 1`, `$h->{q}`, `$a // $b`) look like a quote op and over-run.
    if (!open || /[A-Za-z0-9_\s=,;)\]}>]/.test(open)) return -1;
    const twoBody = op === 's' || op === 'tr' || op === 'y';
    blank(j - i + 1); j++; // op + opening delimiter
    const scanBody = (o: string, cl: string): void => {
      let depth = 1;
      while (j < n) {
        const d = src[j];
        if (d === '\\') { masked += ' '; masked += src[j + 1] === '\n' ? '\n' : ' '; j += 2; continue; }
        if (PERL_PAIR[o] && d === o) depth++;
        else if (d === cl) { depth--; if (depth === 0) { blank(1); j++; return; } }
        masked += d === '\n' ? '\n' : ' '; j++;
      }
    };
    scanBody(open, PERL_PAIR[open] ?? open);
    if (twoBody) {
      let o2 = open, c2 = PERL_PAIR[open] ?? open;
      if (PERL_PAIR[open]) { while (src[j] === ' ' || src[j] === '\t') j++; o2 = src[j]; c2 = PERL_PAIR[o2] ?? o2; if (o2) { blank(1); j++; } }
      scanBody(o2, c2); // a char delimiter's close doubles as the 2nd body's open (already consumed)
    }
    return j;
  };
  const scanTemplate = (i: number): number => {
    masked += ' '; i++;
    const stk = ['`']; // '`' = template-string part, '{' = ${…} interpolation, '"'/"'" = string in interp
    while (i < n && stk.length > 0) {
      const d = src[i];
      if (d === '\\') { i = emitEsc(i); continue; }
      const top = stk[stk.length - 1];
      if (top === '`') {
        if (d === '`') { stk.pop(); masked += ' '; i++; continue; }
        if (d === '$' && src[i + 1] === '{') { stk.push('{'); masked += '  '; i += 2; continue; }
      } else if (top === '"' || top === "'") {
        if (d === top) { stk.pop(); masked += ' '; i++; continue; }
        if (d === '\n') { stk.pop(); masked += '\n'; i++; continue; }
      } else { // top === '{' : a ${…} interpolation — BLANK it. A comparison there produces template
        if (d === '}') { stk.pop(); masked += ' '; i++; continue; } //   display text, not a bounds guard;
        if (d === '{') { stk.push('{'); masked += ' '; i++; continue; } //   and an interpolation reached
        if (d === '`') { stk.push('`'); masked += ' '; i++; continue; } //   through a nested template must
        if (d === '"' || d === "'") { stk.push(d); masked += ' '; i++; continue; } //   never leak (false-VERIFY).
      }
      masked += d === '\n' ? '\n' : ' '; i++;
    }
    return i;
  };
  for (let i = 0; i < n; ) {
    const c = src[i];
    const c2 = src[i + 1];
    // ---- Perl POD doc blocks (=word … =cut) + __END__/__DATA__ trailer (both line-anchored) ----
    if (t.podDoc && (i === 0 || src[i - 1] === '\n')) {
      let le = i; while (le < n && src[le] !== '\n') le++;
      // __END__/__DATA__ must be at column 0 to be a Perl trailer (an indented one is ordinary code, so
      // test the line FROM its first char, not a trimmed copy — else an indented match over-blanks to EOF).
      if (/^__(?:END|DATA)__\b/.test(src.slice(i, le))) { while (i < n) { masked += src[i] === '\n' ? '\n' : ' '; i++; } continue; }
      // A `=word` at column 0 opens POD (closed by `=cut`) — but ONLY if a `=cut` line actually appears
      // later; otherwise a stray leading `=` (an expression continuation, config, diff) is real code and
      // must not be blanked to EOF (that was a false-REJECT that killed real guards).
      if (c === '=' && /[A-Za-z]/.test(c2) && /\n=cut\b/.test(src.slice(i))) {
        for (;;) {
          let j = i; while (j < n && src[j] !== '\n') j++;
          const isCut = /^=cut\b/.test(src.slice(i, j));
          blank(j - i); i = j;
          if (i < n) { masked += '\n'; i++; }
          if (isCut || i >= n) break;
        }
        continue;
      }
    }
    // ---- Perl quote-like operators (q// qq// s/// tr/// m// qr// qw[] …) ----
    if (t.perlQuote && (c === 'q' || c === 'm' || c === 's' || c === 'y' || c === 't') && !isIdent(src[i - 1])) {
      const j = scanPerlQuote(i);
      if (j >= 0) { i = j; continue; }
    }
    // ---- line comments ----
    if (t.slashComment && c === '/' && c2 === '/') { i = skipLineComment(i, t.splice); continue; }
    if (t.hashComment && c === '#') { i = skipLineComment(i, false); continue; }
    if (t.dashComment && c === '-' && c2 === '-') { i = skipLineComment(i, false); continue; }
    if (t.pctComment && c === '%') { i = skipLineComment(i, false); continue; }
    // ---- block comment ----
    if (t.blockComment && c === '/' && c2 === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] === '\n') masked += '\n'; i++; }
      i += 2;
      continue;
    }
    // ---- C++ raw string  (u8|u|U|L)?R"delim(…)delim"  ----
    if (t.cppRaw && (c === 'R' || c === 'u' || c === 'U' || c === 'L') && !isIdent(src[i - 1])) {
      const m = src.slice(i, i + 4).match(/^(u8R|uR|UR|LR|R)"/);
      if (m) {
        let j = i + m[0].length, delim = '';
        while (j < n && src[j] !== '(' && src[j] !== '\n' && src[j] !== ' ' && src[j] !== '\\' && delim.length <= 16) { delim += src[j]; j++; }
        if (src[j] === '(') { blank(j - i + 1); i = blankToClose(j + 1, ')' + delim + '"'); continue; }
      }
    }
    // ---- Rust raw string  b?r#*"…"#*  ----
    if (t.rustRaw && (c === 'r' || c === 'b') && !isIdent(src[i - 1])) {
      const m = src.slice(i, i + 260).match(/^b?r(#*)"/); // wide enough for any real `r####…"` hash run
      if (m) { blank(m[0].length); i = blankToClose(i + m[0].length, '"' + m[1]); continue; }
    }
    // ---- PHP heredoc / nowdoc  <<<['"]?WORD['"]?  (body drained at the newline) ----
    // PHP opens a here/nowdoc with THREE `<`; its `<<` is a left-shift operator, never a heredoc. The
    // closer is WORD alone on a line (PHP 7.3+ allows an indented closer, optionally followed by `;`, `,`,
    // `)`, etc.), so the drain matches WORD at the line's first token rather than the whole line.
    if (t.heredoc === 'php' && c === '<' && c2 === '<' && src[i + 2] === '<') {
      let j = i + 3;
      while (src[j] === ' ' || src[j] === '\t') j++;
      let q = ''; if (src[j] === "'" || src[j] === '"') { q = src[j]; j++; }
      let w = ''; while (j < n && /[A-Za-z0-9_]/.test(src[j])) { w += src[j]; j++; }
      if (q && src[j] === q) j++;
      if (w) { blank(j - i); heredocs.push({ w, indent: true, php: true }); i = j; continue; }
    }
    // ---- heredoc opener  <<[-~]?['"]?WORD  (body drained at the newline) ----
    // Guard against `<<<` (shell here-string, not a multi-line heredoc): reject when either neighbour
    // is another `<`, so neither the 1st nor the 2nd `<` of `<<<` opens a heredoc.
    if ((t.heredoc === 'shell' || t.heredoc === 'ruby') && c === '<' && c2 === '<' && src[i + 2] !== '<' && src[i + 2] !== '=' && src[i - 1] !== '<') {
      let j = i + 2;
      const squig = src[j] === '-' || src[j] === '~'; if (squig) j++;
      if (t.heredoc === 'shell') while (src[j] === ' ' || src[j] === '\t') j++;
      let q = ''; if (src[j] === "'" || src[j] === '"' || src[j] === '`') { q = src[j]; j++; }
      let w = ''; while (j < n && /[A-Za-z0-9_]/.test(src[j])) { w += src[j]; j++; }
      if (q && src[j] === q) j++;
      // shell: every <<WORD is a heredoc. ruby/perl: the -/~/quoted forms are unambiguous; a BARE <<WORD
      // is ambiguous with `<< ` left-shift/append, so treat it as a heredoc ONLY if a matching terminator
      // line (== WORD) actually appears later — a real heredoc always has one; `arr << CONST` does not.
      const bareOk = w && !squig && !q && t.heredoc !== 'shell' && new RegExp('\\n[ \\t]*' + w + '[ \\t\\r]*(?:\\n|$)').test(src.slice(j));
      if (w && (t.heredoc === 'shell' || squig || q || bareOk)) { blank(j - i); heredocs.push({ w, indent: squig || (bareOk as boolean) }); i = j; continue; }
    }
    // ---- PostgreSQL dollar-quoted string  $$…$$  /  $tag$…$tag$  (tag = [A-Za-z0-9_]*) ----
    if (t.dollarQuote && c === '$') {
      let k = i + 1; while (k < n && /[A-Za-z0-9_]/.test(src[k])) k++;
      if (src[k] === '$') { // a real dollar-quote opener (not a `$1` parameter — those have no closing `$`)
        const tag = src.slice(i, k + 1); // includes both `$`
        blank(tag.length); i = blankToClose(k + 1, tag); continue;
      }
    }
    // ---- Python / JVM triple-quoted string ----
    if (t.pyTriple && (c === '"' || c === "'") && src[i + 1] === c && src[i + 2] === c) {
      blank(3); let j = i + 3;
      while (j < n && !(src[j] === c && src[j + 1] === c && src[j + 2] === c)) {
        if (src[j] === '\\') { j = emitEsc(j); continue; }
        masked += src[j] === '\n' ? '\n' : ' '; j++;
      }
      if (j < n) { blank(3); j += 3; }
      i = j; continue;
    }
    // ---- backtick: JS template (${…}-aware) OR Go / superset raw string ----
    if (t.template && c === '`') { i = scanTemplate(i); continue; }
    if (t.rawBacktick && c === '`') {
      masked += ' '; i++;
      while (i < n && src[i] !== '`') { masked += src[i] === '\n' ? '\n' : ' '; i++; }
      masked += ' '; if (src[i] === '`') i++;
      continue;
    }
    // ---- ' / " string / char literal (line-bounded; LF/CRLF `\`-continuation) ----
    if (c === '"' || c === "'") {
      masked += ' '; i++;
      while (i < n && src[i] !== c) {
        if (src[i] === '\\') { i = emitEsc(i); continue; }
        if (src[i] === '\n') break; // a bare newline ends a ' / " literal
        masked += ' '; i++;
      }
      masked += ' '; if (src[i] === c) i++;
      continue;
    }
    // ---- newline: emit it, then drain any pending heredoc bodies ----
    if (c === '\n') {
      masked += '\n'; i++;
      while (heredocs.length > 0) {
        const hd = heredocs.shift() as { w: string; indent: boolean; php?: boolean };
        for (;;) {
          let j = i; while (j < n && src[j] !== '\n') j++;
          const stripped = src.slice(i, j).replace(/\r$/, '');
          blank(j - i); i = j; // blank this body / terminator line
          // PHP: closer is WORD as the line's first token (indent + trailing `;`/`,`/`)` allowed). Others:
          // whole-line match (shell/ruby `<<WORD`), trimmed when the opener was indented (`<<-`/`<<~`).
          const isTerm = hd.php ? new RegExp('^[ \\t]*' + hd.w + '(?![A-Za-z0-9_])').test(stripped)
            : (hd.indent ? stripped.trim() === hd.w : stripped === hd.w);
          if (i < n) { masked += '\n'; i++; }
          if (isTerm || i >= n) break;
        }
      }
      continue;
    }
    masked += c; i++;
  }
  const lines = masked.split('\n');
  if (!t.regexAware) return lines; // no regex literals → every `/` is a division, kept verbatim
  return lines.map((line) => {
    const first = line.indexOf('/'); // every regex opens with `/` → blank past it, its body dies too
    return first === -1 ? line : line.slice(0, first) + ' '.repeat(line.length - first);
  });
}

/**
 * Cite-check: does the refuter's cited killing `guard` actually appear in `source`?
 *
 * Deterministic, and the ONLY thing standing between a hallucinated "if (m_id >= ls.w) continue;"
 * and a wrongly-refuted real finding (the pack-hunt design HT-2). A guard verifies two ways —
 * BOTH hardened so a fabricated guard cannot pass on token coincidence alone:
 *
 *  1. NORMALIZED SUBSTRING: the whitespace-stripped, lowercased quote is a substring of the
 *     normalized source AND the quote has real guard SHAPE (a comparison operator / control keyword /
 *     bounds-call). A bare common token (`length`, or a copy of the sink line) has no guard shape and
 *     cannot verify. Tolerates reformatting/indentation.
 *  2. STRUCTURAL COMPARISON: the quote is a comparison `a OP b`, and SOME source line contains a REAL
 *     comparison whose two operands are exactly `a` and `b` (whole tokens, either order). Mere
 *     co-occurrence of the two operand strings on a line is NOT enough — that was the hole that let
 *     `n > src` / `idx >= width` (operands that never actually get compared) mint a bogus REFUTE and
 *     kill a real finding.
 *
 * @param guard  the cited guard; needs a non-empty `quote`.
 * @param source the FULL text of the cited source file (injected by the caller — this module does no
 *               I/O). Pass '' if the file is missing → false.
 * @returns true iff the guard is corroborated by the source; false if the quote is empty/too-short,
 *          lacks guard shape, the source is empty, or the cited operands are not actually compared in
 *          source (hallucinated / paraphrased-absent).
 */
export function guardExistsInSource(guard: KillingGuard | null | undefined, source: string): boolean {
  if (!guard || !guard.quote) return false;
  const src = String(source ?? '');
  if (!src) return false;
  const rawQuote = String(guard.quote);

  // Reduce to code-only lines: strip comments AND blank string/char/template-literal (and, for a
  // regex-bearing language, regex-literal) contents, then match PER LINE — so a hallucinated guard
  // whose text sits only in a STRING, COMMENT, or REGEX can never verify. The language is decided from
  // the cited file's extension (default: regex-aware / leak-safe) so a C/C++/… source keeps its
  // divisions verbatim while a JS/TS/unknown source is over-blanked past any `/`.
  const codeLines = codeLinesOf(src, langTraits(String(guard.file ?? '')));

  // Path 1 — normalized substring on a SINGLE code line, only for quotes that look like a guard.
  const q = normalize(rawQuote);
  if (q.length >= 6 && GUARD_SHAPE_RE.test(rawQuote)) {
    for (const line of codeLines) if (normalize(line).includes(q)) return true;
  }

  // Path 2 — the cited comparison's operands must be the operands of a REAL comparison on ONE source
  // line, not two strings that merely co-occur, AND with a matching OPERATOR. The operator is the whole
  // semantic content of a bounds guard: a hallucinated `idx >= len` must NOT verify against a source
  // `idx == len` (a non-bounding equality) just because they share operands. So we require the source
  // operator to equal the cited one (same operand order) or its mirror (reversed order).
  const cited = rawQuote.match(COMPARISON_RE);
  if (cited) {
    const a = coreToken(cited[1]);
    const b = coreToken(cited[3]);
    const op = cited[2];
    if (a && b && a !== b) {
      // ⚡ BOLT OPTIMIZATION: Reuse pre-compiled COMPARISON_G_RE and reset lastIndex=0 per line,
      // avoiding thousands of `new RegExp` compilations on hot line scanning loops.
      const re = COMPARISON_G_RE;
      for (let i = 0; i < codeLines.length; i++) {
        const line = codeLines[i];
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(line)) !== null) {
          const la = coreToken(m[1]);
          const lb = coreToken(m[3]);
          const lop = m[2];
          // A source `<` whose right operand is immediately followed by `,`, `>`, or `<` opens a GENERIC
          // argument list (`Map<K, V>`, `Vec<u8>`, `Nested<Vec<…>>`), not a comparison — skip it.
          if (lop === '<') {
            // ⚡ BOLT OPTIMIZATION: Direct character index check to skip whitespace without intermediate `slice` or match allocations.
            let k = re.lastIndex;
            while (k < line.length && (line[k] === ' ' || line[k] === '\t' || line[k] === '\r')) k++;
            const nextCh = line[k];
            if (nextCh === ',' || nextCh === '>' || nextCh === '<') continue;
          }
          if (la === a && lb === b && lop === op) return true; // same order, same operator
          if (la === b && lb === a && lop === MIRROR_OP[op]) return true; // reversed order, mirrored operator
        }
      }
    }
  }
  return false;
}

// =============================================================================
// MANDATORY CITE-CHECK ENFORCEMENT
// =============================================================================

/**
 * Apply the mandatory cite-check to a panel BEFORE adjudicate().
 *
 * For every REFUTED vote that carries a killing_guard: if guardExistsInSource() is
 * false, the vote is DOWNGRADED to SURVIVED (its original verdict preserved on
 * `original_verdict` and `guard_check:'unverified'` recorded for transparency). A
 * REFUTED vote with NO killing_guard also can't stand on a cite — it too is
 * downgraded. This enforces HT-2: agreement can never promote a hallucinated
 * refute; only a cited-and-verified guard refutes.
 *
 * Pure: returns a NEW array of NEW vote objects; input is not mutated. `null`
 * entries and non-REFUTED votes pass through unchanged (copied).
 *
 * @param verdicts the raw panel votes.
 * @param resolveSource maps a guard's `file` to that file's source text (the
 *        caller injects I/O here — e.g. read from disk, or look up an in-memory
 *        code map). Return '' (or undefined) for a missing file → the vote fails
 *        the check and is downgraded.
 */
export function downgradeUnverifiedRefutes(
  verdicts: ReadonlyArray<RefuterVote | null | undefined>,
  resolveSource: (file: string) => string | undefined,
): Array<RefuterVote | null> {
  // ⚡ BOLT OPTIMIZATION: Pre-allocate array size and use direct indexed loop over `verdicts`.
  // Cache cite-check results per unique file+quote to avoid re-parsing/re-tokenizing source
  // files repeatedly for identical cited guards across large vote panels.
  const n = verdicts.length;
  const out: Array<RefuterVote | null> = new Array(n);
  const guardCheckCache = new Map<string, boolean>();

  for (let i = 0; i < n; i++) {
    const v = verdicts[i];
    if (v === null || v === undefined) {
      out[i] = null;
      continue;
    }
    if (v.verdict !== 'REFUTED') {
      out[i] = { ...v };
      continue;
    }
    const guard = v.killing_guard ?? null;
    if (!guard || !guard.quote || !guard.file) {
      out[i] = {
        ...v,
        original_verdict: 'REFUTED' as const,
        verdict: 'SURVIVED' as const,
        guard_check: 'unverified' as const,
      };
      continue;
    }

    const cacheKey = `${guard.file}\0${guard.quote}`;
    let verified = guardCheckCache.get(cacheKey);
    if (verified === undefined) {
      const source = resolveSource(guard.file) ?? '';
      verified = guardExistsInSource(guard, source);
      guardCheckCache.set(cacheKey, verified);
    }

    if (verified) {
      out[i] = { ...v, guard_check: 'verified' as const };
    } else {
      out[i] = {
        ...v,
        original_verdict: 'REFUTED' as const,
        verdict: 'SURVIVED' as const,
        guard_check: 'unverified' as const,
      };
    }
  }
  return out;
}
