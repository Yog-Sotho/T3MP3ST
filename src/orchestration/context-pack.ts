/**
 * context-pack — token-budgeted, repo-map + per-file relevance packing.
 *
 * Replaces the old blind head-slice (`source.slice(0, 24000)`) that silently
 * threw away everything past the first N chars of a large repo. Instead we:
 *
 *   1. ALWAYS emit a compact REPO MAP header (every file, path + approx size) —
 *      cheap, so even a huge repo keeps a full inventory the model can reason
 *      about. If the map itself would blow the budget, it is capped with an
 *      explicit "N more files" note (never a silent drop).
 *   2. Rank files by relevance to the objective / prior intel (keyword hits)
 *      plus a heuristic boost for security-relevant paths/content.
 *   3. Pack whole files highest-score-first until the token budget is spent.
 *      A single oversized file is included as head+tail with a clear middle
 *      elision marker rather than being dropped outright.
 *   4. Report exactly which files were included vs dropped, and how many tokens
 *      were used — so trimming is VISIBLE (no silent loss).
 *
 * Token counting here is a documented approximation (chars/4); it is a budgeting
 * heuristic, not a real tokenizer. It intentionally over- rather than
 * under-estimates for short ASCII so we stay conservatively under real limits.
 */

// =============================================================================
// TYPES
// =============================================================================

export type SourceFile = { path: string; content: string };
export type SourceBundle = SourceFile[];

export interface PackedContext {
  /** The assembled text: REPO MAP header followed by packed file bodies. */
  text: string;
  /** Paths whose (possibly elided) body was included below the map. */
  includedFiles: string[];
  /** Paths that had to be dropped for budget (still listed in the map). */
  droppedFiles: string[];
  /** Approximate tokens the assembled text consumes. */
  tokensUsed: number;
  /** The budget it was packed against (echoed for telemetry). */
  tokenBudget: number;
}

export interface PackOptions {
  /** Approximate token ceiling for the whole assembled text. */
  tokenBudget: number;
  /** The objective (keywords drive relevance ranking). Optional. */
  objective?: string;
  /** Prior intelligence (also contributes ranking keywords). Optional. */
  priorIntel?: string;
}

// =============================================================================
// TOKEN ESTIMATION (approximation — NOT a real tokenizer)
// =============================================================================

/**
 * Estimate token count as chars / 4. This is the widely-used rough rule for
 * English/code and is deliberately an APPROXIMATION — it exists only to keep
 * the packed context under a model context window with headroom, not to bill.
 */
export function estimateTokens(s: string): number {
  if (!s) return 0;
  return Math.ceil(s.length / 4);
}

// =============================================================================
// LOOSE SOURCE PARSING — split a flat blob into files when it has delimiters
// =============================================================================

// Matches common "here is a file" delimiters that tools emit, e.g.:
//   === src/foo.c ===
//   --- FILE: pkg/auth.py ---
//   ## handlers/login.ts
//   // path/to/util.js
// The trailing token must look like a path with an extension so we don't split
// on ordinary "---" horizontal rules or "// a comment sentence.".
const FILE_DELIM_RE =
  /^\s*(?:={3,}|-{3,}|#{2,}|\/\/)\s*(?:FILE:)?\s*([^\s=#/][^\s=]*\.\w{1,10})\s*(?:={3,}|-{3,})?\s*$/i;

/**
 * Parse a loose source blob into a SourceBundle.
 *
 * If the blob contains recognizable per-file delimiters, split on them and use
 * the delimiter's path as each file's path. Otherwise return a single
 * pseudo-file `[{ path: "(source)", content: s }]` so callers always get a
 * bundle they can pack.
 */
export function parseLooseSource(s: string): SourceBundle {
  const src = s || '';
  if (!src.trim()) return [{ path: '(source)', content: src }];

  const lines = src.split('\n');
  const cuts: Array<{ index: number; path: string }> = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(FILE_DELIM_RE);
    if (m) cuts.push({ index: i, path: m[1] });
  }

  // No delimiters → treat the whole thing as one pseudo-file.
  if (cuts.length === 0) return [{ path: '(source)', content: src }];

  const bundle: SourceBundle = [];

  // Preamble before the first delimiter (if any non-blank content) is its own
  // pseudo-file so nothing is lost.
  const preamble = lines.slice(0, cuts[0].index).join('\n');
  if (preamble.trim()) bundle.push({ path: '(preamble)', content: preamble });

  for (let c = 0; c < cuts.length; c++) {
    const start = cuts[c].index + 1;
    const end = c + 1 < cuts.length ? cuts[c + 1].index : lines.length;
    const content = lines.slice(start, end).join('\n');
    bundle.push({ path: dedupePath(bundle, cuts[c].path), content });
  }

  return bundle;
}

function dedupePath(bundle: SourceBundle, path: string): string {
  if (!bundle.some(f => f.path === path)) return path;
  let n = 2;
  while (bundle.some(f => f.path === `${path}#${n}`)) n++;
  return `${path}#${n}`;
}

// =============================================================================
// RELEVANCE SCORING
// =============================================================================

// Security-relevant substrings — paths or content matching any of these get a
// ranking boost, so an auth/route/deserialize file surfaces even when the
// objective's own keywords don't appear verbatim in it.
const SECURITY_HINTS = [
  'route', 'handler', 'controller', 'auth', 'login', 'session', 'deserialize',
  'pickle', 'exec', 'system', 'eval', 'sql', 'query', 'upload', 'template',
];

const KEYWORD_RE = /[a-z0-9_]{3,}/gi;

function extractKeywords(...texts: Array<string | undefined>): string[] {
  const set = new Set<string>();
  for (const t of texts) {
    if (!t) continue;
    const matches = t.toLowerCase().match(KEYWORD_RE);
    if (!matches) continue;
    for (const w of matches) set.add(w);
  }
  return [...set];
}

/**
 * Relevance = count of objective/priorIntel keyword occurrences in path+content
 * (path hits weighted heavier) + a heuristic boost for security-relevant
 * paths/content. Higher = packed sooner.
 */
function scoreFile(file: SourceFile, keywords: string[]): number {
  const path = file.path.toLowerCase();
  const content = file.content.toLowerCase();
  let score = 0;

  for (const kw of keywords) {
    if (path.includes(kw)) score += 5; // a keyword in the path is a strong signal
    // count content occurrences (capped so one huge file can't dominate)
    let idx = content.indexOf(kw);
    let hits = 0;
    while (idx !== -1 && hits < 20) {
      hits++;
      idx = content.indexOf(kw, idx + kw.length);
    }
    score += hits;
  }

  for (const hint of SECURITY_HINTS) {
    if (path.includes(hint)) score += 4;
    if (content.includes(hint)) score += 1;
  }

  return score;
}

// =============================================================================
// REPO MAP
// =============================================================================

function approxLoc(content: string): number {
  if (!content) return 0;
  // count newlines + 1 for the last line if non-empty
  // ⚡ BOLT OPTIMIZATION: Avoid iterating character-by-character in JS.
  // Instead, use native C++-backed `indexOf` loop which is much faster.
  let n = 0;
  let idx = content.indexOf('\n');
  while (idx !== -1) {
    n++;
    idx = content.indexOf('\n', idx + 1);
  }
  return content.length > 0 ? n + 1 : 0;
}

function mapLine(file: SourceFile): string {
  return `  - ${file.path} (~${approxLoc(file.content)} loc, ${file.content.length} bytes)`;
}

/**
 * Build the REPO MAP header. Always lists as many files as fit inside `mapCap`
 * tokens; if the inventory is larger, it caps the listing and appends an
 * explicit "… N more files (not listed)" note so the trim is visible.
 */
function buildRepoMap(bundle: SourceBundle, mapCap: number): string {
  const header = `=== REPO MAP (${bundle.length} file${bundle.length === 1 ? '' : 's'}) ===`;
  const lines: string[] = [header];
  let listed = 0;

  for (const file of bundle) {
    const candidate = mapLine(file);
    // reserve room for a possible "more files" footer
    const projected = estimateTokens([...lines, candidate].join('\n'));
    if (projected > mapCap && listed > 0) break;
    lines.push(candidate);
    listed++;
  }

  const remaining = bundle.length - listed;
  if (remaining > 0) {
    lines.push(`  … ${remaining} more file${remaining === 1 ? '' : 's'} (not listed — map capped for budget)`);
  }

  return lines.join('\n');
}

// =============================================================================
// FILE BODY RENDERING (with head+tail elision for oversized files)
// =============================================================================

function fileHeader(path: string): string {
  return `\n=== FILE: ${path} ===\n`;
}

/**
 * Render a file body into at most `bodyTokenBudget` tokens. If the whole file
 * fits, include it verbatim. Otherwise include a head slice + tail slice with a
 * clear middle-elision marker (never a silent truncation).
 */
function renderFileBody(file: SourceFile, bodyTokenBudget: number): string {
  const full = file.content;
  if (estimateTokens(full) <= bodyTokenBudget) return full;

  // Budget is in tokens (~chars/4); convert to a char budget and split
  // head/tail, leaving room for the marker.
  const marker = '\n\n…[middle elided for context budget]…\n\n';
  const charBudget = Math.max(0, bodyTokenBudget * 4 - marker.length);
  const headChars = Math.floor(charBudget * 0.6);
  const tailChars = charBudget - headChars;

  if (headChars <= 0 && tailChars <= 0) return marker.trim();

  const head = full.slice(0, headChars);
  const tail = tailChars > 0 ? full.slice(full.length - tailChars) : '';
  return `${head}${marker}${tail}`;
}

// =============================================================================
// PACK
// =============================================================================

/**
 * Pack a SourceBundle into a token-budgeted, map-first, relevance-ranked blob.
 *
 * Guarantees:
 *   - The REPO MAP header is ALWAYS present (capped, never silently dropped).
 *   - Files are packed highest-relevance-first until the budget is spent.
 *   - A single oversized file is head+tail elided rather than dropped.
 *   - includedFiles / droppedFiles / tokensUsed are reported for telemetry.
 */
export function packContext(bundle: SourceBundle, opts: PackOptions): PackedContext {
  const tokenBudget = Math.max(0, Math.floor(opts.tokenBudget));
  const files = bundle && bundle.length ? bundle : [{ path: '(source)', content: '' }];

  // Reserve up to ~15% of the budget (min 200 tokens) for the always-present map.
  const mapCap = Math.max(200, Math.floor(tokenBudget * 0.15));
  const repoMap = buildRepoMap(files, mapCap);

  const keywords = extractKeywords(opts.objective, opts.priorIntel);
  const ranked = files
    .map((file, i) => ({ file, i, score: scoreFile(file, keywords) }))
    // stable: score desc, then original order (keeps deterministic packing)
    .sort((a, b) => (b.score - a.score) || (a.i - b.i));

  const sections: string[] = [repoMap];
  const includedFiles: string[] = [];
  const droppedFiles: string[] = [];

  let tokensUsed = estimateTokens(repoMap);

  for (const { file } of ranked) {
    const remaining = tokenBudget - tokensUsed;
    const headerCost = estimateTokens(fileHeader(file.path));
    // Need at least the header + a little body to be worth including.
    if (remaining - headerCost < 8) {
      droppedFiles.push(file.path);
      continue;
    }

    const bodyBudget = remaining - headerCost;
    const body = renderFileBody(file, bodyBudget);
    const section = `${fileHeader(file.path)}${body}`;
    const cost = estimateTokens(section);

    if (tokensUsed + cost > tokenBudget && includedFiles.length > 0) {
      // Would overflow and we already have content — drop this one.
      droppedFiles.push(file.path);
      continue;
    }

    sections.push(section);
    includedFiles.push(file.path);
    tokensUsed += cost;
  }

  return {
    text: sections.join('\n'),
    includedFiles,
    droppedFiles,
    tokensUsed,
    tokenBudget,
  };
}
