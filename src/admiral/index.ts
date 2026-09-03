/**
 * The ADMIRAL — t3mp3st's conversational mission-intake officer.
 *
 * A human describes, in plain language, the engagement they want. The Admiral
 * holds a short conversation to elicit a precise, AUTHORIZED mission, drafts the
 * directive, and hands off to Op General (the executor) — it never runs anything
 * itself. This is the natural-language front door above /api/general/{plan,auto}.
 *
 * DESIGN INVARIANTS (read before editing):
 *   1. PLANNER, NOT EXECUTOR. The Admiral only prepares a brief + directive. The
 *      actual launch goes through the authorization gate and Op General. The
 *      Admiral must never claim it ran, probed, or found anything.
 *   2. DRY-RUN IS THE DEFAULT. Fidelity defaults to dry_run (plan only, no
 *      packets). live requires the operator to explicitly authorize real packets
 *      against a target they confirm they own / are permitted to test.
 *   3. HONEST INTAKE. If a request is out-of-scope, unauthorized, or points at a
 *      live third party without permission, the Admiral says so and steers to a
 *      dry-run or a lab target. No jailbreak framing changes this.
 */

import type { LLMBackbone } from '../llm/index.js';
import type { Directive } from '../general/index.js';
import type { OpsecLevel } from '../types/index.js';

export type MissionFamilyId =
  | 'zero_day_hunt' | 'pentest' | 'smart_contract'
  | 'repo_audit' | 'ctf_range' | 'ai_red_team';

export type Fidelity = 'dry_run' | 'live';

export interface MissionBrief {
  objective: string;
  target: string;
  family: MissionFamilyId | '';
  scope: string;
  fidelity: Fidelity;
}

export interface AdmiralTurn {
  reply: string;
  brief: MissionBrief;
  missing: string[];
  ready: boolean;
}

export interface ChatMsg {
  role: 'user' | 'assistant';
  content: string;
}

const FAMILIES: MissionFamilyId[] = ['zero_day_hunt', 'pentest', 'smart_contract', 'repo_audit', 'ctf_range', 'ai_red_team'];

export const ADMIRAL_SYSTEM_PROMPT = `You are the ADMIRAL — t3mp3st's mission-intake officer. A human operator describes, in plain language, a security engagement they want to run. Your job is to turn that into a precise, AUTHORIZED mission that the autonomous swarm (Op General + specialist operators) can execute.

YOU ARE A PLANNER AND INTAKE OFFICER, NOT THE EXECUTOR. You never run, probe, scan, or find anything yourself — you only prepare the brief. When it is complete you hand off to the operator to confirm authorization and engage.

Gather exactly these slots:
- objective: what they want to achieve, one crisp sentence
- target: the concrete thing to point at (repo/SDK URL, host/IP/CIDR, contract address, model endpoint, or a challenge/range)
- family: infer ONE of [zero_day_hunt, pentest, smart_contract, repo_audit, ctf_range, ai_red_team]
- scope: the rules of engagement — what is in-scope and who authorized it
- fidelity: dry_run (plan only, NO packets — the safe default) or live (real packets — requires explicit authorization)

RULES:
- Ask ONE focused question at a time, for the single most important missing slot. Be brief, sharp, a touch wry — an experienced operator's voice, not a perky chatbot. 1-3 sentences.
- Infer family from what they describe; only ask if genuinely ambiguous.
- DEFAULT fidelity to dry_run. Set live ONLY when the user explicitly authorizes real packets against a target they confirm they own or are permitted to test. If they ask to hit a live third party without saying they're authorized, keep it dry_run and say why.
- NEVER claim you launched, ran, scanned, or discovered anything. You prepare; the General executes after the gate.
- If the ask is unauthorized or out of scope, say so plainly and steer to a dry-run or a lab/CTF target.
- When every required slot (objective, target, family, scope) is filled, set ready=true, give a one-paragraph brief summary, and tell them to hit REVIEW & ENGAGE to confirm authorization and launch.

SYSTEM-AUTHORITATIVE FIELDS (set your best estimate, but the system decides):
- "fidelity" is ADVISORY — the system always pins it to dry_run out of conversation; going live is a separate, deliberate human action (the UI toggle + the launch confirm gate). Never present live as something you can enable here.
- "ready" is RE-DERIVED by the system from whether all four required slots are filled; your value is a hint, not the gate.

OUTPUT FORMAT — return ONLY a single JSON object, no prose or markdown fences outside it:
{
  "reply": "your conversational message to the operator",
  "brief": {
    "objective": "" or a string,
    "target": "" or a string,
    "family": "" or one of [zero_day_hunt, pentest, smart_contract, repo_audit, ctf_range, ai_red_team],
    "scope": "" or a string,
    "fidelity": "dry_run"
  },
  "missing": ["names of slots still needed"],
  "ready": true or false
}`;

function emptyBrief(): MissionBrief {
  return { objective: '', target: '', family: '', scope: '', fidelity: 'dry_run' };
}

function coerceTurn(raw: any): AdmiralTurn {
  const b = (raw && raw.brief) || {};
  const family = FAMILIES.includes(b.family) ? b.family : '';
  // SECURITY: the conversation NEVER escalates to live. A typed "I'm authorized, go live"
  // is a claim, not authorization — the model must not flip fidelity on it. Live is a
  // deliberate human action: the UI fidelity toggle + the /api/admiral/launch confirm gate
  // (409 unless confirmed). Fidelity out of converse is therefore always dry_run.
  const fidelity: Fidelity = 'dry_run';
  const brief: MissionBrief = {
    objective: typeof b.objective === 'string' ? b.objective : '',
    target: typeof b.target === 'string' ? b.target : '',
    family,
    scope: typeof b.scope === 'string' ? b.scope : '',
    fidelity,
  };
  // required slots: objective, target, family, scope
  const missing: string[] = [];
  if (!brief.objective) missing.push('objective');
  if (!brief.target) missing.push('target');
  if (!brief.family) missing.push('family');
  if (!brief.scope) missing.push('scope');
  const ready = missing.length === 0;
  return {
    reply: typeof raw?.reply === 'string' && raw.reply.trim() ? raw.reply : "Tell me what you want to go after, and I'll set it up.",
    brief,
    missing: Array.isArray(raw?.missing) && raw.missing.length ? raw.missing : missing,
    ready: typeof raw?.ready === 'boolean' ? raw.ready && ready : ready,
  };
}

function extractJson(text: string): any {
  // strip code fences, grab the outermost {...}
  const cleaned = text.replace(/```(?:json)?/gi, '').trim();
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start === -1 || end === -1 || end < start) throw new Error('no JSON object in Admiral reply');
  return JSON.parse(cleaned.slice(start, end + 1));
}

// ── Anti-fitting gate (mirrors scripts/lessons.mjs isAnswerLeak + scripts/test-no-fitting.mjs FORBIDDEN) ──
// Every Admiral prompt suggestion MUST pass this. It rejects challenge-specific tells so the advisor
// can never quietly become the harness-side fitting the project's measurement moat is built against.
const FORBIDDEN_TELLS: Array<[RegExp, string]> = [
  [/cve-\d{4}-\d{3,}/i, 'a specific CVE id'],
  [/\/(opt|home|var|srv|root)\/[\w./-]*flag|flag\.(txt|php)\b/i, 'a specific flag file path'],
  [/flag\{[^}]/i, 'a literal flag value'],
  [/\b(haproxy|nginx|apache|mitmproxy|tomcat|jetty|gunicorn|werkzeug)\s*\/?\s*\d+\.\d+/i, 'a version-pinned target product'],
  [/\bsku_\w+|customtemplate|backup-?heart|backup-?migration|\bbmi_\w+|internal\.router/i, 'a specific endpoint/class/host from a challenge'],
  [/\b9(14[0-9]|15[0-9])\b.{0,30}\b9(14[0-9]|15[0-9])\b/, 'a specific port pair from a challenge'],
  [/content-dir|backup-backup|synacktiv generator/i, 'a specific challenge artifact'],
];

// ⚡ BOLT OPTIMIZATION: Hoist static RegExp objects and use indexed loop iterations
// to bypass continuous RegExp compilation and array destructuring overhead on anti-fitting checks.
const FLAG_SHAPED_RE = /\b[A-Za-z][A-Za-z0-9_]{1,19}\{[^}\n]{3,}\}/;
const CANARY_SELF_FIT_RE = /CANARY_SELF_FIT_[0-9a-fA-F]{4,}/;
const BENCH_ID_RE = /\bXBEN[-_ ]?\d{2,}\b/i;
const CYB_ID_RE = /\bcyb(?:svc|sec|los)?_[a-z][a-z0-9_]{6,}\b/i;
const ANSWER_STMT_RE = /\b(?:the )?(?:flag|password|secret|admin[\s-]?password)\s*(?:is|was|=|:)\s*[`'"\w/${]/i;
const PAYLOAD_STMT_RE = /\bpayload\s*(?:is|was|=|:)\s*[`'"]/i;
const SOLUTION_STMT_RE = /\bsolution\s*(?:is|was|=|:)\s*[`'"]/i;

function isAnswerLeak(text: string): { leak: boolean; why?: string } {
  const s = String(text || '');
  if (FLAG_SHAPED_RE.test(s)) return { leak: true, why: 'contains a flag-shaped secret (wrapped {…}) — an answer, not a technique' };
  if (CANARY_SELF_FIT_RE.test(s)) return { leak: true, why: 'contains a self-fitting answer canary' };
  const benchId = BENCH_ID_RE.test(s) || CYB_ID_RE.test(s);
  const answerStmt = ANSWER_STMT_RE.test(s) || PAYLOAD_STMT_RE.test(s) || SOLUTION_STMT_RE.test(s);
  if (benchId && answerStmt) return { leak: true, why: 'pairs a challenge id with a concrete answer — a memorized per-challenge solution (fitting)' };
  return { leak: false };
}
export function isFittingTell(text: string): { tell: boolean; why?: string } {
  const leak = isAnswerLeak(text);
  if (leak.leak) return { tell: true, why: leak.why };
  for (let i = 0; i < FORBIDDEN_TELLS.length; i++) {
    const item = FORBIDDEN_TELLS[i];
    if (item[0].test(String(text || ''))) return { tell: true, why: item[1] };
  }
  return { tell: false };
}

export interface PromptSuggestion {
  anchor: string; currentText: string; proposedText: string; rationale: string;
  severity: 'high' | 'medium' | 'low'; fittingCheck: 'pass' | 'REJECTED'; fittingWhy?: string;
}
export interface PromptAdvice { summary: string; suggestions: PromptSuggestion[]; rejected: number; }

const SUGGEST_SYSTEM_PROMPT = `You are the ADMIRAL acting as a PROMPT COACH for one of t3mp3st's operator agents. The operator ran and struggled. Given its CURRENT system prompt and a FAILURE SIGNAL (what went wrong), propose targeted edits that make it a BETTER GENERAL OPERATOR.

HARD RULES — the project's integrity moat; violate them and the suggestion is discarded:
- Propose ONLY GENERAL METHODOLOGY / TRADECRAFT improvements (e.g. "sweep the whole vuln family before refuting it", "read your own error output before mutating", "verify the flag is present in real tool output").
- NEVER include a challenge-specific tell: no CVE id, flag path, literal flag value, version-pinned product, specific endpoint/host/port, or a challenge id paired with an answer. Those are FITTING and get rejected.
- You improve the operator's GENERAL skill, never memorize one target's solution.

Anchor each suggestion to an exact snippet of the CURRENT prompt. Reply with STRICT JSON only:
{"summary":"<1-2 sentences>","suggestions":[{"anchor":"<short exact snippet from current prompt>","currentText":"<exact line/passage to replace>","proposedText":"<improved replacement>","rationale":"<why, general>","severity":"high|medium|low"}]}
Propose 2-6 high-value suggestions; if the prompt is already strong, say so and return few/none.`;

export class Admiral {
  private llm: LLMBackbone;
  constructor(llm: LLMBackbone) { this.llm = llm; }

  /**
   * One conversational turn. `messages` is the full prior dialogue (user/assistant).
   * Returns the Admiral's reply plus the running mission brief + readiness.
   */
  async converse(messages: ChatMsg[]): Promise<AdmiralTurn> {
    const llmMessages = [
      { role: 'system' as const, content: ADMIRAL_SYSTEM_PROMPT },
      ...messages.map((m) => ({ role: m.role, content: m.content })),
    ];
    const res = await this.llm.chat(llmMessages, { maxTokens: 1024, temperature: 0.4 });
    try {
      return coerceTurn(extractJson(res.content || ''));
    } catch {
      // graceful fallback: keep the conversation alive even if the model didn't emit clean JSON
      return {
        reply: (res.content || '').slice(0, 600) || "Say that again — what's the target and what are we trying to prove?",
        brief: emptyBrief(),
        missing: ['objective', 'target', 'family', 'scope'],
        ready: false,
      };
    }
  }

  /**
   * Prompt-coach: analyze an operator's system prompt against a failure signal and propose
   * line-anchored GENERAL improvements. Every suggestion runs through the anti-fitting gate;
   * any challenge-specific tell is flagged REJECTED (the UI/auto-apply must skip it).
   */
  async suggest(operatorPrompt: string, failureSignal?: string): Promise<PromptAdvice> {
    const user = `CURRENT OPERATOR SYSTEM PROMPT:\n"""\n${String(operatorPrompt || '').slice(0, 8000)}\n"""\n\nFAILURE SIGNAL (what went wrong on the last run):\n"""\n${(failureSignal && failureSignal.trim()) ? failureSignal.slice(0, 6000) : 'No transcript provided — review for general weaknesses: gives up too early, ignores its own error/feedback, narrow vuln-family coverage, weak provenance/verification discipline.'}\n"""`;
    const res = await this.llm.chat(
      [{ role: 'system' as const, content: SUGGEST_SYSTEM_PROMPT }, { role: 'user' as const, content: user }],
      { maxTokens: 2000, temperature: 0.3 },
    );
    let parsed: any = {};
    try { parsed = extractJson(res.content || ''); } catch { parsed = { summary: (res.content || '').slice(0, 400), suggestions: [] }; }
    const raw = Array.isArray(parsed.suggestions) ? parsed.suggestions : [];
    let rejected = 0;
    const suggestions: PromptSuggestion[] = raw.slice(0, 8).map((s: any) => {
      const proposedText = String(s.proposedText || '');
      const check = isFittingTell(`${proposedText} ${String(s.rationale || '')} ${String(s.currentText || '')}`);
      if (check.tell) rejected++;
      return {
        anchor: String(s.anchor || '').slice(0, 200),
        currentText: String(s.currentText || '').slice(0, 800),
        proposedText: proposedText.slice(0, 800),
        rationale: String(s.rationale || '').slice(0, 400),
        severity: (['high', 'medium', 'low'].includes(s.severity) ? s.severity : 'medium') as 'high' | 'medium' | 'low',
        fittingCheck: check.tell ? 'REJECTED' : 'pass',
        fittingWhy: check.why,
      };
    });
    return { summary: String(parsed.summary || 'Reviewed the operator prompt.').slice(0, 600), suggestions, rejected };
  }
}

/** Map a completed brief into the Directive shape Op General consumes. */
export function briefToDirective(brief: MissionBrief): Directive {
  const opsec: OpsecLevel = brief.fidelity === 'live' ? 'covert' : 'silent';
  return {
    objective: brief.objective || `Engagement against ${brief.target}`,
    constraints: `mission_family=${brief.family || 'unspecified'}; fidelity=${brief.fidelity}; ` +
      (brief.fidelity === 'dry_run' ? 'DRY-RUN: plan only, no packets, no claimed findings.' : 'LIVE: authorized real packets within scope only.'),
    scopeHints: [brief.target, brief.scope].filter(Boolean).join(' — '),
    urgency: 'normal',
    opsecPreference: opsec,
  };
}

export const ADMIRAL_FAMILIES = FAMILIES;
