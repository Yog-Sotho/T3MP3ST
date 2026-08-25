// =============================================================================
// RATE-LIMIT / DEGRADED-HEALTH + LLM SEMAPHORE — Phase-0 pack-hunt safety primitive (HT-3)
// =============================================================================
// The exact cli-swarm lesson, ported into the engine path: N keyless local-agent operators share
// ONE subscription quota. Under a pack hunt they trip usage limits; several calls come back empty.
// If an empty/errored slot reads as "clean / found-nothing", the pack calls a rate-limited target
// CONVERGED. That is the failure this module exists to make impossible.
//
// Three pure, dependency-free primitives (no engine imports — safe to share everywhere):
//   1. isRateLimited(text)  — detect 429 / quota / usage-limit / rate-limit signatures.
//   2. DegradedTracker      — records ok/fail per local-agent call; a run where failures DOMINATE
//                             (>= 50%) verdicts INVALID_DEGRADED, NEVER a clean assessment.
//   3. Semaphore            — a correct bounded-concurrency async gate. A SINGLE GLOBAL instance
//                             (localAgentSemaphore) caps ALL local-agent calls across the pack, so
//                             8 operators behind one quota don't self-DoS into rate-limit hell.
//
// Ported verbatim from scripts/cli-swarm.mjs:
//   - the isRateLimited regex (cli-swarm.mjs:54-56).
//   - the degraded rule `backendFails / backendCalls >= 0.5 => INVALID_DEGRADED` (cli-swarm.mjs:355-358).
// =============================================================================

/**
 * True when `text` carries a rate-limit / quota-exhaustion / usage-limit / overload signature. A
 * local-agent call that hits its subscription quota returns an ERROR STRING, not findings — surface
 * it so the slot is flagged degraded and can NEVER be mistaken for a clean "found nothing".
 *
 * Broadened past cli-swarm's original (which missed Anthropic 529/"overloaded", Bedrock
 * "TooManyRequestsException", gRPC/Vertex "RESOURCE_EXHAUSTED", bare "throttled", and reversed
 * "exceeded your quota" phrasings) so a throttled reply can't slip through as a clean result. The
 * fail-safe direction is to OVER-flag degraded — a false positive just re-runs a slot; a false
 * negative books a rate-limited body as a clean assessment, the exact bug this guards.
 *
 * Word/phrase signatures fire anywhere; the numeric HTTP status codes (429/503/529) fire ONLY when
 * they read as a status/error, so a bare integer in benign output ("line 429", "CWE-529",
 * "4290 findings") does not false-positive.
 *
 * Signatures are provider ERROR-ENVELOPE tokens, NOT the bare English a security finding uses. In a
 * pack hunt the local-agent's own result body legitimately describes rate-limit / DoS vulnerabilities
 * ("rate limiting is MISSING on /login", "no rate-limit on password reset", "CWE-400 … service
 * unavailable", "slow down attacker", "concurrent request bug") — those must read as FINDINGS, not as a
 * throttled slot (adversarial review, 7th pass). So the ambiguous bare phrases were dropped: a limit
 * being HIT is matched ("rate limit exceeded/reached/hit", past-tense "rate-limited"), while a finding
 * that a limit is ABSENT is not. Genuine 503/"service unavailable" throttles are still caught via the
 * numeric HTTP-status regex.
 */
const RATE_LIMIT_SIGNATURES =
  /too[ _]?many[ _]?requests|throttl(?:ed|ing)|resource_exhausted|resource has been exhausted|overloaded(?!\s+(?:operator|function|method))|insufficient_quota|rate_limit_error|quota[ _]?exceeded|exceeded your (?:current )?quota|secondary rate limit|retry[ _-]?after|rate[ _-]?limited\b|(?:hit|reached|exceeded)\s+(?:your |the )?(?:usage|message)\s+limit|(?:usage|message)\s+limit\s+(?:reached|exceeded|hit)|rate[ _-]?limit(?:s|ing)?\s+(?:exceeded|reached|hit)|(?:exceed(?:ed)?|reach(?:ed)?|hit|would exceed|will exceed)\s+(?:the |your )?(?:[a-z'’-]+\s+)*rate[ _-]?limit/i;
const RATE_LIMIT_HTTP_STATUS =
  /(?:\bhttp\b|status|code|error)[\s:=/_-]*(?:429|503|529)\b|\b(?:429|503|529)\b\s*[:-]?\s*(?:too many|over[ _-]?load|service unavailable|rate|throttl|slow down)/i;

export function isRateLimited(text: string): boolean {
  const s = String(text ?? '');
  return RATE_LIMIT_SIGNATURES.test(s) || RATE_LIMIT_HTTP_STATUS.test(s);
}

/** Health verdict for a batch of local-agent calls. Mirrors cli-swarm's verdict vocabulary. */
export type DegradedVerdict = 'OK' | 'INVALID_DEGRADED';

/** Failures must DOMINATE for a run to be invalid: a few lost calls = partial coverage, not invalid. */
export const DEGRADED_THRESHOLD = 0.5;

/**
 * Accounting for a batch of local-agent (LLM backbone) calls. `record(ok)` per call; `verdict()` is
 * INVALID_DEGRADED once the failure ratio reaches DEGRADED_THRESHOLD — i.e. the assessment didn't
 * meaningfully run, so it must NOT read as "clean / secure". A run with zero calls is INVALID_DEGRADED
 * (nothing actually executed); a run with only successes is OK.
 *
 * Rule ported from scripts/cli-swarm.mjs:355 — `degraded = backendCalls > 0 && backendFails/backendCalls >= 0.5`.
 * (This tracker additionally treats the zero-call case as degraded: an engine slot that never ran is
 * not a clean result either.)
 */
export class DegradedTracker {
  /** total local-agent calls attempted */
  calls = 0;
  /** calls that failed (error, timeout, empty, or rate-limited) */
  fails = 0;

  /** Record one call outcome. `ok=false` for any error / timeout / empty / rate-limited result. */
  record(ok: boolean): void {
    this.calls += 1;
    if (!ok) this.fails += 1;
  }

  /**
   * Convenience: record a raw result string. A rate-limited body counts as a FAILURE even if the
   * call technically "returned", so a quota banner can never be booked as a good call.
   */
  recordResult(ok: boolean, text?: string): void {
    this.record(ok && !(text !== undefined && isRateLimited(text)));
  }

  /** Ratio of failed calls in [0,1]; 0 when no calls have been recorded. */
  failRatio(): number {
    return this.calls > 0 ? this.fails / this.calls : 0;
  }

  /**
   * INVALID_DEGRADED when failures dominate (>= DEGRADED_THRESHOLD of calls) OR nothing ran at all;
   * OK otherwise. A rate-limited slot must NEVER surface here as a clean / found-nothing verdict.
   */
  verdict(): DegradedVerdict {
    if (this.calls === 0) return 'INVALID_DEGRADED';
    return this.failRatio() >= DEGRADED_THRESHOLD ? 'INVALID_DEGRADED' : 'OK';
  }
}

/**
 * A correct bounded-concurrency async semaphore. `acquire()` resolves once a slot is free and hands
 * back a release function; call it exactly once when the guarded work finishes. Waiters are served
 * strictly FIFO. Never lets more than `max` holders run at once.
 *
 * A SINGLE GLOBAL instance (localAgentSemaphore) is meant to wrap every local-agent call across the
 * pack so N keyless operators on one shared quota don't stampede into rate-limits. Node's
 * single-threaded loop makes the counter mutations here genuinely atomic (no yield between check and
 * decrement in the acquire fast-path).
 */
export class Semaphore {
  private readonly max: number;
  private active = 0;
  private readonly waiters: Array<(() => void) | undefined> = [];
  private waitersHead = 0;

  constructor(max: number) {
    if (!Number.isFinite(max) || max < 1) {
      throw new RangeError(`Semaphore max must be a finite integer >= 1 (got ${max})`);
    }
    this.max = Math.floor(max);
  }

  /** Number of holders currently inside the guarded section (for tests / introspection). */
  get inFlight(): number {
    return this.active;
  }

  /** Number of callers currently blocked in acquire() waiting for a slot. */
  get queued(): number {
    return this.waiters.length - this.waitersHead;
  }

  /**
   * Acquire a slot. Resolves with an idempotent release fn — calling it more than once is a no-op,
   * so a double-release can't inflate the pool past `max`.
   */
  acquire(): Promise<() => void> {
    return new Promise<() => void>((resolve) => {
      const grant = (): void => {
        this.active += 1;
        let released = false;
        resolve(() => {
          if (released) return; // idempotent: guard against double-release
          released = true;
          this.active -= 1;
          // ⚡ BOLT OPTIMIZATION: Avoid $O(N)$ Array.prototype.shift() re-indexing on every release.
          // Use an O(1) read pointer index (`waitersHead`) and clear the array buffer when drained
          // or periodically pruned.
          let next: (() => void) | undefined;
          if (this.waitersHead < this.waiters.length) {
            next = this.waiters[this.waitersHead];
            this.waiters[this.waitersHead] = undefined;
            this.waitersHead++;
            if (this.waitersHead === this.waiters.length) {
              this.waiters.length = 0;
              this.waitersHead = 0;
            } else if (this.waitersHead > 1024 && this.waitersHead > (this.waiters.length >> 1)) {
              this.waiters.splice(0, this.waitersHead);
              this.waitersHead = 0;
            }
          }
          if (next) next();
        });
      };
      if (this.active < this.max) grant();
      else this.waiters.push(grant);
    });
  }

  /** Run `fn` while holding a slot; always releases, even if `fn` throws. */
  async run<T>(fn: () => Promise<T>): Promise<T> {
    const release = await this.acquire();
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

/**
 * Global concurrency cap over ALL local-agent (LLM backbone) calls across a pack hunt. One shared
 * subscription quota => a single global semaphore, NOT one per operator (per HT-3). Bound from
 * T3MP3ST_LLM_CONCURRENCY (default 2). Wrap every local-agent dispatch in
 * `localAgentSemaphore.run(() => localAgentChat(...))`.
 */
function resolveConcurrency(): number {
  const raw = parseInt((process.env.T3MP3ST_LLM_CONCURRENCY || '').trim(), 10);
  return Number.isFinite(raw) && raw >= 1 ? raw : 2;
}

export const localAgentSemaphore = new Semaphore(resolveConcurrency());
