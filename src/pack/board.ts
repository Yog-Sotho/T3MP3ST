/**
 * T3MP3ST Pack Hunt — PackBoard (Phase-2 shared workspace / lead-board)
 *
 * An APPEND-ONLY event log + folded projections (a leads map, live claims, per-agent
 * heartbeats), on the same EventEmitter discipline as `EvidenceVault`
 * (src/evidence/index.ts). This is the pack's shared workspace: agents post leads, claim
 * work so they don't re-tread, and endorse/refute each other — and each agent is threaded
 * a BOUNDED `situationReport()` at task start instead of the raw board.
 *
 * See the pack-hunt design. The three red-team invariants this file
 * is responsible for (§2):
 *  - HT-1: `claim()` is a REAL synchronous compare-and-set — no `await` between the version
 *    read and the write, so Node's single-threaded loop makes it genuinely atomic.
 *  - HT-1: de-dup collapses an honest duplicate into an *endorsement* that raises `smoke`,
 *    never a second lead card.
 *  - HT-2: `refute()` only APPENDS a refutation vote; it never unilaterally flips `status`.
 *    Flipping to refuted is the audit quorum's job (Phase-3), gated on `guardExistsInSource()`.
 *
 * The board mirrors lightweight finding *cards*; it is NOT the vault and does not gate
 * provenance. `where.targetId` is the foreign key back to the provenance-gated `Finding.id`.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import type { Severity } from '../types/index.js';
import type {
  AgentActivity,
  AgentStatus,
  BoardEvent,
  Lead,
  LeadProvenance,
  LeadVote,
} from './types.js';

// =============================================================================
// dedupKey — reused VERBATIM from scripts/cli-swarm.mjs (the `dedupKey` formula).
// file::CWE::line-bucket(15). Two posts that map to the same key are the SAME lead.
// We accept the cli-swarm finding shape ({file, cwe, line}) so a card built from a
// specialist's JSON row keys identically to how the swarm already de-dups.
// =============================================================================

/**
 * Collision key for de-dup. Extends cli-swarm's `file::CWE::line-bucket(15)` with two fixes:
 *  - vulnClass is folded in, so two DIFFERENT vuln classes at the same file:line-bucket (an XSS and
 *    an SQLi a line apart, or two classes when CWE is absent) never silently shadow each other.
 *  - a coordinate-less lead (no `file` — a recon/networked lead carrying only a `url`) keys on the
 *    surface + class, so every url-only lead doesn't collapse into a single empty-file-bucket card.
 */
export function dedupKey(f: { file?: string; cwe?: string; line?: number; vulnClass?: string; url?: string }): string {
  const cls = `${(f.cwe || '').toUpperCase()}::${(f.vulnClass || '').toLowerCase()}`;
  if (f.file) return `${f.file.toLowerCase()}::${cls}::${Math.round((f.line || 0) / 15)}`;
  if (f.url) return `url::${f.url.toLowerCase()}::${cls}`;
  return `::${cls}::${Math.round((f.line || 0) / 15)}`;
}

// =============================================================================
// EVENTS — typed emit, same pattern as EvidenceVaultEvents.
// `board:event` fires on EVERY mutation (the raw log entry); the specific events are
// conveniences for subscribers that only care about one kind.
// =============================================================================

export interface PackBoardEvents {
  'board:event': BoardEvent;
  'lead:posted': Lead;
  'lead:endorsed': Lead;
  'lead:refuted': Lead;
  'lead:claimed': { lead: Lead; agentId: string };
  'lead:claim-denied': { leadId: string; agentId: string; version: number };
  'lead:claim-released': { lead: Lead; reason: 'expired' | 'released' };
  'lead:status-changed': { lead: Lead; from: Lead['status']; to: Lead['status'] };
  'agent:heartbeat': AgentStatus;
}

// =============================================================================
// INPUT SHAPES — what a caller supplies. The board owns id / dedupKey / version /
// smoke / timestamps / vote arrays, so callers can't forge them.
// =============================================================================

/** The caller-supplied fields of a new lead. The board derives everything else. If a
 *  `dedupKey` is not supplied it is computed from `where` + `cwe` via cli-swarm's formula. */
export interface LeadInput {
  kind: Lead['kind'];
  title: string;
  where: Lead['where'];
  vulnClass: string;
  confidence: Lead['confidence'];
  provenance: LeadProvenance;
  /** CWE id (e.g. "CWE-22") — folded into the dedupKey exactly like cli-swarm does. */
  cwe?: string;
  /** Explicit override of the computed dedupKey (rare; tests / cross-surface merges). */
  dedupKey?: string;
  severity?: Lead['severity'];
}

// =============================================================================
// CONFIG — bounds that keep the situation report from ever dumping the raw board.
// =============================================================================

export interface PackBoardConfig {
  /** Hard upper bound on the length of any `situationReport()` string. Never exceeded. */
  reportCharCap: number;
  /** Default number of top-smoke unclaimed leads to include when the caller omits maxLeads. */
  defaultMaxLeads: number;
  /** An agent whose last heartbeat is older than this (ms) is treated as `gone` / not live. */
  livenessWindowMs: number;
}

export const DEFAULT_PACKBOARD_CONFIG: PackBoardConfig = {
  reportCharCap: 4000,
  defaultMaxLeads: 8,
  livenessWindowMs: 90_000,
};

// =============================================================================
// PACK BOARD
// =============================================================================

export class PackBoard extends EventEmitter<PackBoardEvents> {
  /** The append-only log. Never mutated in place; only pushed. The single source of truth. */
  private readonly log: BoardEvent[] = [];

  /** Folded projection: the current leads, keyed by lead id. */
  private readonly leads: Map<string, Lead> = new Map();

  /** Fast index dedupKey → leadId, so a duplicate post collapses in O(1). */
  private readonly byDedup: Map<string, string> = new Map();

  /** Folded projection: latest heartbeat per agent. */
  private readonly agents: Map<string, AgentStatus> = new Map();

  private readonly cfg: PackBoardConfig;

  /** Injected clock — defaults to Date.now, overridable so tests are deterministic. */
  private readonly now: () => number;

  constructor(config: Partial<PackBoardConfig> = {}, now: () => number = Date.now) {
    super();
    this.cfg = { ...DEFAULT_PACKBOARD_CONFIG, ...config };
    this.now = now;
  }

  // ---------------------------------------------------------------------------
  // internal: append one entry to the log + emit. The ONLY writer of `this.log`.
  // ---------------------------------------------------------------------------
  private append(
    type: BoardEvent['type'],
    actor: string,
    leadId?: string,
    data?: Record<string, unknown>,
  ): BoardEvent {
    const ev: BoardEvent = { id: randomUUID(), type, actor, leadId, data, at: this.now() };
    this.log.push(ev);
    this.emit('board:event', ev);
    return ev;
  }

  // ---------------------------------------------------------------------------
  // internal helpers: evidence ranking + defensive snapshots.
  // ---------------------------------------------------------------------------

  /** A real tool reproduction outranks a context guess outranks none. */
  private static provenanceRank(p: LeadProvenance): number {
    return p === 'tool' ? 2 : p === 'context' ? 1 : 0;
  }

  /** Severity rank (higher = worse); unknown/undefined ranks lowest. */
  private static severityRank(s?: Severity): number {
    const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return s ? rank[s] : -1;
  }

  /**
   * Monotonically upgrade a card's evidence from a duplicate post: adopt the incoming provenance /
   * severity ONLY when stronger than what the card already carries (never downgrade). Called on the
   * de-dup collapse so a second, better-sourced find of the same bug isn't thrown away.
   */
  private upgradeEvidence(lead: Lead, input: { provenance: LeadProvenance; severity?: Severity }): void {
    if (PackBoard.provenanceRank(input.provenance) > PackBoard.provenanceRank(lead.provenance)) {
      lead.provenance = input.provenance;
    }
    if (input.severity && PackBoard.severityRank(input.severity) > PackBoard.severityRank(lead.severity)) {
      lead.severity = input.severity;
    }
  }

  /** A defensive deep copy of a lead. The board NEVER hands out a live reference to its internal
   *  projection — a caller mutating `version`/`status`/`claim` would bypass the CAS + quorum. */
  private snapshotLead(lead: Lead): Lead {
    return structuredClone(lead);
  }

  // ===========================================================================
  // postLead — de-dup via dedupKey. A duplicate collapses into an ENDORSEMENT
  // that raises smoke, NEVER a new lead card (HT-1).
  // ===========================================================================
  postLead(actor: string, input: LeadInput): Lead {
    const key =
      input.dedupKey ||
      dedupKey({
        file: input.where.file,
        cwe: input.cwe,
        line: input.where.line,
        vulnClass: input.vulnClass,
        url: input.where.url,
      });

    const existingId = this.byDedup.get(key);
    if (existingId !== undefined) {
      const existing = this.leads.get(existingId);
      if (existing) {
        // Honest duplicate → monotonically upgrade the card with any STRONGER evidence the second
        // finder brought (never downgrade), then fold into an endorsement (chase-the-smoke). NOTE
        // (HT-2): a duplicate of a quorum-refuted card is recorded as an endorsement but does NOT
        // resurface it — a verified refutation is sticky; re-finding it must not re-open it.
        this.upgradeEvidence(existing, input);
        return this.endorse(actor, existing.id, `duplicate: ${input.title}`) ?? this.snapshotLead(existing);
      }
    }

    const t = this.now();
    const lead: Lead = {
      id: randomUUID(),
      dedupKey: key,
      kind: input.kind,
      title: input.title,
      // Clone on INGEST too (not just on the outbound snapshot): a caller that retains and later mutates
      // the `where` object it passed in must not be able to re-point the board's internal projection —
      // that would poison situationReport() coords and desync the frozen dedupKey. Mirrors the board's
      // no-live-reference invariant on the inbound path.
      where: { ...input.where },
      vulnClass: input.vulnClass,
      confidence: input.confidence,
      status: 'open',
      smoke: 1,
      postedBy: actor,
      endorsements: [],
      refutations: [],
      provenance: input.provenance,
      version: 0,
      postedAt: t,
      updatedAt: t,
      severity: input.severity,
    };
    this.leads.set(lead.id, lead);
    this.byDedup.set(key, lead.id);
    this.append('lead:posted', actor, lead.id, { dedupKey: key, kind: lead.kind });
    this.emit('lead:posted', this.snapshotLead(lead));
    return this.snapshotLead(lead);
  }

  // ===========================================================================
  // claim — a REAL synchronous compare-and-set. There is NO `await` anywhere
  // between the version read and the write, so on Node's single-threaded loop
  // this is genuinely atomic: two calls racing the same expectedVersion can only
  // have ONE win (HT-1). Grants a lease; an already-held live lease blocks.
  // ===========================================================================
  claim(
    leadId: string,
    agentId: string,
    expectedVersion: number,
    leaseMs = 120_000,
  ): { granted: boolean; version: number } {
    const lead = this.leads.get(leadId);
    if (!lead) return { granted: false, version: -1 };

    // A quorum-terminal lead (confirmed / refuted / dead) is NOT claimable — a verified refutation is
    // sticky (HT-2), so re-claiming can never resurrect a killed lead back into active work.
    if (lead.status === 'refuted' || lead.status === 'confirmed' || lead.status === 'dead') {
      this.append('lead:claim-denied', agentId, lead.id, { reason: 'terminal', status: lead.status, version: lead.version });
      this.emit('lead:claim-denied', { leadId, agentId, version: lead.version });
      return { granted: false, version: lead.version };
    }

    // --- BEGIN atomic critical section (no await past this point until write) ---
    const t = this.now();

    // Someone else holds a live (unexpired) lease → deny, regardless of version.
    if (lead.claim && lead.claim.leaseUntil > t && lead.claim.by !== agentId) {
      this.append('lead:claim-denied', agentId, lead.id, { reason: 'held', version: lead.version });
      this.emit('lead:claim-denied', { leadId, agentId, version: lead.version });
      return { granted: false, version: lead.version };
    }

    // Compare-and-set: the caller's view of the lead must be current.
    if (lead.version !== expectedVersion) {
      this.append('lead:claim-denied', agentId, lead.id, { reason: 'stale-version', version: lead.version });
      this.emit('lead:claim-denied', { leadId, agentId, version: lead.version });
      return { granted: false, version: lead.version };
    }

    // Win: bump version (invalidates every other racer's expectedVersion), set the lease.
    lead.version += 1;
    lead.claim = { by: agentId, leaseUntil: t + leaseMs, version: lead.version };
    lead.updatedAt = t;
    this.setStatus(lead, 'claimed', agentId);
    // --- END atomic critical section ---

    this.append('lead:claimed', agentId, lead.id, { version: lead.version, leaseUntil: lead.claim.leaseUntil });
    this.emit('lead:claimed', { lead: this.snapshotLead(lead), agentId });
    return { granted: true, version: lead.version };
  }

  // ===========================================================================
  // releaseExpiredClaims — the lease reaper (the same timeout-backstop idea that
  // reaps wedged dispatches). Frees any lease whose leaseUntil has passed and
  // returns the lead to `open` so another agent can take it.
  // ===========================================================================
  releaseExpiredClaims(now: number = this.now()): string[] {
    const released: string[] = [];
    for (const lead of this.leads.values()) {
      if (lead.claim && lead.claim.leaseUntil <= now) {
        const holder = lead.claim.by;
        delete lead.claim;
        lead.version += 1;
        lead.updatedAt = now;
        // only demote back to open if it's still merely claimed (don't clobber confirmed/refuted)
        if (lead.status === 'claimed') this.setStatus(lead, 'open', holder);
        this.append('lead:claim-released', holder, lead.id, { reason: 'expired', version: lead.version });
        this.emit('lead:claim-released', { lead: this.snapshotLead(lead), reason: 'expired' });
        released.push(lead.id);
      }
    }
    return released;
  }

  /** Voluntarily release a claim you hold (e.g. work finished / abandoned). No-op if you
   *  don't hold the live lease. Returns the freed lead, or undefined. */
  releaseClaim(agentId: string, leadId: string): Lead | undefined {
    const lead = this.leads.get(leadId);
    if (!lead || !lead.claim || lead.claim.by !== agentId) return undefined;
    delete lead.claim;
    lead.version += 1;
    lead.updatedAt = this.now();
    if (lead.status === 'claimed') this.setStatus(lead, 'open', agentId);
    this.append('lead:claim-released', agentId, lead.id, { reason: 'released', version: lead.version });
    this.emit('lead:claim-released', { lead: this.snapshotLead(lead), reason: 'released' });
    return this.snapshotLead(lead);
  }

  // ===========================================================================
  // endorse — append-only vote that raises smoke (chase-the-smoke priority).
  // ===========================================================================
  endorse(actor: string, leadId: string, note?: string): Lead | undefined {
    const lead = this.leads.get(leadId);
    if (!lead) return undefined;
    const vote: LeadVote = { by: actor, note, at: this.now() };
    lead.endorsements.push(vote);
    lead.smoke += 1;
    lead.version += 1;
    lead.updatedAt = vote.at;
    this.append('lead:endorsed', actor, lead.id, { smoke: lead.smoke });
    this.emit('lead:endorsed', this.snapshotLead(lead));
    return this.snapshotLead(lead);
  }

  // ===========================================================================
  // refute — APPEND-ONLY. Records a refutation vote (and optional cited guard) but
  // NEVER flips status by itself (HT-2). Only the audit quorum (Phase-3), after
  // guardExistsInSource() verifies the cited guard, may set status to 'refuted'.
  // A `refute()` here is a signal, not a verdict.
  // ===========================================================================
  refute(actor: string, leadId: string, note?: string, guard?: string): Lead | undefined {
    const lead = this.leads.get(leadId);
    if (!lead) return undefined;
    const vote: LeadVote = { by: actor, note, guard, at: this.now() };
    lead.refutations.push(vote);
    lead.version += 1;
    lead.updatedAt = vote.at;
    // NOTE: status is intentionally NOT changed here. See method doc + HT-2.
    this.append('lead:refuted', actor, lead.id, { refutations: lead.refutations.length, guard: guard ?? null });
    this.emit('lead:refuted', this.snapshotLead(lead));
    return this.snapshotLead(lead);
  }

  // ===========================================================================
  // heartbeat — per-agent liveness projection.
  // ===========================================================================
  heartbeat(agentId: string, activity: AgentActivity, note?: string): AgentStatus {
    const status: AgentStatus = { agentId, activity, note, lastSeen: this.now() };
    this.agents.set(agentId, status);
    this.append('agent:heartbeat', agentId, undefined, { activity });
    this.emit('agent:heartbeat', status);
    return status;
  }

  // ---------------------------------------------------------------------------
  // internal: status transition (the ONLY path that changes Lead.status).
  // The board only ever drives open ⇄ claimed. confirmed/refuted/dead are set by
  // the quorum through `setLeadStatus`, kept separate so the board never flips a
  // status on agreement alone.
  // ---------------------------------------------------------------------------
  private setStatus(lead: Lead, to: Lead['status'], actor: string): void {
    if (lead.status === to) return;
    const from = lead.status;
    lead.status = to;
    lead.updatedAt = this.now();
    this.append('lead:status-changed', actor, lead.id, { from, to });
    this.emit('lead:status-changed', { lead: this.snapshotLead(lead), from, to });
  }

  /**
   * Quorum-only status setter (Phase-3 hook). The audit coordinator calls this to promote a
   * card to `confirmed` (after strict-majority + independent reproduction + gate) or `refuted`
   * (after guardExistsInSource() verified a cited guard) or retire it as `dead`. It is NOT
   * called by `endorse()`/`refute()` — those only append votes.
   */
  setLeadStatus(actor: string, leadId: string, to: Lead['status']): Lead | undefined {
    const lead = this.leads.get(leadId);
    if (!lead) return undefined;
    lead.version += 1;
    this.setStatus(lead, to, actor);
    return this.snapshotLead(lead);
  }

  // ===========================================================================
  // situationReport — a BOUNDED string threaded into an agent's prompt at task
  // start. It NEVER dumps the raw board: top-K unclaimed leads by smoke, YOUR own
  // claims, refuted-guard keys to avoid, and the live agents — hard-capped to
  // cfg.reportCharCap chars. Mirrors cli-swarm's renderBoard four-section layout.
  // ===========================================================================
  situationReport(forAgentId: string, opts: { maxLeads?: number } = {}): string {
    const cap = this.cfg.reportCharCap;
    const maxLeads = Math.max(0, opts.maxLeads ?? this.cfg.defaultMaxLeads);
    const now = this.now();

    // Perform single-pass allocation-free classification directly over Map values to avoid
    // generating intermediate arrays (e.g. Array.from(this.leads.values())) or multiple filter passes.
    let totalLeads = 0;
    const unclaimed: Lead[] = [];
    const mine: Lead[] = [];
    const refuted: Lead[] = [];

    for (const l of this.leads.values()) {
      totalLeads++;
      if (l.status === 'open' && !(l.claim && l.claim.leaseUntil > now)) {
        unclaimed.push(l);
      }
      if (l.claim && l.claim.by === forAgentId && l.claim.leaseUntil > now) {
        mine.push(l);
      }
      if (l.status === 'refuted') {
        refuted.push(l);
      }
    }

    // ── top-K UNCLAIMED open leads, ranked by smoke (chase-the-smoke), then recency ──
    if (maxLeads > 0 && unclaimed.length > 0) {
      unclaimed.sort((a, b) => b.smoke - a.smoke || b.updatedAt - a.updatedAt);
      if (unclaimed.length > maxLeads) {
        unclaimed.length = maxLeads;
      }
    } else if (maxLeads === 0) {
      unclaimed.length = 0;
    }

    // ── live agents (fresh heartbeat within the liveness window) ──
    const live: AgentStatus[] = [];
    for (const a of this.agents.values()) {
      if (a.activity !== 'gone' && now - a.lastSeen <= this.cfg.livenessWindowMs) {
        live.push(a);
      }
    }
    if (live.length > 1) {
      live.sort((a, b) => b.lastSeen - a.lastSeen);
    }

    const lines: string[] = [];
    lines.push(`PACK BOARD — situation for ${forAgentId} (${totalLeads} lead(s) total)`);

    if (unclaimed.length) {
      lines.push('OPEN LEADS — unclaimed, hottest first (claim before you dig; don\'t re-tread):');
      for (const l of unclaimed) {
        lines.push(`  ? [smoke ${l.smoke}/${l.confidence}/${l.vulnClass}] ${this.coords(l)} — ${clip(l.title, 90)} (v${l.version})`);
      }
    }
    if (mine.length) {
      lines.push('YOUR CLAIMS (you hold the lease — finish or release):');
      for (const l of mine) {
        lines.push(`  ◉ ${this.coords(l)} — ${clip(l.title, 90)} (lease→${l.claim?.leaseUntil ?? 0})`);
      }
    }
    if (refuted.length) {
      lines.push('REFUTED / CLEARED (quorum killed these — do NOT resurface):');
      const refutedSlice = refuted.length > maxLeads ? refuted.slice(0, maxLeads) : refuted;
      for (const l of refutedSlice) {
        const g = l.refutations.find((r) => r.guard)?.guard;
        lines.push(`  ✗ ${this.coords(l)} — ${clip(l.title, 70)}${g ? ` (guard: ${clip(g, 60)})` : ''}`);
      }
    }
    if (live.length) {
      lines.push(`LIVE AGENTS: ${live.map((a) => `${a.agentId}:${a.activity}`).join(', ')}`);
    }

    return boundedJoin(lines, cap);
  }

  // ---------------------------------------------------------------------------
  // display coords: prefer file:line, fall back to url, then the vault FK.
  // ---------------------------------------------------------------------------
  private coords(l: Lead): string {
    if (l.where.file) return `${l.where.file}:${l.where.line ?? '?'}`;
    if (l.where.url) return l.where.url;
    if (l.where.targetId) return `finding:${l.where.targetId}`;
    return l.dedupKey;
  }

  // ===========================================================================
  // read-only projection accessors (for the controller / tests / SSE).
  // ===========================================================================

  /** The append-only log (defensive DEEP copy — callers cannot mutate history or entry payloads). */
  getLog(): BoardEvent[] {
    return this.log.map((e) => structuredClone(e));
  }

  getLead(leadId: string): Lead | undefined {
    const lead = this.leads.get(leadId);
    return lead ? this.snapshotLead(lead) : undefined;
  }

  getAllLeads(): Lead[] {
    return Array.from(this.leads.values(), (l) => this.snapshotLead(l));
  }

  /** Open, currently-unclaimed leads (what a fresh agent can pick up). */
  getOpenLeads(now: number = this.now()): Lead[] {
    const openLeads: Lead[] = [];
    for (const l of this.leads.values()) {
      if (l.status === 'open' && !(l.claim && l.claim.leaseUntil > now)) {
        openLeads.push(this.snapshotLead(l));
      }
    }
    return openLeads;
  }

  getAgents(): AgentStatus[] {
    const agents: AgentStatus[] = [];
    for (const a of this.agents.values()) {
      agents.push({ ...a });
    }
    return agents;
  }

  /** Agents whose last heartbeat is within the liveness window. */
  getLiveAgents(now: number = this.now()): AgentStatus[] {
    const liveAgents: AgentStatus[] = [];
    for (const a of this.agents.values()) {
      if (a.activity !== 'gone' && now - a.lastSeen <= this.cfg.livenessWindowMs) {
        liveAgents.push({ ...a });
      }
    }
    return liveAgents;
  }
}

// =============================================================================
// helpers — pure string bounding
// =============================================================================

/** Clip a string to `n` chars with an ellipsis, so no single field blows the budget. */
function clip(s: string, n: number): string {
  const str = String(s ?? '');
  return str.length <= n ? str : `${str.slice(0, Math.max(0, n - 1))}…`;
}

/**
 * Join lines with '\n' but NEVER exceed `cap` chars. If the full join fits, return it.
 * Otherwise take as many whole leading lines as fit, and append a truncation marker that
 * itself is accounted for in the budget — the returned string is guaranteed <= cap.
 */
function boundedJoin(lines: string[], cap: number): string {
  const full = lines.join('\n');
  if (full.length <= cap) return full;

  const marker = '\n…(truncated)';
  const budget = Math.max(0, cap - marker.length);
  const out: string[] = [];
  let used = 0;
  for (const line of lines) {
    const add = out.length === 0 ? line.length : line.length + 1; // +1 for the '\n'
    if (used + add > budget) break;
    out.push(line);
    used += add;
  }
  const joined = out.join('\n') + marker;
  // Final belt-and-suspenders: hard-slice in the pathological case of a single over-long line.
  return joined.length <= cap ? joined : joined.slice(0, cap);
}
