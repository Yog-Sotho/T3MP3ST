/**
 * Attack-Graph scaffolding — the data contract that recon agents fill, and a
 * deterministic family-aware scaffold generator.
 *
 * THE SPLIT (read before editing):
 *   - The STRUCTURE of the attack graph is generated per-target by recon (it
 *     looks different for a repo audit vs a pentest vs a smart-contract vs a
 *     model endpoint). This module defines the schema operators emit, plus a
 *     deterministic scaffold to seed/guide them and to render before live recon
 *     has populated anything.
 *   - The VISUAL STYLE is owned by ONE renderer in the UI (renderBoard in
 *     docs/war-room.html). Any conforming AttackGraph renders in the same look.
 *
 * HONESTY: a scaffold is a STARTING SKELETON, not findings. Scaffold nodes are
 * marked status 'probing'/'hypothesized' (recon-pending). Only the verify
 * pipeline promotes a node to 'verified' with an evidence hash.
 */

export type NodeKind = 'target_root' | 'service' | 'finding' | 'sink' | 'pivot';
export type NodeStatus = 'verified' | 'active' | 'probing' | 'hypothesized' | 'discarded';
export type EdgeKind = 'proven' | 'hypothesized' | 'discarded';

export interface AttackGraphNode {
  id: string;
  label: string;          // short display label, e.g. "deserializer"
  phase: string;          // one of graph.phases
  kind: NodeKind;
  status: NodeStatus;
  operator?: string;      // assigned operator callsign, e.g. "GHOST"
  evidence?: string;      // provenance hash once verified, e.g. "ev#a4f9"
  note?: string;          // short annotation, e.g. "dup-cve" / "no-poc"
}

export interface AttackGraphEdge {
  from: string;
  to: string;
  kind: EdgeKind;
}

export interface AttackGraphKillcam {
  nodeId: string;
  chain: string[];        // e.g. ["live target","tool output","flag bytes"]
  evidence: string;       // e.g. "evidence#a4f9c2"
  fidelity: 'LIVE' | 'SIM';
}

export interface AttackGraph {
  target: string;
  family: string;
  phases: string[];       // ordered column headers, left → right
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  killcam?: AttackGraphKillcam;
  source: 'scaffold' | 'recon';   // honest provenance of the structure
}

// ── phase columns per mission family (the kill-chain shape differs by target type) ──
const PHASES: Record<string, string[]> = {
  zero_day_hunt: ['SURFACE', 'ENTRYPOINTS', 'SINKS', 'PRIMITIVE', 'IMPACT'],
  repo_audit:    ['SURFACE', 'ENTRYPOINTS', 'SINKS', 'PRIMITIVE', 'IMPACT'],
  pentest:       ['RECON', 'FOOTHOLD', 'PRIVESC', 'LATERAL', 'EXFIL'],
  smart_contract:['SURFACE', 'ENTRYPOINTS', 'STATE', 'INVARIANT', 'IMPACT'],
  ai_red_team:   ['PROBE', 'ELICIT', 'BYPASS', 'EXFIL'],
  ctf_range:     ['RECON', 'FOOTHOLD', 'EXPLOIT', 'FLAG'],
  default:       ['RECON', 'FOOTHOLD', 'PRIVESC', 'LATERAL', 'EXFIL'],
};

// vocab the recon scaffold draws candidate nodes from (clearly recon-pending, not findings)
const VOCAB: Record<string, string[]> = {
  zero_day_hunt: ['parser', 'codec', 'deserializer', 'net-io', 'alloc', 'session', 'frame-hdr', 'length-field', 'state-machine'],
  repo_audit:    ['parser', 'codec', 'deserializer', 'net-io', 'alloc', 'session', 'frame-hdr', 'length-field', 'sink'],
  pentest:       ['/login', '/api', '/admin', '/upload', 'session', 'jwt', 'smb', 'rdp', 'metadata'],
  smart_contract:['withdraw()', 'deposit()', '_transfer', 'oracle', 'vault', 'collateral', 'price-feed', 'reentry'],
  ai_red_team:   ['system-prompt', 'tool-router', 'context-window', 'guardrail', 'refusal-edge', 'memory'],
  ctf_range:     ['port-1337', '/cgi-bin', 'binary', 'libc', 'canary', 'overflow'],
  default:       ['service', 'endpoint', 'sink', 'pivot', 'creds'],
};

const OPERATORS = ['WRAITH', 'GHOST', 'RAVEN', 'CIPHER', 'ORACLE', 'QUARRY', 'SERAPH', 'STRATUS'];

// stable string hash → deterministic-but-varied scaffolds (no Math.random; same target = same skeleton)
function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}

function rootLabel(target: string): string {
  const t = target.replace(/^https?:\/\//, '').replace(/\/$/, '');
  const seg = t.split('/').filter(Boolean);
  if (/^0x[0-9a-fA-F]{6,}/.test(t)) return t.slice(0, 10) + '…';
  return (seg[seg.length - 1] || seg[0] || t).slice(0, 18);
}

export function familyPhases(family: string): string[] {
  return PHASES[family] || PHASES.default;
}

/**
 * Produce a deterministic scaffold for a target+family: phase columns, a
 * target_root, and 3-5 recon-pending candidate nodes drawn from the family
 * vocab. This is the SKELETON recon starts from — every node is probing /
 * hypothesized, NOT a finding. Different targets/families yield different
 * topologies; the renderer draws them all in the same style.
 */
export function scaffoldAttackGraph(target: string, family: string): AttackGraph {
  const phases = familyPhases(family);
  const vocab = VOCAB[family] || VOCAB.default;
  const h = hash(target + '|' + family);
  const root: AttackGraphNode = { id: 'root', label: rootLabel(target), phase: phases[0], kind: 'target_root', status: 'active' };

  const nodes: AttackGraphNode[] = [root];
  const edges: AttackGraphEdge[] = [];

  // node count scales with target complexity proxy (length) — bigger targets, busier boards
  const count = 3 + (h % 3) + Math.min(2, Math.floor(target.length / 24)); // 3..7
  let prevId = 'root';
  for (let i = 0; i < count; i++) {
    // unsigned shifts — a signed >> goes negative once the hash exceeds 2^31, yielding a
    // negative modulo / out-of-range index (which silently dropped node labels).
    const v = vocab[(h >>> (i * 3)) % vocab.length] || vocab[i % vocab.length] || 'node';
    const phase = phases[Math.min(1 + Math.floor(i * (phases.length - 1) / count), phases.length - 1)];
    const id = `n${i}`;
    const probing = i < 2;
    nodes.push({
      id, label: v, phase,
      kind: phase === phases[phases.length - 1] ? 'sink' : 'service',
      status: probing ? 'probing' : 'hypothesized',
      operator: OPERATORS[(h >>> i) % OPERATORS.length],
    });
    // chain the early nodes off the root, later nodes off the previous (a forming path)
    edges.push({ from: i === 0 ? 'root' : prevId, to: id, kind: 'hypothesized' });
    if (i >= 1 && ((h >>> i) & 1)) edges.push({ from: 'root', to: id, kind: 'discarded' });
    prevId = id;
  }

  return { target, family, phases, nodes, edges, source: 'scaffold' };
}

/** JSON-schema-ish contract handed to recon agents so they emit conforming graphs. */
export const ATTACK_GRAPH_SCHEMA = {
  type: 'object',
  required: ['target', 'family', 'phases', 'nodes', 'edges'],
  properties: {
    target: { type: 'string' },
    family: { type: 'string' },
    phases: { type: 'array', items: { type: 'string' }, description: 'ordered kill-chain column headers, left→right' },
    nodes: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'label', 'phase', 'kind', 'status'],
        properties: {
          id: { type: 'string' },
          label: { type: 'string', description: 'short, ≤18 chars' },
          phase: { type: 'string', description: 'must be one of phases[]' },
          kind: { enum: ['target_root', 'service', 'finding', 'sink', 'pivot'] },
          status: { enum: ['verified', 'active', 'probing', 'hypothesized', 'discarded'] },
          operator: { type: 'string' },
          evidence: { type: 'string' },
          note: { type: 'string' },
        },
      },
    },
    edges: {
      type: 'array',
      items: {
        type: 'object',
        required: ['from', 'to', 'kind'],
        properties: { from: { type: 'string' }, to: { type: 'string' }, kind: { enum: ['proven', 'hypothesized', 'discarded'] } },
      },
    },
  },
} as const;

/** System prompt that guides a recon operator to map a target into the schema. */
export function attackGraphReconPrompt(target: string, family: string): string {
  const phases = familyPhases(family);
  return `You are a RECON operator mapping an attack surface into a structured attack graph.

TARGET: ${target}
FAMILY: ${family}
PHASE COLUMNS (left→right kill-chain): ${phases.join(' → ')}

Emit the surface you actually observe as an attack graph: one target_root node, then the real components/endpoints/sinks you map, placed in the right phase column, with edges showing how an attacker would move between them.

INTEGRITY RULES:
- Only mark a node 'verified' with an evidence hash if the verify pipeline confirmed it. Recon output is 'probing' (actively mapped) or 'hypothesized' (suspected, unconfirmed).
- An edge is 'proven' only with an executed PoC across it; otherwise 'hypothesized'. Dead/discarded paths are 'discarded'.
- Keep labels short (≤18 chars). Do not invent findings.

Return ONLY a JSON object matching the attack-graph schema (target, family, phases, nodes[], edges[]).`;
}

// Fast-path module-level Sets for O(1) membership checks during graph validation (avoid array allocations and .includes() scans)
const VALID_KINDS = new Set<string>(['target_root', 'service', 'finding', 'sink', 'pivot']);
const VALID_STATUSES = new Set<string>(['verified', 'active', 'probing', 'hypothesized', 'discarded']);
const VALID_EDGE_KINDS = new Set<string>(['proven', 'hypothesized', 'discarded']);

/** Defensive validation + normalization of an agent- or client-supplied graph. */
export function validateAttackGraph(g: any): AttackGraph {
  if (!g || typeof g !== 'object') throw new Error('attack graph must be an object');

  let phases: string[];
  if (Array.isArray(g.phases) && g.phases.length > 0) {
    const rawPhases = g.phases;
    phases = new Array(rawPhases.length);
    for (let i = 0; i < rawPhases.length; i++) {
      phases[i] = String(rawPhases[i]);
    }
  } else {
    phases = PHASES.default;
  }
  const phaseSet = new Set(phases);

  // Single-pass node validation and deduplication in indexed loop
  const rawNodes: any[] = Array.isArray(g.nodes) ? g.nodes : [];
  const ids = new Set<string>();
  const nodes: AttackGraphNode[] = [];
  const defaultPhase = phases[0];

  for (let i = 0; i < rawNodes.length; i++) {
    const n = rawNodes[i];
    if (!n || n.id === undefined || n.id === null) continue;
    const idStr = String(n.id);
    if (ids.has(idStr)) continue;
    ids.add(idStr);

    nodes.push({
      id: idStr,
      label: String(n.label || n.id).slice(0, 18),
      phase: phaseSet.has(n.phase) ? n.phase : defaultPhase,
      kind: VALID_KINDS.has(n.kind) ? n.kind : 'service',
      status: VALID_STATUSES.has(n.status) ? n.status : 'probing',
      operator: n.operator ? String(n.operator) : undefined,
      evidence: n.evidence ? String(n.evidence) : undefined,
      note: n.note ? String(n.note) : undefined,
    });
  }

  // Reuse `ids` Set directly (containing all valid node IDs) for O(1) edge validation in single pass
  const rawEdges: any[] = Array.isArray(g.edges) ? g.edges : [];
  const edges: AttackGraphEdge[] = [];
  for (let i = 0; i < rawEdges.length; i++) {
    const e = rawEdges[i];
    if (!e || e.from === undefined || e.to === undefined) continue;
    const fromStr = String(e.from);
    const toStr = String(e.to);
    if (!ids.has(fromStr) || !ids.has(toStr)) continue;

    edges.push({
      from: fromStr,
      to: toStr,
      kind: VALID_EDGE_KINDS.has(e.kind) ? e.kind : 'hypothesized',
    });
  }

  return {
    target: String(g.target || 'unknown'),
    family: String(g.family || 'default'),
    phases,
    nodes,
    edges,
    killcam: g.killcam && ids.has(String(g.killcam.nodeId)) ? g.killcam : undefined,
    source: g.source === 'recon' ? 'recon' : 'scaffold',
  };
}
