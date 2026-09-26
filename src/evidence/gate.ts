/**
 * The live verification gate — the honesty spine, IN the engine path.
 *
 * The disclosure-grade gates (scripts/verify-finding.mjs: anchors, poc ladder,
 * refuter panel, novelty) run on hand-authored finding JSON at the CLI. This is
 * their in-process counterpart for live, operator-produced findings: it refuses
 * to let a Finding be marked `verified` unless it is actually backed by real tool
 * output — provenance-strict, applied to the autonomous swarm, not beside it.
 *
 * The principle is the same one disclosure-gen enforces: a claim is only as strong
 * as its provenance. Prose is not evidence. A severity assertion with no evidence
 * is an overclaim. This is the door — not a decoration next to it.
 */

import type { Finding } from '../types/index.js';

/** Evidence types that represent real machine/tool output (vs a human note). */
const TOOL_EVIDENCE = new Set(['output', 'command', 'response', 'request', 'log', 'file']);

export type LiveProvenance = 'none' | 'context' | 'tool';

export interface LiveGateResult {
  passed: boolean;
  provenance: LiveProvenance;
  reasons: string[];
  checkedAt: number;
}

/**
 * Gate a live finding. PASS only when the claim is backed by real tool output.
 * Honest by construction: it never invents provenance, and it states WHY it blocked.
 * ⚡ BOLT OPTIMIZATION: Single-pass direct loop iteration without intermediate array allocations from `.filter()`.
 */
export function gateLiveFinding(f: Finding): LiveGateResult {
  const reasons: string[] = [];
  const evidence = Array.isArray(f.evidence) ? f.evidence : [];

  let toolEvCount = 0;
  for (let i = 0; i < evidence.length; i++) {
    const e = evidence[i];
    if (e && TOOL_EVIDENCE.has(e.type) && String(e.content || '').trim().length > 0) {
      toolEvCount++;
    }
  }

  if (toolEvCount === 0) {
    reasons.push('no tool-output evidence (output/command/response/log/file) — provenance-strict requires a finding be backed by real tool output, not prose');
  }
  if ((f.severity === 'critical' || f.severity === 'high') && evidence.length === 0) {
    reasons.push(`${f.severity} severity asserted with zero evidence — severity must be backed by evidence`);
  }

  const provenance: LiveProvenance = toolEvCount > 0 ? 'tool' : (evidence.length > 0 ? 'context' : 'none');
  return { passed: reasons.length === 0, provenance, reasons, checkedAt: Date.now() };
}
