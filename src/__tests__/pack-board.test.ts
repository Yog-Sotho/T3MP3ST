/**
 * PackBoard — pins the load-bearing invariants of the Phase-2 shared workspace
 * (the pack-hunt design + the red-team §2):
 *  - de-dup collapses a duplicate post into an ENDORSEMENT that raises smoke (HT-1)
 *  - claim() is an ATOMIC compare-and-set: two calls, same expectedVersion → exactly one grant (HT-1)
 *  - an expired lease is reclaimable (the reaper backstop)
 *  - refute() does NOT flip status by itself (HT-2)
 *  - situationReport() is BOUNDED — never dumps the raw board, even with many leads
 */

import { describe, it, expect } from 'vitest';
import { PackBoard, dedupKey } from '../pack/board.js';
import type { LeadInput } from '../pack/board.js';

// A deterministic, hand-cranked clock so lease/liveness math is exact in tests.
function fakeClock(start = 1_000_000) {
  let t = start;
  const now = () => t;
  return { now, set: (v: number) => { t = v; }, advance: (dt: number) => { t += dt; } };
}

const leadInput = (over: Partial<LeadInput> = {}): LeadInput => ({
  kind: 'lead',
  title: 'command injection in exec sink',
  where: { file: 'src/router.js', line: 42 },
  vulnClass: 'injection',
  confidence: 'high',
  provenance: 'tool',
  cwe: 'CWE-77',
  ...over,
});

describe('dedupKey — reuses cli-swarm formula', () => {
  it('near lines collapse, far lines are distinct (line bucket of 15)', () => {
    expect(dedupKey({ file: 'lib/x.js', cwe: 'CWE-22', line: 100 }))
      .toBe(dedupKey({ file: 'lib/x.js', cwe: 'CWE-22', line: 103 }));
    expect(dedupKey({ file: 'lib/x.js', cwe: 'CWE-22', line: 100 }))
      .not.toBe(dedupKey({ file: 'lib/x.js', cwe: 'CWE-22', line: 580 }));
  });

  it('distinct vuln classes at the same file:line-bucket do NOT collide (H11)', () => {
    // no CWE to disambiguate — vulnClass must keep an XSS and an SQLi a line apart distinct
    expect(dedupKey({ file: 'app.js', line: 10, vulnClass: 'xss' }))
      .not.toBe(dedupKey({ file: 'app.js', line: 12, vulnClass: 'sqli' }));
  });

  it('coordinate-less url leads key on the surface, not one shared empty bucket (H13)', () => {
    expect(dedupKey({ url: 'https://x/a', vulnClass: 'ssrf' }))
      .not.toBe(dedupKey({ url: 'https://x/b', vulnClass: 'ssrf' }));
  });
});

describe('PackBoard — reference/evidence hardening (H12/H15/M5)', () => {
  it('getLead returns a SNAPSHOT — mutating it cannot corrupt the CAS version/status/claim', () => {
    const board = new PackBoard({}, fakeClock().now);
    const lead = board.postLead('a', leadInput());
    const snap = board.getLead(lead.id)!;
    snap.version = 9999; // caller pokes the returned object
    snap.status = 'confirmed';
    snap.claim = { by: 'x', leaseUntil: 9e15, version: 9999 };
    const fresh = board.getLead(lead.id)!;
    expect(fresh.version).toBe(lead.version); // internal state untouched
    expect(fresh.status).toBe('open');
    expect(fresh.claim).toBeUndefined();
  });

  it('a duplicate with STRONGER provenance/severity monotonically upgrades the card (never downgrades)', () => {
    const board = new PackBoard({}, fakeClock().now);
    const weak = board.postLead('a', leadInput({ provenance: 'context', severity: 'low' }));
    board.postLead('b', leadInput({ provenance: 'tool', severity: 'high' })); // same dedupKey, stronger
    const up = board.getLead(weak.id)!;
    expect(up.provenance).toBe('tool');
    expect(up.severity).toBe('high');
    board.postLead('c', leadInput({ provenance: 'none', severity: 'info' })); // weaker dup
    const still = board.getLead(weak.id)!;
    expect(still.provenance).toBe('tool'); // not downgraded
    expect(still.severity).toBe('high');
  });

  it('EVENT payloads are snapshots too — a subscriber mutating a lead:claimed payload cannot corrupt the CAS', () => {
    // the outbound accessors were hardened; the emit paths must match (7th-pass finding) or a
    // synchronous SSE/controller subscriber could flip status / reset the version / forge a lease.
    const board = new PackBoard({}, fakeClock().now);
    const posted = board.postLead('a', leadInput());
    board.on('lead:claimed', ({ lead }: { lead: any }) => { lead.status = 'open'; lead.version = 0; delete lead.claim; });
    board.claim(posted.id, 'agentA', posted.version);
    const after = board.getLead(posted.id)!;
    expect(after.status).toBe('claimed'); // not reverted to open by the subscriber
    expect(after.version).toBe(1); // CAS token intact
    expect(after.claim?.by).toBe('agentA'); // lease intact
  });

  it('INGEST clones `where` — mutating the caller-retained object after postLead cannot re-point the card', () => {
    const board = new PackBoard({}, fakeClock().now);
    const w = { file: 'safe.js', line: 10 };
    const snap = board.postLead('a', leadInput({ where: w }));
    w.file = 'attacker.js';
    (w as unknown as { url: string }).url = 'http://evil';
    const after = board.getLead(snap.id)!;
    expect(after.where.file).toBe('safe.js'); // internal projection immune to post-hoc mutation
    expect((after.where as { url?: string }).url).toBeUndefined();
  });
});

describe('postLead — de-dup collapses a duplicate into an endorsement (raises smoke)', () => {
  it('a second post with the same dedupKey does NOT create a new lead; it endorses and raises smoke', () => {
    const board = new PackBoard({}, fakeClock().now);
    const a = board.postLead('agent-a', leadInput());
    expect(a.smoke).toBe(1);
    expect(a.endorsements).toHaveLength(0);

    // same file, a nearby line (same bucket), same CWE → same dedupKey → duplicate
    const b = board.postLead('agent-b', leadInput({ title: 'dup from B', where: { file: 'src/router.js', line: 45 } }));

    expect(board.getAllLeads()).toHaveLength(1);       // no second card
    expect(b.id).toBe(a.id);                           // returned the SAME lead
    expect(b.smoke).toBe(2);                           // smoke rose
    expect(b.endorsements).toHaveLength(1);
    expect(b.endorsements[0].by).toBe('agent-b');
  });

  it('a genuinely different lead (different dedupKey) is a new card', () => {
    const board = new PackBoard({}, fakeClock().now);
    board.postLead('agent-a', leadInput());
    board.postLead('agent-a', leadInput({ where: { file: 'src/other.js', line: 9 }, cwe: 'CWE-22' }));
    expect(board.getAllLeads()).toHaveLength(2);
  });
});

describe('claim — a real synchronous compare-and-set (atomic)', () => {
  it('two claims with the SAME expectedVersion → exactly one granted', () => {
    const board = new PackBoard({}, fakeClock().now);
    const lead = board.postLead('poster', leadInput());
    const v = lead.version; // both racers see the same version

    const first = board.claim(lead.id, 'agent-1', v);
    const second = board.claim(lead.id, 'agent-2', v);

    const grants = [first.granted, second.granted].filter(Boolean);
    expect(grants).toHaveLength(1);           // exactly one winner
    expect(first.granted).toBe(true);         // FIFO on the single-threaded loop: first wins
    expect(second.granted).toBe(false);       // stale expectedVersion (and lease held) → denied

    const held = board.getLead(lead.id);
    expect(held?.claim?.by).toBe('agent-1');
    expect(held?.status).toBe('claimed');
  });

  it('a stale expectedVersion is rejected and returns the current version', () => {
    const board = new PackBoard({}, fakeClock().now);
    const lead = board.postLead('poster', leadInput());
    board.endorse('x', lead.id);              // bumps version
    const res = board.claim(lead.id, 'agent-1', 0); // expected the pre-endorse version
    expect(res.granted).toBe(false);
    expect(res.version).toBe(board.getLead(lead.id)?.version);
  });

  it('a quorum-terminal lead (refuted/confirmed/dead) is NOT claimable — sticky refutation (HT-2)', () => {
    const board = new PackBoard({}, fakeClock().now);
    const lead = board.postLead('poster', leadInput());
    board.setLeadStatus('quorum', lead.id, 'refuted'); // the quorum killed it
    const res = board.claim(lead.id, 'agent-1', board.getLead(lead.id)!.version);
    expect(res.granted).toBe(false); // cannot be re-claimed back into active work
    expect(board.getLead(lead.id)?.status).toBe('refuted'); // not resurrected to 'claimed'
  });
});

describe('releaseExpiredClaims — an expired lease is reclaimable', () => {
  it('reaps a lease past its leaseUntil and returns the lead to open, then another agent can claim it', () => {
    const clock = fakeClock();
    const board = new PackBoard({}, clock.now);
    const lead = board.postLead('poster', leadInput());

    const c = board.claim(lead.id, 'agent-1', lead.version, 1000);
    expect(c.granted).toBe(true);

    // before expiry: agent-2 cannot claim (live lease held)
    expect(board.claim(lead.id, 'agent-2', c.version).granted).toBe(false);

    clock.advance(1001); // lease window elapses
    const released = board.releaseExpiredClaims();
    expect(released).toContain(lead.id);

    const reopened = board.getLead(lead.id);
    expect(reopened?.claim).toBeUndefined();
    expect(reopened?.status).toBe('open');

    // now agent-2 CAN claim it with the current version
    const retry = board.claim(lead.id, 'agent-2', reopened?.version ?? -1);
    expect(retry.granted).toBe(true);
    expect(board.getLead(lead.id)?.claim?.by).toBe('agent-2');
  });
});

describe('refute — does NOT flip status by itself (HT-2)', () => {
  it('appends a refutation vote but leaves status unchanged; only the quorum flips it', () => {
    const board = new PackBoard({}, fakeClock().now);
    const lead = board.postLead('poster', leadInput());
    expect(lead.status).toBe('open');

    const r = board.refute('auditor', lead.id, 'claims a startsWith guard', 'src/router.js:12');
    expect(r?.refutations).toHaveLength(1);
    expect(r?.refutations[0].guard).toBe('src/router.js:12');
    expect(r?.status).toBe('open'); // STILL open — refute() is a signal, not a verdict

    // even many refutations don't flip it
    board.refute('auditor-2', lead.id, 'agrees');
    board.refute('auditor-3', lead.id, 'agrees');
    expect(board.getLead(lead.id)?.status).toBe('open');

    // only the explicit quorum path changes status
    board.setLeadStatus('quorum', lead.id, 'refuted');
    expect(board.getLead(lead.id)?.status).toBe('refuted');
  });
});

describe('situationReport — bounded, never dumps the raw board', () => {
  it('stays under the char cap even with far more leads than the cap could hold verbatim', () => {
    const cap = 1200;
    const board = new PackBoard({ reportCharCap: cap, defaultMaxLeads: 8 }, fakeClock().now);

    // flood the board with 500 distinct leads (distinct files → distinct dedupKeys)
    for (let i = 0; i < 500; i++) {
      board.postLead(`agent-${i % 7}`, leadInput({
        title: `finding number ${i} with a deliberately long descriptive title `.repeat(3),
        where: { file: `src/module_${i}.js`, line: (i * 31) % 400 },
        cwe: `CWE-${i % 90}`,
      }));
    }
    for (let i = 0; i < 20; i++) board.heartbeat(`agent-${i}`, 'hunting', 'x'.repeat(50));

    const report = board.situationReport('agent-0', { maxLeads: 8 });
    expect(report.length).toBeLessThanOrEqual(cap);
    expect(report).toContain('PACK BOARD');
  });

  it('ranks unclaimed leads by smoke and excludes leads claimed by others / includes your own', () => {
    const clock = fakeClock();
    const board = new PackBoard({ reportCharCap: 4000 }, clock.now);

    const hot = board.postLead('a', leadInput({ title: 'HOT lead', where: { file: 'src/hot.js', line: 1 }, cwe: 'CWE-1' }));
    board.endorse('b', hot.id);
    board.endorse('c', hot.id); // smoke = 3

    const cold = board.postLead('a', leadInput({ title: 'cold lead', where: { file: 'src/cold.js', line: 1 }, cwe: 'CWE-2' }));

    // a lead claimed by SOMEONE ELSE should not appear in the open-leads section
    const other = board.postLead('a', leadInput({ title: 'owned by z', where: { file: 'src/z.js', line: 1 }, cwe: 'CWE-3' }));
    board.claim(other.id, 'agent-z', other.version);

    // a lead the reader claims → should show under YOUR CLAIMS
    const own = board.postLead('a', leadInput({ title: 'my own work', where: { file: 'src/mine.js', line: 1 }, cwe: 'CWE-4' }));
    board.claim(own.id, 'reader', own.version);

    board.heartbeat('reader', 'hunting');
    const report = board.situationReport('reader', { maxLeads: 8 });

    expect(report).toContain('HOT lead');
    expect(report).toContain('cold lead');
    expect(report.indexOf('HOT lead')).toBeLessThan(report.indexOf('cold lead')); // smoke ranking
    expect(report).not.toContain('owned by z'); // claimed by another agent → hidden from open leads
    expect(report).toContain('YOUR CLAIMS');
    expect(report).toContain('my own work');
    expect(cold.smoke).toBe(1);
  });
});
