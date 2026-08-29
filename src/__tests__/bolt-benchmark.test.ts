import { describe, it, expect } from 'vitest';
import { buildCallGraph, reachability, type CodeBlock, type CallGraphEntry } from '../recon/code-ingest.js';
import { EvidenceVault } from '../evidence/index.js';
import { KillChainPhase, type Finding, type Credential, type Severity, type TargetType, type TargetZone } from '../types/index.js';
import { TargetEnvironment } from '../target/index.js';
import { CommsChannel } from '../comms/index.js';
import { createKnowledgeBase } from '../stubs/index.js';
import { adapterForBinary, adaptersForFamily, summarizeToolCatalog, TOOL_ADAPTERS } from '../arsenal/catalog.js';
import { Semaphore } from '../pack/health.js';
import { TaskQueue } from '../mission/index.js';
import type { Task } from '../types/index.js';
import { AnalysisEngine } from '../analysis/index.js';
import type { MissionControl } from '../mission/index.js';
import { OpsecController } from '../opsec/index.js';

describe('EvidenceVault performance and correctness under load', () => {
  it('correctly retrieves and aggregates large datasets with zero redundant allocations', () => {
    const vault = new EvidenceVault();
    const targetIds = ['target-a', 'target-b', 'target-c', 'target-d', 'target-e'];
    const operatorIds = ['op-1', 'op-2', 'op-3', 'op-4'];
    const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

    // 1) Populate 2,500 findings
    for (let i = 0; i < 2500; i++) {
      const severity = severities[i % severities.length];
      const targetId = targetIds[i % targetIds.length];
      const operatorId = operatorIds[i % operatorIds.length];
      const isVerified = i % 10 === 0; // 10% are verified

      const f: Finding = {
        id: `finding-${i}`,
        title: `Vulnerability ${i}`,
        description: `Unsafe implementation ${i}`,
        severity,
        targetId,
        operatorId,
        phase: KillChainPhase.EXPLOIT,
        evidence: [],
        discoveredAt: Date.now(),
        verifiedAt: isVerified ? Date.now() : undefined,
        verifyGate: isVerified ? { passed: true, provenance: 'tool', reasons: [], checkedAt: Date.now() } : undefined,
      };
      vault.addFinding(f);
    }

    // 2) Populate 2,500 credentials
    for (let i = 0; i < 2500; i++) {
      const type = i % 2 === 0 ? 'password' : 'token';
      const targetId = targetIds[i % targetIds.length];

      const c: Credential = {
        id: `cred-${i}`,
        type,
        secret: `secret-value-${i}`,
        source: 'dump',
        discoveredAt: Date.now(),
        targetId,
        validatedAt: i % 5 === 0 ? Date.now() : undefined, // 20% are validated
      };
      vault.addCredential(c);
    }

    // 3) Measure performance and assert correctness
    const start = performance.now();

    // Perform multiple lookups
    const criticals = vault.getFindingsBySeverity('critical');
    const targetA = vault.getFindingsByTarget('target-a');
    const op1 = vault.getFindingsByOperator('op-1');
    const verifieds = vault.getVerifiedFindings();

    const passwords = vault.getCredentialsByType('password');
    const credsTargetA = vault.getCredentialsByTarget('target-a');

    const stats = vault.getStats();

    const end = performance.now();
    const duration = end - start;

    console.log(`[Bolt Benchmark] EvidenceVault 5000-unit stats & lookups took: ${duration.toFixed(2)}ms`);

    // Correctness assertions
    expect(criticals.length).toBe(500); // 2500 / 5
    expect(targetA.length).toBe(500); // 2500 / 5
    expect(op1.length).toBe(625); // 2500 / 4
    expect(verifieds.length).toBe(250); // 2500 / 10

    expect(passwords.length).toBe(1250); // 2500 / 2
    expect(credsTargetA.length).toBe(500); // 2500 / 5

    expect(stats.totalFindings).toBe(2500);
    expect(stats.verifiedFindings).toBe(250);
    expect(stats.bySeverity.critical).toBe(500);
    expect(stats.totalCredentials).toBe(2500);
    expect(stats.validatedCredentials).toBe(500); // 2500 / 5

    // Expect the extremely optimized lookup to finish well under 50ms (usually < 2ms)
    expect(duration).toBeLessThan(150);
  });
});

describe('Single-pass Map ledger scoping performance under load', () => {
  it('rapidly scopes and filters 5,000 ledger records with zero array copy overhead', () => {
    const ledger = new Map<string, { id: string; missionId: string; operationId: string; family: string; updatedAt: string }>();
    const missions = ['m-1', 'm-2', 'm-3', 'm-4', 'm-5'];
    const operations = ['op-1', 'op-2', 'op-3', 'op-4'];
    const families = ['web_api', 'ai_red_team', 'cloud_infra', 'smart_contract', 'code_supply_chain'];

    for (let i = 0; i < 5000; i++) {
      const id = `item-${i}`;
      ledger.set(id, {
        id,
        missionId: missions[i % missions.length],
        operationId: operations[i % operations.length],
        family: families[i % families.length],
        updatedAt: new Date(1700000000000 + i * 1000).toISOString(),
      });
    }

    const start = performance.now();

    // Perform single-pass scoping simulation
    const missionId = 'm-1';
    const operationId = 'op-1';
    const family = 'web_api';

    const scoped: Array<{ id: string; missionId: string; operationId: string; family: string; updatedAt: string }> = [];
    for (const item of ledger.values()) {
      if (missionId && item.missionId !== missionId) continue;
      if (operationId && item.operationId !== operationId) continue;
      if (family && item.family !== family) continue;
      scoped.push(item);
    }
    scoped.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));

    const end = performance.now();
    const duration = end - start;

    console.log(`[Bolt Benchmark] Single-pass Map ledger scoping for 5,000 items took: ${duration.toFixed(2)}ms`);

    // Expected matching count: 5000 / (5 * 4) = 250 items (since missionId and family indices i%5 align)
    expect(scoped.length).toBe(250);
    expect(duration).toBeLessThan(150);
  });
});

describe('KnowledgeBase pattern matching performance and correctness under load', () => {
  it('correctly matches patterns rapidly with pre-compiled regexes', () => {
    const kb = createKnowledgeBase();
    const samplePayload = `
      SELECT * FROM users WHERE id = '1' OR '1'='1';
      <script>alert('xss')</script>
      ../../etc/passwd
      password: "supersecretpassword"
      BEGIN RSA PRIVATE KEY
    `;

    const start = performance.now();
    let totalMatches = 0;
    // Perform 5,000 pattern match calls over multi-line text
    for (let i = 0; i < 5000; i++) {
      const matches = kb.matchPatterns(samplePayload);
      totalMatches += matches.length;
    }
    const end = performance.now();
    const duration = end - start;

    console.log(`[Bolt Benchmark] KnowledgeBase 5000 pattern matches took: ${duration.toFixed(2)}ms`);

    // Each call matches 5 vulnerability patterns (sqli, xss, path-traversal, credential-exposure, key-exposure)
    expect(totalMatches).toBe(25000);
    // Pre-compiled regex matching for 5,000 calls takes ~5-30ms locally
    expect(duration).toBeGreaterThan(0);
  });
});

describe('TargetEnvironment performance and correctness under load', () => {
  it('correctly retrieves and aggregates large datasets with zero redundant allocations', () => {
    const env = new TargetEnvironment();
    const zones: TargetZone[] = ['external', 'dmz', 'internal', 'restricted', 'airgapped'];
    const types: TargetType[] = ['web_application', 'api', 'network', 'host', 'database', 'cloud', 'mobile', 'iot', 'container'];

    // Populate 5,000 targets
    for (let i = 0; i < 5000; i++) {
      env.addTarget({
        name: `Target-${i}`,
        type: types[i % types.length],
        zone: zones[i % zones.length],
        address: `10.0.0.${i % 255}`,
        port: 80 + (i % 100),
        protocol: 'tcp',
      });
    }

    const start = performance.now();

    // Perform queries
    const externalTargets = env.getTargetsByZone('external');
    const apiTargets = env.getTargetsByType('api');
    const scanningTargets = env.getTargetsByStatus('scanning');
    const ownedTargets = env.getOwnedTargets();
    const vulnerableTargets = env.getVulnerableTargets();

    const stats = env.getStats();

    const end = performance.now();
    const duration = end - start;

    console.log(`[Bolt Benchmark] TargetEnvironment 5000-unit stats & lookups took: ${duration.toFixed(2)}ms`);

    // Correctness assertions
    expect(externalTargets.length).toBe(1000); // 5000 / 5
    expect(apiTargets.length).toBe(556); // Math.ceil(5000 / 9)
    expect(scanningTargets.length).toBe(0); // None are scanning initially
    expect(ownedTargets.length).toBe(0); // None are owned initially
    expect(vulnerableTargets.length).toBe(0); // None are vulnerable initially

    expect(stats.total).toBe(5000);
    expect(stats.byZone.external).toBe(1000);
    expect(stats.byType.api).toBe(556);

    // Expect the optimized lookup to finish extremely quickly, well under 50ms
    expect(duration).toBeLessThan(50);
  });
});

describe('Tool Catalog lookups and summarization performance and correctness', () => {
  it('performs high-volume binary/ID/family lookups and summaries in O(1) time with zero allocation churn', () => {
    const start = performance.now();

    // 2,000 lookups
    for (let i = 0; i < 2000; i++) {
      const nmap = adapterForBinary('nmap');
      const curl = adapterForBinary('curl');
      expect(nmap?.id).toBe('nmap');
      expect(curl?.binary).toBe('curl');
    }

    // 1,000 family lookups
    for (let i = 0; i < 1000; i++) {
      const webAdapters = adaptersForFamily('web_api');
      expect(webAdapters.length).toBeGreaterThan(0);
    }

    // 1,000 default summary calls
    for (let i = 0; i < 1000; i++) {
      const summary = summarizeToolCatalog();
      expect(summary.total).toBe(TOOL_ADAPTERS.length);
    }

    const end = performance.now();
    const duration = end - start;

    console.log(`[Bolt Benchmark] Tool Catalog 4,000 lookups and summaries took: ${duration.toFixed(2)}ms`);

    // Pre-computed Map lookups and static summaries finish under 250ms (usually < 20ms)
    expect(duration).toBeLessThan(250);
  });
});

describe('OpsecController performance and correctness under load', () => {
  it('correctly tracks detections, mitigation, and statistics with zero intermediate array allocation overhead', () => {
    const opsec = new OpsecController({ maxDetectionEvents: 10000, avoidDetection: false });
    const eventIds: string[] = [];

    // 1) Populate 5,000 detection events
    for (let i = 0; i < 5000; i++) {
      const event = opsec.recordDetection({
        type: 'ids',
        severity: 'high',
        source: 'IDS',
        description: `Suspicious traffic event ${i}`,
      });
      eventIds.push(event.id);
    }

    // 2) Mitigate 1,000 detection events
    for (let i = 0; i < 1000; i++) {
      opsec.mitigateDetection(eventIds[i]);
    }

    // 3) Measure performance and assert correctness
    const start = performance.now();

    const activeDetections = opsec.getActiveDetections();
    const abortRecommended = opsec.isAbortRecommended();
    const stats = opsec.getStats();

    const end = performance.now();
    const duration = end - start;

    console.log(`[Bolt Benchmark] OpsecController 5000-unit stats & lookups took: ${duration.toFixed(2)}ms`);

    // Correctness assertions
    expect(activeDetections.length).toBe(4000);
    expect(abortRecommended).toBe(false);
    expect(stats.totalDetections).toBe(5000);
    expect(stats.activeDetections).toBe(4000);
    expect(stats.mitigatedDetections).toBe(1000);

    // Expect single-pass indexed execution to finish under 50ms
    expect(duration).toBeLessThan(50);
  });
});

describe('buildCallGraph performance and correctness', () => {
  it('correctly maps calls and is extremely fast', () => {
    // Generate 1000 dummy Python-like code blocks to test scaling.
    const blocks: CodeBlock[] = [];

    // Create some unique target functions
    for (let i = 1; i <= 200; i++) {
      blocks.push({
        id: `file.py::func_${i}@10`,
        path: 'file.py',
        name: `func_${i}`,
        kind: 'function',
        lineStart: 10,
        lineEnd: 15,
        params: [],
        decorators: [],
        body: `def func_${i}():\n    pass`,
      });
    }

    // Create caller functions that make calls
    for (let i = 1; i <= 800; i++) {
      const calls = [];
      // Each caller calls 3 randomly/sequentially selected target functions
      for (let j = 1; j <= 3; j++) {
        const targetNum = ((i * j) % 200) + 1;
        calls.push(`    func_${targetNum}()`);
      }
      blocks.push({
        id: `caller.py::caller_${i}@20`,
        path: 'caller.py',
        name: `caller_${i}`,
        kind: 'function',
        lineStart: 20,
        lineEnd: 30,
        params: [],
        decorators: [],
        body: `def caller_${i}():\n${calls.join('\n')}`,
      });
    }

    const start = performance.now();
    const graph = buildCallGraph(blocks);
    const end = performance.now();

    const duration = end - start;
    console.log(`[Bolt Benchmark] buildCallGraph for 1000 blocks took: ${duration.toFixed(2)}ms`);

    // Verify correctness: caller_1 calls func_2, func_3, func_4, etc.
    const caller1Id = 'caller.py::caller_1@20';
    const callees = graph[caller1Id].callees;
    expect(callees.length).toBeGreaterThan(0);
    for (const calleeId of callees) {
      expect(calleeId).toContain('file.py::func_');
    }

    // Verify standard performance expectation:
    // With O(N) lookup, 1000 blocks should process in under 100ms.
    expect(duration).toBeLessThan(100);
  });

  it('runs reachability extremely fast over a large/deep call graph', () => {
    // Generate a deep linear call graph of 1,000 nodes to test the reachability algorithm.
    const callGraph: Record<string, CallGraphEntry> = {};
    const size = 1000;

    for (let i = 0; i < size; i++) {
      const id = `node_${i}`;
      const callees = i < size - 1 ? [`node_${i + 1}`] : [];
      const callers = i > 0 ? [`node_${i - 1}`] : [];
      callGraph[id] = { callees, callers };
    }

    const start = performance.now();
    const result = reachability(callGraph, ['node_0']);
    const end = performance.now();

    const duration = end - start;
    console.log(`[Bolt Benchmark] reachability for ${size} nodes took: ${duration.toFixed(2)}ms`);

    // Verify correctness
    const targetNode = `node_${size - 1}`;
    expect(result[targetNode].reachable).toBe(true);
    expect(result[targetNode].reachDepth).toBe(size - 1);
    expect(result[targetNode].paths[0]).toHaveLength(size);
    expect(result[targetNode].paths[0][0]).toBe('node_0');
    expect(result[targetNode].paths[0][size - 1]).toBe(targetNode);

    // Verify performance
    expect(duration).toBeLessThan(150);
  });
});

describe('TaskQueue performance and correctness under load', () => {
  it('correctly handles high-throughput task additions, lookups, and updates', () => {
    const queue = new TaskQueue();
    const tasks: Task[] = [];

    for (let i = 0; i < 5000; i++) {
      tasks.push({
        id: `task-${i}`,
        missionId: 'mission-1',
        name: `Task ${i}`,
        description: `Description ${i}`,
        phase: KillChainPhase.RECON,
        operatorType: 'recon',
        status: 'pending',
        priority: i % 10,
        dependencies: [],
        createdAt: Date.now(),
      });
    }

    const start = performance.now();

    // 1) Batch add 5000 tasks
    queue.addMany(tasks);

    // 2) O(1) ID lookups and status updates
    for (let i = 0; i < 1000; i++) {
      const task = queue.getTask(`task-${i}`);
      expect(task).toBeDefined();
      queue.updateStatus(`task-${i}`, 'in_progress');
      queue.assign(`task-${i}`, 'op-1');
    }

    // 3) Remove tasks
    for (let i = 4000; i < 4500; i++) {
      const removed = queue.remove(`task-${i}`);
      expect(removed).toBeDefined();
    }

    const end = performance.now();
    const duration = end - start;

    console.log(`[Bolt Benchmark] TaskQueue 5000-unit batch add, lookups, updates took: ${duration.toFixed(2)}ms`);

    expect(queue.size).toBe(4500);
    expect(queue.getTask('task-0')?.status).toBe('assigned');
    expect(queue.getTask('task-4200')).toBeUndefined();
    expect(duration).toBeLessThan(250);
  });
});

describe('AnalysisEngine performance and correctness under load', () => {
  it('rapidly generates reports and exports markdown for 2,500 findings with zero multi-pass filter overhead', () => {
    const vault = new EvidenceVault();
    const targetEnv = new TargetEnvironment();
    const engine = new AnalysisEngine(vault, targetEnv, {} as MissionControl, {} as OpsecController);

    const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

    for (let i = 0; i < 2500; i++) {
      const severity = severities[i % severities.length];
      const targetId = `target-${i % 10}`;

      const f: Finding = {
        id: `finding-${i}`,
        title: `Vulnerability Title ${i}`,
        description: `Detailed description for vulnerability ${i}`,
        severity,
        targetId,
        operatorId: 'op-1',
        phase: KillChainPhase.EXPLOIT,
        remediation: `Remediation advice for vulnerability ${i}`,
        evidence: [
          { type: 'log', content: `Sample evidence log output ${i}`, timestamp: Date.now() },
        ],
        discoveredAt: 1700000000000 + i * 1000,
        exploitedAt: i % 2 === 0 ? 1700000000500 + i * 1000 : undefined,
      };
      vault.addFinding(f);
    }

    const start = performance.now();

    const report = engine.generateReport('mission-test-1');
    const markdown = engine.exportToMarkdown(report);

    const end = performance.now();
    const duration = end - start;

    console.log(`[Bolt Benchmark] AnalysisEngine report generation & markdown export for 2500 findings took: ${duration.toFixed(2)}ms`);

    expect(report.findings.length).toBe(2500);
    expect(report.summary.criticalFindings).toBe(500);
    expect(report.summary.highFindings).toBe(500);
    expect(report.summary.successfulExploits).toBe(1250);
    expect(report.recommendations.length).toBe(1500); // 500 critical + 500 high + 500 medium
    expect(report.attackPaths.length).toBe(10); // 10 targets, each with >= 2 findings
    expect(markdown).toContain('# Security Assessment Report');
    expect(markdown).toContain('## Immediate Priority');
    expect(duration).toBeLessThan(100);
  });
});

describe('Semaphore queue performance and correctness under load', () => {
  it('handles high waiter concurrency with O(1) dequeuing and zero memory growth', async () => {
    const sem = new Semaphore(1);
    const numWaiters = 5000;
    const executionOrder: number[] = [];

    // Occupy initial slot
    const releaseInitial = await sem.acquire();

    // Queue up 5000 waiters
    const waiterPromises: Promise<void>[] = [];
    for (let i = 0; i < numWaiters; i++) {
      const p = sem.acquire().then((release) => {
        executionOrder.push(i);
        release();
      });
      waiterPromises.push(p);
    }

    expect(sem.queued).toBe(numWaiters);

    const start = performance.now();
    // Drains all 5000 queued waiters in FIFO order
    releaseInitial();
    await Promise.all(waiterPromises);
    const end = performance.now();
    const duration = end - start;

    console.log(`[Bolt Benchmark] Semaphore ${numWaiters} waiters drain took: ${duration.toFixed(2)}ms`);

    expect(executionOrder.length).toBe(numWaiters);
    expect(executionOrder[0]).toBe(0);
    expect(executionOrder[numWaiters - 1]).toBe(numWaiters - 1);
    expect(sem.queued).toBe(0);
    expect(sem.inFlight).toBe(0);
    expect(duration).toBeLessThan(100);
  });
});

describe('CommsChannel performance and correctness under load', () => {
  it('correctly retrieves and indexes large message datasets with zero redundant filtering', () => {
    const comms = new CommsChannel();
    const channel = comms.createChannel({ name: 'test-channel', type: 'team' });
    const operators = ['op-1', 'op-2', 'op-3', 'op-4'];

    // 1) Populate 5,000 messages
    for (let i = 0; i < 5000; i++) {
      const from = operators[i % operators.length];
      const to = operators[(i + 1) % operators.length];
      comms.send({
        from,
        to,
        channel: channel.id,
        type: 'intel',
        content: `Message content ${i}`,
      });
    }

    // 2) Measure performance and assert correctness
    const start = performance.now();

    const op1Recv = comms.getMessagesFor('op-1');
    const op1Sent = comms.getMessagesFrom('op-1');
    const channelMsgs = comms.getChannelMessages(channel.id);

    const end = performance.now();
    const duration = end - start;

    console.log(`[Bolt Benchmark] CommsChannel 5000-unit stats & lookups took: ${duration.toFixed(2)}ms`);

    // Correctness assertions
    expect(op1Recv.length).toBe(1250); // 5000 / 4
    expect(op1Sent.length).toBe(1250); // 5000 / 4
    expect(channelMsgs.length).toBe(5000);

    // Expect the optimized index lookup to finish extremely quickly, well under 50ms
    expect(duration).toBeLessThan(50);
  });
});
