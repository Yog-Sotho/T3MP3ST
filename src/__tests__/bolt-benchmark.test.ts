import { describe, it, expect } from 'vitest';
import { buildCallGraph, reachability, type CodeBlock, type CallGraphEntry } from '../recon/code-ingest.js';

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
    expect(duration).toBeLessThan(50);
  });
});
