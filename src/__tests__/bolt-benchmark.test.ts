import { describe, it, expect } from 'vitest';
import { buildCallGraph, reachability, type CodeBlock } from '../recon/code-ingest.js';

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

  it('benchmark: reachability handles a large call graph of 5000 blocks quickly', () => {
    const blocks: CodeBlock[] = [];

    // Create a binary tree call graph of 5000 functions: parent of func_i is func_floor(i/2)
    for (let i = 1; i <= 5000; i++) {
      const calls = [];
      const leftChild = i * 2;
      const rightChild = i * 2 + 1;
      if (leftChild <= 5000) calls.push(`    func_${leftChild}()`);
      if (rightChild <= 5000) calls.push(`    func_${rightChild}()`);

      blocks.push({
        id: `file.py::func_${i}@10`,
        path: 'file.py',
        name: `func_${i}`,
        kind: 'function',
        lineStart: 10,
        lineEnd: 15,
        params: [],
        decorators: [],
        body: `def func_${i}():\n${calls.join('\n')}`,
      });
    }

    const callGraph = buildCallGraph(blocks);

    const start = performance.now();
    const result = reachability(callGraph, ['file.py::func_1@10']);
    const duration = performance.now() - start;

    console.log(`[Bolt Benchmark] reachability for 5000-node tree took: ${duration.toFixed(2)}ms`);

    // Verify correctness: the 5000th node should be reachable at depth 12
    const lastId = 'file.py::func_5000@10';
    expect(result[lastId]).toBeDefined();
    expect(result[lastId].reachable).toBe(true);
    expect(result[lastId].reachDepth).toBe(12); // floor(log2(5000)) = 12

    // Performance expectation: With O(V + E) pointer-based queue and memoized backtracking,
    // 5000-node tree traversal should take under 50ms.
    expect(duration).toBeLessThan(50);
  });
});
