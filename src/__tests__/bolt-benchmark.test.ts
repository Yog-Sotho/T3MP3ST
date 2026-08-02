import { describe, it, expect } from 'vitest';
import { buildCallGraph, type CodeBlock } from '../recon/code-ingest.js';

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
});

import { packContext, type SourceBundle } from '../orchestration/context-pack.js';

describe('packContext performance and correctness', () => {
  it('correctly ranks and packs files and is extremely fast with optimized regexp matching', () => {
    // Generate 200 files, some large, to benchmark lowercase allocation vs case-insensitive RegExp match scaling
    const bundle: SourceBundle = [];
    for (let i = 1; i <= 200; i++) {
      // Create some large files with simulated content and a security hint or objective keyword
      const path = `src/module_${i}.ts`;
      let content = 'const x = 1;\n'.repeat(1000); // ~13KB file
      if (i % 20 === 0) {
        content += 'import pickle\npickle.loads(data)\n'; // security hint / keyword
      }
      bundle.push({ path, content });
    }

    const start = performance.now();
    const packed = packContext(bundle, {
      tokenBudget: 15000,
      objective: 'find pickle deserialize sink',
    });
    const end = performance.now();

    const duration = end - start;
    console.log(`[Bolt Benchmark] packContext for 200 files took: ${duration.toFixed(2)}ms`);

    // Verify correctness: files with deserialize/pickle should be prioritized and included
    expect(packed.includedFiles.length).toBeGreaterThan(0);
    const hasPrioritized = packed.includedFiles.some(f => f.includes('module_20') || f.includes('module_40'));
    expect(hasPrioritized).toBe(true);

    // Verify optimized regex performance expectation:
    // Without allocating large lowercase copies of 200 large files, it should complete in under 50ms.
    expect(duration).toBeLessThan(50);
  });
});
