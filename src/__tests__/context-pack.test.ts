/**
 * context-pack tests
 *
 * Covers the token-budgeted, repo-map + relevance packer that replaced the old
 * blind head-slice truncation:
 *   - packContext respects the token budget
 *   - the REPO MAP header is ALWAYS present
 *   - higher-relevance files are packed before lower ones when budget is tight
 *   - droppedFiles is reported when the bundle exceeds budget (no silent loss)
 *   - parseLooseSource splits a delimited blob and handles a plain blob
 */

import { describe, it, expect } from 'vitest';
import {
  parseLooseSource,
  packContext,
  estimateTokens,
  type SourceBundle,
} from '../orchestration/context-pack.js';

describe('estimateTokens', () => {
  it('approximates chars / 4', () => {
    expect(estimateTokens('')).toBe(0);
    expect(estimateTokens('abcd')).toBe(1);
    expect(estimateTokens('a'.repeat(40))).toBe(10);
  });
});

describe('parseLooseSource', () => {
  it('splits a delimited blob into files by delimiter path', () => {
    const blob = [
      '=== src/auth.py ===',
      'def login(u, p):',
      '    return check(u, p)',
      '--- FILE: src/util.js ---',
      'function noop() {}',
      '## handlers/route.ts',
      'export const route = 1;',
    ].join('\n');

    const bundle = parseLooseSource(blob);
    const paths = bundle.map(f => f.path);
    expect(paths).toContain('src/auth.py');
    expect(paths).toContain('src/util.js');
    expect(paths).toContain('handlers/route.ts');

    const auth = bundle.find(f => f.path === 'src/auth.py');
    expect(auth?.content).toContain('def login');
    expect(auth?.content).not.toContain('function noop'); // stays in util.js
  });

  it('returns a single pseudo-file for a plain blob with no delimiters', () => {
    const blob = 'just some prose about a struct\nwith no file markers at all';
    const bundle = parseLooseSource(blob);
    expect(bundle).toHaveLength(1);
    expect(bundle[0].path).toBe('(source)');
    expect(bundle[0].content).toBe(blob);
  });

  it('does not split on ordinary horizontal rules or comment sentences', () => {
    // "---" with no path, and a "// a comment." that is not a file path
    const blob = 'line one\n---\nline two\n// this is a normal comment here\nline three';
    const bundle = parseLooseSource(blob);
    expect(bundle).toHaveLength(1);
    expect(bundle[0].path).toBe('(source)');
  });

  it('preserves preamble content before the first delimiter', () => {
    const blob = 'README notes here\n=== a/b.c ===\nint main(){}';
    const bundle = parseLooseSource(blob);
    expect(bundle.map(f => f.path)).toContain('(preamble)');
    expect(bundle.find(f => f.path === '(preamble)')?.content).toContain('README notes');
  });
});

describe('packContext', () => {
  it('always emits a REPO MAP header, even for a huge repo on a tiny budget', () => {
    const bundle: SourceBundle = Array.from({ length: 200 }, (_, i) => ({
      path: `src/file_${i}.ts`,
      content: 'x'.repeat(500),
    }));
    const packed = packContext(bundle, { tokenBudget: 300 });
    expect(packed.text).toContain('=== REPO MAP');
    // Huge inventory on a tiny budget must cap the map, not silently drop it.
    expect(packed.text).toMatch(/more files/);
  });

  it('respects the token budget (uses at most ~the budget)', () => {
    const bundle: SourceBundle = Array.from({ length: 30 }, (_, i) => ({
      path: `mod_${i}.ts`,
      content: 'const x = 1;\n'.repeat(200),
    }));
    const budget = 2000;
    const packed = packContext(bundle, { tokenBudget: budget });
    // tokensUsed is the reported accounting; assert it never overruns the budget.
    expect(packed.tokensUsed).toBeLessThanOrEqual(budget);
    // and the real assembled text is in the same ballpark (small map/newline slack)
    expect(estimateTokens(packed.text)).toBeLessThanOrEqual(budget + 50);
  });

  it('reports droppedFiles when the bundle exceeds the budget', () => {
    const bundle: SourceBundle = Array.from({ length: 20 }, (_, i) => ({
      path: `big_${i}.ts`,
      content: 'y'.repeat(4000), // ~1000 tokens each — cannot all fit in 1500
    }));
    const packed = packContext(bundle, { tokenBudget: 1500 });
    expect(packed.droppedFiles.length).toBeGreaterThan(0);
    // included + dropped account for every file (nothing vanishes off the books)
    expect(packed.includedFiles.length + packed.droppedFiles.length).toBe(bundle.length);
  });

  it('packs higher-relevance files before lower ones when budget is tight', () => {
    const bundle: SourceBundle = [
      { path: 'unrelated/readme.md', content: 'z'.repeat(3000) },
      { path: 'src/deserialize_handler.py', content: 'pickle.loads(data)\n'.repeat(150) },
      { path: 'misc/notes.txt', content: 'w'.repeat(3000) },
    ];
    // Budget fits roughly one file body below the map. The security-relevant /
    // objective-matching file must win.
    const packed = packContext(bundle, {
      tokenBudget: 1200,
      objective: 'find an unsafe deserialize sink using pickle',
    });
    expect(packed.includedFiles).toContain('src/deserialize_handler.py');
    // the winner appears in the body, not just the map
    const bodyStart = packed.text.indexOf('=== FILE:');
    expect(packed.text.slice(bodyStart)).toContain('src/deserialize_handler.py');
    expect(packed.droppedFiles.length).toBeGreaterThan(0);
  });

  it('head+tail elides a single oversized file instead of dropping it', () => {
    const marker = 'UNIQUE_TAIL_MARKER_9f3';
    const huge = 'A'.repeat(20000) + marker;
    const bundle: SourceBundle = [{ path: 'one/giant.c', content: huge }];
    const packed = packContext(bundle, { tokenBudget: 1000 });
    expect(packed.includedFiles).toContain('one/giant.c');
    expect(packed.text).toContain('…[middle elided');
    expect(packed.text).toContain('A'); // head present
    expect(packed.text).toContain(marker); // tail present
  });

  it('echoes the budget and never drops the map for a plain single-file bundle', () => {
    const bundle = parseLooseSource('int main() { return 0; }');
    const packed = packContext(bundle, { tokenBudget: 5000 });
    expect(packed.tokenBudget).toBe(5000);
    expect(packed.text).toContain('=== REPO MAP');
    expect(packed.includedFiles).toContain('(source)');
    expect(packed.droppedFiles).toHaveLength(0);
  });

  it('benchmark: packContext handles 100 large files (100KB each) with dynamic keywords and security hints quickly', () => {
    // Generate 100 large dummy files (100KB each) filled with text, occasional keywords, and security hints
    const bundle: SourceBundle = Array.from({ length: 100 }, (_, i) => {
      const parts = [];
      for (let j = 0; j < 1000; j++) {
        parts.push(`line_${j}_random_content_for_context_packing_benchmark_data_structure_efficiency`);
      }
      // Insert some keywords and security hints at intervals
      parts[100] = 'route handler auth login session controller';
      parts[500] = 'target_objective_keyword_match_relevance_booster';
      return {
        path: `src/performance_bench/large_module_${i}.py`,
        content: parts.join('\n'),
      };
    });

    const start = performance.now();
    const packed = packContext(bundle, {
      tokenBudget: 50000,
      objective: 'find the target_objective_keyword_match_relevance_booster route handler',
    });
    const duration = performance.now() - start;

    console.log(`[Bolt Benchmark] packContext for 100 large files (10MB total) took: ${duration.toFixed(2)}ms`);

    expect(packed.includedFiles.length).toBeGreaterThan(0);
    // Performance expectation: With our O(1) lowercasing elimination, it should easily run in under 150ms.
    expect(duration).toBeLessThan(150);
  });
});
