# Bolt's Journal - Critical Learnings Only

## 2025-02-15 - [Initial setup]
**Learning:** Initial setup of Bolt's Journal. No specific performance issues identified yet.
**Action:** Keep an eye out for potential optimization bottlenecks.

## 2025-02-15 - [O(N * M) call graph construction bottleneck]
**Learning:** The previous implementation of static code call graph resolution iterated over every block $N$, compiling a custom `RegExp` per unique block name $M$, resulting in an $O(N \times M)$ nested loop. For codebases with hundreds of blocks, this became extremely CPU intensive and slow.
**Action:** Replace the $O(N \times M)$ nested regex testing loop with an $O(N)$ single-pass extraction step per block. We parse out all target-shaped name strings first (matching words followed by `(`) and check if those names exist in the `byName` lookup map. Support both standard letters/digits/underscores and the `$` character (commonly used in JS/TS/PHP identifiers) to ensure broad multi-language compatibility.

## 2025-03-05 - [High-Throughput Secret Redaction Bottleneck]
**Learning:** String/credential redaction in high-throughput paths (e.g. processing whole code blocks, log lines, or audit trails) suffered from a performance bottleneck where 18 separate regexes were tested and `Object.values(SECRET_PATTERNS)` was allocated on every single string, even when the string was completely safe and free of secrets.
**Action:** Implement a fast-path pre-screening check (`PRE_SCREEN_RE`) that filters out 99.9% of normal clean lines in O(N) time, and hoist regex objects and array definitions outside of hot-path loops to avoid redundant allocations and compilation overhead.

## 2025-03-06 - [Avoid split/join on hot string loops and character loops on large content]
**Learning:** Splitting multi-line block bodies with `.split('\n')` inside loops (e.g. `buildCallGraph`) causes large amounts of heap allocations and heavy GC overhead. Similarly, scanning large strings character-by-character inside JavaScript loops (e.g. `approxLoc`) is slow compared to native C++-backed `indexOf()` searches.
**Action:** Use fast, non-allocating string searches (`indexOf` and `substring`) to isolate specific sections/substrings, and leverage C++-optimized substring scan loops in JS runtimes.

## 2025-03-07 - [O(N) vs O(1) traversal path excludes pre-categorization]
**Learning:** Checking a file path against a list of exclude glob patterns by calling `.split(sep)` and performing linear array checks on every file and directory in a recursive traversal is highly CPU-intensive and causes major GC overhead. Since traversals prune directories hierarchically, we can skip redundant checks of already-passed parent segments.
**Action:** Pre-categorize exclude patterns into plain single-segment Sets, wildcard arrays, and multi-segment arrays at the start of `crawl`. Match folder/file names against the plain Set in O(1) time during recursive walk traversals, and use fast non-allocating character scanning (`isSegmentOfPath`) for multi-segment path exclusions.
