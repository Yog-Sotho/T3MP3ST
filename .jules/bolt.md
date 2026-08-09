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

## 2025-03-07 - [O(1) Excludes Check and Object/Regex Allocation Hot Paths]
**Learning:** File crawling can be slowed down significantly by repeated path-segment splits and array list-scans against multiple exclusions. Similarly, instantiating regexes or calling `Object.entries` on hot loops produces high GC overhead due to intermediate array allocation.
**Action:** Pre-compute file excludes into a plain names `Set` to check in O(1) time before falling back to full wildcard path matching. Hoist RegExp literals to static constants and replace `Object.entries` with a fast `for ... in` loop using `hasOwnProperty` in performance-critical loops.

## 2025-03-08 - [Case-Insensitive Context Packing Keyword Search Bottleneck]
**Learning:** During token-budgeted context packing, scoring files with `file.content.toLowerCase()` and `file.path.toLowerCase()` created brand-new string allocations on the V8 heap for every single file in the bundle. For codebases with multi-megabyte files, this led to massive GC pauses, high heap churn, and high CPU usage.
**Action:** Pre-compile case-insensitive, global `RegExp` objects for security hints (at the module level) and dynamic keywords (once per pack session) to search directly on original, uncopied content. This completely eliminates large-string `.toLowerCase()` allocations on hot scoring paths.

## 2025-03-09 - [BFS Queue Traversal and Path Copying Bottleneck]
**Learning:** Performing array-shifting (`queue.shift()`) in BFS loops on large graphs causes significant memory allocation and has O(N^2) complexity in JS arrays. Additionally, copying path string arrays (`[...path, callee]`) during active traversal causes massive garbage collection churn and high CPU overhead on deep graphs.
**Action:** Replace `queue.shift()` with an index pointer `head` to achieve true O(1) dequeues, and defer/memoize path reconstruction by keeping parent pointers during BFS and rebuilding paths recursively once at the end of the traversal. This keeps BFS traversal highly efficient and O(V + E).
