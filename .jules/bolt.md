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

## 2025-03-09 - [BFS Reachability Queue Shifting and Backtracking Bottlenecks]
**Learning:** In BFS reachability traversals over code call graphs, calling `queue.shift()` inside a while loop is $O(N)$ per element, leading to $O(N^2)$ time complexity on large graphs. Additionally, replicating and copying path arrays with `[...path, callee]` at every step incurs massive allocation/GC overhead. Finally, reconstructing paths backwards with individual backtracking on deeply nested linear structures results in $O(N^2)$ backtracking traversals.
**Action:** Use a fast-read pointer index to dequeue in $O(1)$ time, record parent pointers during BFS in a simple `Map`, and reconstruct the paths in a single topological/BFS order pass to build path arrays with optimal $O(1)$ prepending of previously cached parent paths.

## 2025-03-10 - [EvidenceVault High-Throughput Redundant Cloning and Allocation Bottlenecks]
**Learning:** Query and statistic methods on database-like storage classes (such as `EvidenceVault`) can easily introduce silent, heavy CPU and memory churn if we first copy/clone all stored values (`getAllFindings()`) and then filter or aggregate them. Deeply cloning complex objects like findings recursively is extremely expensive, and creating multiple intermediate array allocations causes heavy GC pressure.
**Action:** Use single-pass, allocation-free iteration (directly over Map `.values()`) and perform conditional/lazy cloning, copying only the matched elements. Compute all statistics in a single-pass loop without intermediate `.filter()` arrays.

## 2025-03-11 - [TargetEnvironment Redundant Array Allocation and Filter Bottlenecks]
**Learning:** Storage/environment query methods (such as those in `TargetEnvironment`) that perform repeated filtering/searching of active targets are highly susceptible to redundant memory allocations and CPU churn when calling intermediate getters like `getAllTargets()`. Converting Map values into a full array only to immediately run `.filter()` creates massive array footprint allocations and garbage collection pauses under high-throughput settings.
**Action:** Utilize single-pass, allocation-free iteration (looping directly over the Map `.values()`) and perform direct checks to push only match-filtered results into the final returned array. Compute all target statistics inside `getStats()` in a single-pass loop directly over the Map values.

## 2025-03-12 - [CommsChannel Query Filter Bottleneck and Reference State Safety]
**Learning:** High-throughput query routes on communication hubs (such as `CommsChannel`) can suffer from severe $O(N)$ linear-scan filter performance degradation under dense agent message polling. Simply returning the internal indexed array reference directly is a major reference-leak risk that allows external code to mutate private internal indexes.
**Action:** Replace $O(N)$ message-filtering loops with $O(1)$ lookup maps and return a shallow copy of the matched subset `[...list]` to achieve extremely high throughput without compromising data encapsulation and state safety.

## 2025-03-13 - [KnowledgeBase Pattern Match RegExp Compilation Bottleneck]
**Learning:** Instantiating `new RegExp(p.pattern, 'i')` dynamically inside `matchPatterns` loops recreates regex objects on every scan invocation. Additionally, relying on array identity checks (e.g. `this.patterns === DEFAULT_PATTERNS`) is fragile and breaks whenever patterns are cloned or dynamically modified.
**Action:** Maintain a pattern string to `RegExp` lookup Map (`PATTERN_REGEX_CACHE`) to lazily cache compiled RegExp objects per pattern string, avoiding RegExp instantiation overhead across all custom and default pattern lists.

## 2025-03-14 - [TaskQueue Linear Search and Multi-Pass Sort Bottlenecks]
**Learning:** High-throughput mission task queues that perform $O(N)$ linear array searches (`this.tasks.find(...)`) on every status update, assignment, or task check experience significant CPU degradation under large task volume. Additionally, calling `add()` iteratively in `addMany()` re-sorts the queue array $N$ times unnecessarily.
**Action:** Maintain an internal `tasksById` Map index to execute $O(1)$ task lookups across `getTask`, `updateStatus`, `assign`, and `remove`. Defer array sorting in `addMany` to a single pass after all tasks are populated.

## 2025-03-15 - [Panel Adjudication Cite-Check Re-Parsing Bottleneck]
**Learning:** During pack audit adjudication, verifying cited killing guards across large panels of auditor/refuter votes re-tokenized and re-parsed source files on every single vote, causing $O(M \times L)$ CPU time (where $M$ is votes and $L$ is source lines) and taking over 4.7 seconds for 5,000 votes. Additionally, instantiating `new RegExp(...)` per source line inside guard checks caused heavy regex compilation overhead and heap object allocation.
**Action:** Pre-compile `COMPARISON_G_RE` globally and reset `lastIndex = 0` per line. Cache cite-check verification results per unique file+quote in `downgradeUnverifiedRefutes()` to execute the cite-check once per unique guard across vote panels, reducing 5,000-vote adjudication time from ~4,777ms to 4.33ms (~1,100x speedup).
