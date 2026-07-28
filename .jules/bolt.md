# Bolt's Journal - Critical Learnings Only

## 2025-02-15 - [Initial setup]
**Learning:** Initial setup of Bolt's Journal. No specific performance issues identified yet.
**Action:** Keep an eye out for potential optimization bottlenecks.

## 2025-02-15 - [O(N * M) call graph construction bottleneck]
**Learning:** The previous implementation of static code call graph resolution iterated over every block $N$, compiling a custom `RegExp` per unique block name $M$, resulting in an $O(N \times M)$ nested loop. For codebases with hundreds of blocks, this became extremely CPU intensive and slow.
**Action:** Replace the $O(N \times M)$ nested regex testing loop with an $O(N)$ single-pass extraction step per block. We parse out all target-shaped name strings first (matching words followed by `(`) and check if those names exist in the `byName` lookup map. Support both standard letters/digits/underscores and the `$` character (commonly used in JS/TS/PHP identifiers) to ensure broad multi-language compatibility.
