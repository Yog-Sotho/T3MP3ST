# Codebase Audit Report

**Date:** 2026-08-25
**Project:** T3MP3ST
**Language / Framework:** TypeScript / Node.js — Express API server + Commander CLI
**Project Type:** Web Service (Express API) + CLI tool
**Audit Mode:** Global (single `src/` directory)

---

## Executive Summary

T3MP3ST has a security posture well above average for a local pentesting tool: CSRF/CORS protection, DNS-rebinding mitigation, subprocess allowlisting, and no secrets logged. The primary concerns are a 7,749-line god file (`server.ts`) that blends routing, state management, persistence, and lifecycle; nine npm vulnerabilities that were present before this audit (all fixed via `npm audit fix` as part of this run); and no rate-limiting on any of the 68 mutation endpoints. The test suite is healthy (491 tests, all pass), types are clean, and lifecycle handling is correct. Priority action is splitting `server.ts` into domain modules — this is the single highest-leverage quality improvement available.

## Overall Score: 7.4 / 10

| Dimension | Score | Priority | Status |
|---|---|---|---|
| Security | 8/10 | CRITICAL | WARN |
| Build & Types | 9/10 | CRITICAL | PASS |
| Concurrency | 8/10 | HIGH | PASS |
| Code Principles | 5/10 | HIGH | WARN |
| Dependencies | 7/10 | MEDIUM | PASS (post-fix) |
| Observability | 7/10 | MEDIUM | PASS |
| Lifecycle | 9/10 | MEDIUM | PASS |
| Code Quality | 8/10 | MEDIUM | WARN |
| Dead Code | 8/10 | LOW | PASS |

*Hard caps: no CRITICAL security finding; no CRITICAL build error. Overall uncapped.*

---

## Strengths

1. **Layered localhost-only security** — CSRF origin guard on state-changing methods, Host-header DNS-rebinding block, loopback-only CORS, and X-Frame-Options all applied before any route handler runs. The inline comments explain the threat model clearly.
2. **Safe subprocess execution** — `execFile` (no shell) with a hard binary allowlist, NUL-byte argument rejection, and hostname regex validation before any arg reaches the OS. Injection surface is near-zero.
3. **Robust state persistence** — serialize-and-debounce write queue prevents concurrent filesystem writes; `flushPersist()` on SIGTERM/SIGINT closes the data-loss window before exit.
4. **Comprehensive test coverage** — 491 tests across 37 files, all passing. Both unit and integration scenarios covered.
5. **Thoughtful async error handling** — unhandledRejection and uncaughtException global handlers keep the process alive; tick errors caught per-iteration so a single LLM failure doesn't crash the command loop.

---

## Findings by Dimension

### Security [8/10]

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| MEDIUM | `src/server.ts` (all routes) | No rate limiting on 68 mutation endpoints. A local bug or a compromised browser tab could flood the server with requests. | Add `express-rate-limit` with a generous limit (e.g. 200 req/min per IP) on POST/PUT/DELETE routes. |
| LOW | `src/server.ts:302` | `express.json({ limit: '10mb' })` — 10 MB JSON body accepted. For local use this is fine, but a crafted payload can trigger high GC pressure. | Reduce to `1mb` unless a specific route genuinely needs larger bodies; override per-route if needed. |
| LOW | `src/server.ts` | Request logging on every request (`console.log`) logs full paths including any query params that might carry tokens or IDs. | Redact sensitive query params or switch to a structured logger that supports a `redact` config (e.g. pino). |

**Fixed during this audit:**
- 9 npm audit vulnerabilities resolved (see Dependencies) — including `ip-address` SSRF bypass (HIGH), `hono` cross-user data disclosure (MODERATE), and `body-parser` DoS (MODERATE).

### Build & Types [9/10]

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `tsconfig.json` | `"types": ["node", "vitest"]` in compilerOptions — these type stubs are needed but fail when `node_modules` is absent (e.g. fresh clone without install). CI must run `npm install` before `tsc`. | Document this in CI; consider adding a Makefile/justfile target that installs then type-checks. |
| LOW | `src/**/__tests__/*.ts` | 70 lint warnings: `@typescript-eslint/no-explicit-any` and `no-non-null-assertion` in test files. No errors. | Acceptable in test code; optionally add `/* eslint-disable */` at test file top or relax rule for `__tests__/` glob in eslint config. |

**Current state:** `tsc --noEmit` — 0 errors. `npm test` — 491/491 pass. `npm run lint` — 0 errors, 70 warnings (test files only).

### Concurrency [8/10]

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `src/server.ts:314,337` | `llm` and `tempestCommand` are module-level `let` singletons. Concurrent requests that both hit a "create if null" branch could theoretically double-initialize. Node's event loop makes this unlikely in practice. | Guard initialization with a `let initPromise: Promise<...> | null = null` pattern to make it idempotent. |

**Positive patterns:** `persistQueue.then(...)` serializes disk writes correctly. Debounce + flush-on-shutdown is correct. Tick errors caught per-iteration.

### Code Principles [5/10]

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| HIGH | `src/server.ts` (7,749 lines) | God file: API routing, state management, persistence, SSE broadcast, session lifecycle, and request/body parsing all co-located. Changes to any single concern require reading the whole file. | Extract into domain modules: `src/routes/`, `src/persistence/`, `src/sse/`. Each should be < 500 lines. `server.ts` becomes a composition root. |
| MEDIUM | `src/arsenal/index.ts` (3,322 lines) | Arsenal tool registry + execution + catalog in one file. | Split catalog into `catalog.ts` (already partially done) and keep `index.ts` as a thin dispatcher. |
| MEDIUM | `src/index.ts` (1,497 lines) | `TempestCommand` handles mission orchestration, operator lifecycle, stall detection, and event plumbing. | Extract stall detection and auto-spawn logic into separate strategy classes. |

**Advisory:** `src/general/index.ts` (1,597 lines) appears to be a unified domain model — meets the high-cohesion exception (`[High cohesion module]`).

### Dependencies [7/10]

| Severity | Package | Issue | Status |
|---|---|---|---|
| ~~HIGH~~ | `ip-address ≤10.3.0` | SSRF / trust-boundary bypass via octal/CIDR parsing | **Fixed** via `npm audit fix` |
| ~~HIGH~~ | `fast-uri 3.0.0–3.1.4` | Host confusion via backslash delimiter | **Fixed** |
| ~~HIGH~~ | `nanoid ≤3.3.17` | Infinite loop on negative/zero size | **Fixed** |
| ~~HIGH~~ | `postcss ≤8.5.22` | Path traversal via sourceMappingURL | **Fixed** |
| ~~HIGH~~ | `brace-expansion ≤1.1.17, 2.0.0–2.1.3` | ReDoS / OOM via consecutive `{}` | **Fixed** |
| ~~HIGH~~ | `js-yaml 4.0.0–4.3.0` | Quadratic CPU in omap resolution | **Fixed** |
| ~~MODERATE~~ | `hono ≤4.12.33` | Cross-user SSR data disclosure, CORS ReDoS | **Fixed** |
| ~~MODERATE~~ | `body-parser ≥2.0.0<2.3.0` | DoS via invalid limit | **Fixed** |
| ~~LOW~~ | `@hono/node-server <1.19.15` | Path traversal on Windows | **Fixed** |

**Post-fix state:** `npm audit` — 0 vulnerabilities.

### Observability [7/10]

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| MEDIUM | `src/server.ts` | 82 `console.log/warn/error` calls with no log level, no structured fields, no log shipping. Debug output mixed with operational output. | Adopt pino or winston with JSON output mode; log at appropriate levels (debug/info/warn/error). |
| LOW | `src/server.ts:4800` | `/health` endpoint returns server state but no uptime, memory usage, or dependency checks. | Extend health response to include `uptime`, `heapUsed`, and a simple ping to the LLM provider. |

**Positive:** Multiple domain-specific `/api/*/status` endpoints. SSE stream provides real-time event observability for the dashboard. Global rejection/exception handlers log and keep the process alive.

### Lifecycle [9/10]

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| INFO | `src/mcp-server.ts:230` | `main().catch(console.error)` — crash exits process with no cleanup. | Add SIGTERM/SIGINT handlers to the MCP server similar to the main server. |

**Positive:** SIGTERM/SIGINT flush `persistState` before exit. Tick loop errors don't propagate to process. SSE clients tracked and cleaned up on disconnect.

### Code Quality [8/10]

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| MEDIUM | `src/__tests__/*.ts` | 70 lint warnings across test files (`any`, `!`). Not blocking but signals test hygiene drift. | Add `@typescript-eslint/no-explicit-any: off` and `@typescript-eslint/no-non-null-assertion: off` to eslint `overrides` for `__tests__/**` so real production warnings aren't diluted by test noise. |
| LOW | `src/server.ts:305` | Request log middleware logs every request including high-frequency SSE tick pings, creating log noise in dev. | Gate verbose request logs behind a `DEBUG` env flag. |

### Dead Code [8/10]

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `src/index.ts` | Barrel re-exports everything from all sub-modules. Makes it hard to detect dead exports via tree-shaking. | Consider explicit named exports only for the public API surface; unexported internal helpers are invisible to consumers and easier to delete. |

---

## Advisory Findings

- **`src/general/index.ts` (1,597 lines)** — flagged as large file but is a unified domain model with clear single responsibility. `[High cohesion module — advisory only]`
- **Singleton init race** (concurrency) — Node.js event loop makes double-init extremely unlikely in a local tool context. `[Single-threaded runtime reduces risk to advisory]`

---

## Recommended Actions (Priority Order)

1. **[MEDIUM — SECURITY]** Add rate limiting to mutation endpoints: `npm install express-rate-limit` and apply middleware before route registration.
2. **[HIGH — PRINCIPLES]** Begin `server.ts` decomposition: extract persistence (`src/persistence/`), SSE (`src/sse/`), and domain route groups (`src/routes/`) into separate files. Target < 1,000 lines for the composition root.
3. **[MEDIUM — QUALITY]** Relax eslint rules for `__tests__/` glob so test-file warnings don't obscure production warnings.
4. **[LOW — OBSERVABILITY]** Adopt structured logging (pino recommended — zero-dep, fast, ESM-native) and gate per-request debug logs behind `LOG_LEVEL=debug`.
5. **[LOW — LIFECYCLE]** Add SIGTERM/SIGINT handlers to `src/mcp-server.ts`.
6. **[LOW — SECURITY]** Reduce JSON body limit from 10 MB to 1 MB; raise per-route only where needed.

---

## Sources Consulted

- `src/server.ts`, `src/index.ts`, `src/mcp-server.ts`, `src/config/index.ts`, `src/llm/index.ts`, `src/arsenal/index.ts`
- `tsconfig.json`, `package.json`, `eslint.config.js`
- `npm audit` output (pre- and post-fix)
- `npm run typecheck`, `npm run lint`, `npm test`, `npm run build`
- `docs/index.html` — dashboard confirmed present (25,963 lines, full multi-page SSE-driven UI)
