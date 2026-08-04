# Sentinel's Journal - Critical Security Learnings

## 2026-07-28 - Whitelisted Binaries Flag Injection and Local File Disclosure
**Vulnerability:** The `/api/tools/execute` endpoint allowed direct command-line arguments to be passed to whitelisted binaries (like `curl` and `nmap`) via `execFile` without sanitizing or blocking dangerous option flags. This could allow attackers to perform flag injection to read/write arbitrary local files or execute arbitrary scripts.
**Learning:** Whitelisting binaries is a good starting security measure, but is insufficient if those binaries have powerful flags (e.g., `-o` in `curl`, `--script` in `nmap`) that can be abused for administrative actions or code execution.
**Prevention:** Always sanitize or block dangerous command-line flags and local-file-read prefixes (like `@` and `<` in `curl`) before calling any whitelisted subprocess, even if execution is done via safe APIs like `execFile`.

## 2026-07-29 - Unsanitized Error Messages and Extended Binary Flag Injection
**Vulnerability:** The `/api/whitebox/analyze` and `handleMissionReport` endpoints directly returned raw `error.message` strings to the client in their `catch` blocks, potentially leaking local system paths, repository internals, and stack details. Additionally, the whitelisted binary `dig` lacked flag-injection protection for its `-f` (batch file read) option, enabling local file disclosure via crafted direct execution commands.
**Learning:** Having a custom error sanitizer is only effective if it is consistently applied across all error-boundary catch blocks that output to the client. Similarly, whitelisted binary validation lists must cover all tools capable of reading local files.
**Prevention:** Always use `sanitizeErrorForResponse(error)` for every API error response block. Keep the list of whitelisted command flag injection guards up to date for any tool that accepts file paths (like `dig -f`).

## 2026-07-30 - IPv4-Mapped IPv6 SSRF Protection Bypass
**Vulnerability:** The `isRestrictedInternalIP` function checked if a given hostname was a restricted loopback or private IP, but failed to handle IPv4-mapped IPv6 address formats (e.g. `::ffff:127.0.0.1` or `[::ffff:10.0.0.1]`). Since underlying HTTP clients and DNS resolution libraries naturally resolve these mapped formats back to their IPv4 equivalents, this allowed SSRF protection to be bypassed on the `http_request` tool and other networked adapters.
**Learning:** Checking for standard IPv4/IPv6 strings or simple prefixes is insufficient when resolving mechanisms/libraries are capable of interpreting hybrid or mapped address spaces (such as IPv4-mapped IPv6).
**Prevention:** Always sanitize IP and host inputs by stripping brackets and mapped prefixes (like `::ffff:`) before passing them to defensive IP validation regexes or list checks.

## 2026-07-31 - Prototype Bypass via Direct Object Lookups on User-Supplied Keys
**Vulnerability:** Direct lookup of a user-supplied platform key on a `CONNECTORS` map or `creds` configuration object (e.g. `CONNECTORS[platform]` or `creds[platform]`) allowed attackers to bypass standard validity checks by supplying prototype properties like `toString`, `constructor`, or `__proto__`. These resolved to valid functions/objects on the global prototype chain rather than triggering expected key-missing/not-found logic.
**Learning:** Using untrusted/user-provided keys directly as properties on standard JavaScript objects can lead to prototype lookup bypasses, returning prototype methods or objects instead of undefined.
**Prevention:** Always validate user-provided keys against an array of safe, own properties via `listConnectors().includes(platform)` before any object lookup is performed.
