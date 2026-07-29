# Sentinel's Journal - Critical Security Learnings

## 2026-07-28 - Whitelisted Binaries Flag Injection and Local File Disclosure
**Vulnerability:** The `/api/tools/execute` endpoint allowed direct command-line arguments to be passed to whitelisted binaries (like `curl` and `nmap`) via `execFile` without sanitizing or blocking dangerous option flags. This could allow attackers to perform flag injection to read/write arbitrary local files or execute arbitrary scripts.
**Learning:** Whitelisting binaries is a good starting security measure, but is insufficient if those binaries have powerful flags (e.g., `-o` in `curl`, `--script` in `nmap`) that can be abused for administrative actions or code execution.
**Prevention:** Always sanitize or block dangerous command-line flags and local-file-read prefixes (like `@` and `<` in `curl`) before calling any whitelisted subprocess, even if execution is done via safe APIs like `execFile`.

## 2026-07-29 - Unsanitized Error Messages and Extended Binary Flag Injection
**Vulnerability:** The `/api/whitebox/analyze` and `handleMissionReport` endpoints directly returned raw `error.message` strings to the client in their `catch` blocks, potentially leaking local system paths, repository internals, and stack details. Additionally, the whitelisted binary `dig` lacked flag-injection protection for its `-f` (batch file read) option, enabling local file disclosure via crafted direct execution commands.
**Learning:** Having a custom error sanitizer is only effective if it is consistently applied across all error-boundary catch blocks that output to the client. Similarly, whitelisted binary validation lists must cover all tools capable of reading local files.
**Prevention:** Always use `sanitizeErrorForResponse(error)` for every API error response block. Keep the list of whitelisted command flag injection guards up to date for any tool that accepts file paths (like `dig -f`).
