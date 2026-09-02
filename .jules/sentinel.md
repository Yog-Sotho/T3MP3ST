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

## 2026-07-31 - Unspecified/Wildcard Address SSRF Protection Bypass
**Vulnerability:** The `isRestrictedInternalIP` function validated hostnames against loopback, link-local, and private IP ranges to block SSRF, but failed to intercept the IPv4 unspecified address `0.0.0.0`, the `0.0.0.0/8` local network block, or the IPv6 unspecified address `::` / `[::]`. Since many operating systems and network libraries resolve unspecified or wildcard addresses back to loopback (localhost), this allowed SSRF protection to be bypassed for networked adapters.
**Learning:** Standard private/loopback IP validation must cover both unspecified/wildcard addresses and their broad local address blocks (`0.0.0.0/8` and `::`), as they route to localhost on most Unix-like platforms.
**Prevention:** Explicitly block wildcard/unspecified IP formats (such as `0.0.0.0`, `::`) and the entire local network block `0.0.0.0/8` within any SSRF filtering layer.

## 2026-08-01 - Prototype Pollution and Lookup Bypass in Bounty Connectors Registry
**Vulnerability:** The bounty platform CONNECTORS registry was initialized as a standard object literal. Consequently, standard Javascript prototype properties (such as `toString` or `__proto__`) were queryable and could bypass platform checks or cause unexpected runtime behavior / prototype lookup vulnerabilities when calling platform connector helpers.
**Learning:** Standard object literals inherit prototype properties that can be exploited in dynamic property lookups if user-supplied inputs are used as keys.
**Prevention:** Instantiate internal registries using `Object.create(null)` to completely strip the prototype, check properties securely using `Object.prototype.hasOwnProperty.call`, and validate input dynamically using the registry's own keys via `listConnectors()`.

## 2026-08-02 - IPv4-Compatible IPv6 SSRF Protection Bypass and Config Secret Leak
**Vulnerability:** The `isRestrictedInternalIP` function filtered IPv4-mapped IPv6 address formats (`::ffff:`) to prevent SSRF, but failed to process IPv4-compatible IPv6 addresses (`::<ipv4>`), allowing SSRF protection bypass. Additionally, `exportConfig` did not redact the `local` provider's API key slot, risking plaintext leakage of developer credentials during configuration sharing.
**Learning:** IPv6-mapped IPv4 checks must encompass both mapped (`::ffff:`) and deprecated-but-supported compatible (`::`) representations, as modern host network resolvers naturally map both formats back to internal IPv4 addresses. Similarly, credentials must be exhaustively redacted across all configured provider keys before exporting configuration models.
**Prevention:** Always use a single, unified regex `replace(/^::(?:ffff:(?:0:)?)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i, '$1')` to cleanly resolve both hybrid formats to standard IPv4 dot-decimal form before range checks. Maintain an exhaustive redacting map for all supported provider slots when serializing config data.

## 2026-08-03 - SSRF Bypass via IPv6 Zone Index
**Vulnerability:** The `isRestrictedInternalIP` function checked resolved IPv4-mapped/compatible IPv6 addresses against private/loopback IP blocks, but failed to strip IPv6 zone indices (such as `%eth0` or URL-encoded `%25eth0`) if appended to the input IP string. This allowed the address to bypass the extraction regex pattern matching, resulting in an SSRF bypass.
**Learning:** Checking for IPv4-mapped formats using strict regex patterns can be bypassed if characters like zone indices are allowed to persist at the end of the address. Any network/URI parsers and resolvers might still process the address as loopback or local.
**Prevention:** Explicitly strip zone indices (by splitting on `%` character) before executing any format-dependent security filtering or IP regex matches.

## 2026-08-04 - SSRF Bypass via Alternative IPv4 Formats
**Vulnerability:** The `isRestrictedInternalIP` function checked if a given hostname was a restricted loopback or private IP, but failed to handle alternative IPv4 representations (such as decimal IPs like `2130706433`, hexadecimal IPs like `0x7f000001`, octal IPs like `0177.0.0.1`, or shortened notations like `127.1`). Since many operating systems, DNS/IP resolvers, and HTTP libraries naturally parse these representations to standard internal IPs, this allowed SSRF protection to be bypassed for networked adapters.
**Learning:** Hardened IP filtering must not rely on simple dot-decimal regex pattern matching. It must convert any potential IP string into its standard canonical representation before performing range checks.
**Prevention:** Implement a full `inet_aton` parser to normalize alternative IPv4 formats into standard dot-decimal form before checking private, loopback, and local address spaces.

## 2026-08-05 - SSRF Bypass via Uncompressed Zero-Padded IPv6 Addresses
**Vulnerability:** The `isRestrictedInternalIP` function checked IPv6 addresses against loopback (`::1`), unspecified (`::`), and IPv4-mapped prefixes (`::ffff:`), but failed to handle uncompressed or zero-padded IPv6 notation (e.g. `0:0:0:0:0:0:0:1`, `0000:0000:0000:0000:0000:0000:0000:0001`, `0:0:0:0:0:ffff:127.0.0.1`, or `::0001`). As a result, network resolvers that expand zero-padded IPv6 addresses back to loopback or mapped IPv4 addresses bypassed the SSRF checks.
**Learning:** IPv6 checks that rely solely on `::` compressed representations fail when encountering fully uncompressed or zero-padded IPv6 address representations.
**Prevention:** Generalize IPv6 prefix stripping regexes to account for leading zero-hex groups (e.g., `^(?:(?:0*:){1,5}|::)`) and use wildcard/loopback matching patterns (`/^(?:0|:)*1$/i` and `/^(?:0|:)+$/i`) that handle uncompressed zero groups.

## 2026-08-06 - SSRF Bypass via Port-Appended, Scheme-Prefixed, or Path-Suffixed Target Inputs
**Vulnerability:** The `isRestrictedInternalIP` function evaluated target hostnames for restricted internal addresses, but failed to strip scheme prefixes (`http://`, `https://`), path/query/fragment suffixes (`/path`), or port suffixes (`:port`) before parsing alternative IPv4 formats or matching loopback/private IP strings. As a result, inputs like `localhost:8080`, `[::1]:8080`, or `127.0.0.1:8080` bypassed internal IP checks when passed to networked tools or API parameters expecting full target strings.
**Learning:** Security validation functions checking host/IP properties must canonicalize inputs by stripping schemes, paths, bracket wrappers, and port numbers before performing IP range or representation checks.
**Prevention:** Normalize input targets in IP/host validators by stripping scheme prefixes (`/^[a-z][a-z0-9+.-]*:\/\//i`), URL paths (`split('/')[0]`), bracket wrappers (`[...]`), and trailing port numbers (`:\d+`) prior to address pattern matching.

## 2026-08-07 - Whitelisted Binary Flag Injection via GDB/R2 Command Evaluation
**Vulnerability:** Whitelisted binaries (`gdb`, `r2`, `file`, `sqlmap`, `nikto`) lacked flag injection guards in `parseCommand`, allowing arbitrary shell command execution via flags like `gdb -ex "shell <cmd>"` or `r2 -c "!<cmd>"` when passed to `/api/tools/execute`.
**Learning:** Whitelisting binaries without restricting dangerous flags (command evaluation or file import options) permits arbitrary command execution or local file access through direct subprocess arguments.
**Prevention:** Maintain explicit `dangerousFlags` regex filters blocking `-ex`, `-c`, `-f`, `--os-cmd`, and config/script options for all whitelisted tools that support nested command or file evaluation.
## 2026-08-07 - SSRF Bypass via Userinfo Credentials in Target URLs
**Vulnerability:** The `isRestrictedInternalIP` function evaluated target hostnames/URLs for restricted internal addresses, but failed to strip userinfo prefixes (e.g. `user:pass@`) prior to extracting bracketed IPv6/IPv4 hosts or parsing IP representations. As a result, target inputs containing userinfo like `user:pass@127.0.0.1` or `http://admin@169.254.169.254` bypassed SSRF checks because the `@` symbol prevented matching IP patterns or parsing logic.
**Learning:** Host/IP validation logic must strip userinfo segments (`@`) along with schemes, paths, and ports during target URL canonicalization.
**Prevention:** Always strip userinfo prefixes (`ip = ip.slice(ip.lastIndexOf('@') + 1)`) after stripping schemes and paths before performing IP address evaluation.

## 2026-08-08 - SSRF Bypass via Trailing-Dot FQDN Targets and Domain Suffixes
**Vulnerability:** The `isRestrictedInternalIP` function evaluated target hostnames for restricted internal addresses, but failed to strip trailing dots (e.g. `localhost.`, `127.0.0.1.`, `[::1].`, `0x7f000001.`) or match `.localhost` domain suffixes and `localhost.localdomain`. Because standard DNS resolvers treat trailing dots as valid FQDNs, inputs with trailing dots or subdomain suffixes bypassed exact string equality and regex matches.
**Learning:** Target host/IP string validation must strip trailing dots (`ip = ip.replace(/\.+$/, '')`) during canonicalization and check domain suffix wildcards (such as `.endsWith('.localhost')`) so FQDN representations cannot evade loopback/private range detection.
**Prevention:** Always strip trailing dots from hostname/IP strings prior to IPv4 alternative parsing and exact name/regex evaluations.

## 2026-08-09 - SSRF Bypass via Carrier-Grade NAT (CGNAT) / Shared Address Space
**Vulnerability:** The `isRestrictedInternalIP` function evaluated target hostnames for restricted internal addresses, but failed to block the Carrier-Grade NAT (CGNAT) / Shared Address Space (`100.64.0.0/10`, RFC 6598), which includes Alibaba Cloud metadata IP `100.100.100.100`. Attackers could exploit targets in CGNAT ranges to perform SSRF against internal cloud metadata services or shared network infrastructure.
**Learning:** Defensive IP checks must include Carrier-Grade NAT ranges (`100.64.0.0/10`) alongside standard RFC 1918 private IP ranges, as cloud providers (like Alibaba Cloud) bind internal metadata endpoints within `100.64.0.0/10`.
**Prevention:** Include `/^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./` in restricted IP filters to block CGNAT range and cloud metadata endpoints.

## 2026-08-10 - LLM Provider Unclassified Errors in Fallback Routing & Missing Binary Flag Injection Guard
**Vulnerability:** `OpenAIAdapter.chat` threw generic `Error` instances instead of structured `LLMApiError` instances on HTTP error responses. Consequently, `classifyErrorKind` failed to identify 401/403/404 errors as permanent during fallback routing, causing futile retries and failing to honor `retryAfterMs` backoff. Additionally, `nuclei` lacked flag-injection filtering in `parseCommand`, leaving `-o`/`-t`/`-config` options unblocked on `/api/tools/execute`.
**Learning:** All LLM provider adapters must throw `LLMApiError` carrying the HTTP status code and `retryAfterMs` so `LLMBackbone`'s fallback routing can distinguish transient errors from permanent auth/missing-model failures. Whitelisted binary argument filters must also cover scanner binaries capable of taking template/code or output file options.
**Prevention:** Throw `LLMApiError` consistently across all LLM adapters when `!response.ok`, and maintain `dangerousFlags` regex rules for every binary in `SAFE_COMMANDS` that accepts file output or code execution arguments.

## 2026-08-11 - SSRF Bypass via Uncompressed 6-Group IPv4-Compatible IPv6 Addresses
**Vulnerability:** The `isRestrictedInternalIP` function stripped IPv6 prefix patterns using `^(?:(?:0*:){1,5}|::)`, which matched IPv4-mapped IPv6 addresses (`0:0:0:0:0:ffff:127.0.0.1`), but failed to match uncompressed IPv4-compatible IPv6 addresses (`0:0:0:0:0:0:127.0.0.1` or `0000:0000:0000:0000:0000:0000:10.0.0.1`) which have 6 zero-hex groups (96 zero bits). As a result, uncompressed IPv4-compatible targets bypassed extraction and evaded SSRF filters.
**Learning:** Uncompressed IPv4-compatible IPv6 notation contains 6 zero-hex groups before the embedded IPv4 address, unlike IPv4-mapped notation which contains 5 zero-hex groups followed by `ffff`.
**Prevention:** Match up to 6 leading zero-hex groups (`^(?:(?:0*:){1,6}|::)`) when stripping IPv6 prefixes to normalize both IPv4-mapped and IPv4-compatible addresses into standard IPv4 representations.

## 2026-08-12 - Whitelisted Binary Flag Injection via Katana and Naabu Options
**Vulnerability:** The whitelisted binaries `katana` and `naabu` lacked entries in `dangerousFlags` in `parseCommand`, allowing attackers to pass file output (`-o`/`-output`), file input (`-f`/`-file`/`-dL`/`-iL`), or config options (`-config`) during direct execution via `/api/tools/execute`.
**Learning:** Adding tools to `SAFE_COMMANDS` without defining flag-injection filters allows file read/write and arbitrary configuration loading through direct tool flags.
**Prevention:** Whenever a new binary is registered in `SAFE_COMMANDS`, verify and add explicit `dangerousFlags` regex rules in `parseCommand` covering all output, input file list, request file, and config flags.
