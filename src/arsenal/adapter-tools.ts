/**
 * T3MP3ST Arsenal — Kali+ adapter → CustomTool factory (Phase-1)
 *
 * Turns the catalogued Kali+ `ToolAdapter`s (src/arsenal/catalog.ts) into real, arg-templated,
 * scope-checked, gracefully-degrading `CustomTool`s (src/types/index.ts) that the engine's Arsenal
 * can register and an operator can call.
 *
 * Design constraints (from the pack-hunt design HT-1):
 *  - Dangerous adapters stay off the callable surface: `execution === 'catalog_only'` (metasploit,
 *    hydra) and `execution === 'import_only'` (bloodhound) are NEVER minted — `adapterToCustomTool`
 *    returns `null` for them, so a keyless pack agent cannot invoke them through generic execution.
 *  - Missing binary DEGRADES, never throws: the handler returns `{ success:false, error: installHint }`
 *    exactly like the hand-written `EXTERNAL_TOOLS` (nmap_scan/nuclei_scan) do, so the model can pick
 *    another tool instead of crashing the loop.
 *  - Scope is enforced BEFORE the subprocess runs. The Arsenal already has a hard egress gate in
 *    `execute()` (scopeViolation), but that only fires when a mission has set a scope. This factory
 *    accepts an OPTIONAL `scopeOk(target)` predicate as a second, in-handler belt-and-braces check on
 *    the resolved target for THIS specific adapter; when provided and it returns false the handler
 *    returns a `SCOPE DENIED` result without spawning anything.
 *
 * Everything is done through INJECTED dependencies (`runSubprocess` / `isToolAvailable` from
 * src/arsenal/index.ts, an optional `scopeOk`) so this module stays self-contained and unit-testable
 * with fakes — it spawns no real binaries of its own and imports no server code.
 */

import type { ToolAdapter } from './catalog.js';
import type { CustomTool, ToolContext, ToolResult } from '../types/index.js';

// =============================================================================
// INJECTED DEPENDENCIES
// =============================================================================

/** Result shape of the real `runSubprocess` in src/arsenal/index.ts. */
export interface SubprocessResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * The (fakeable) dependencies the factory needs. `runSubprocess` / `isToolAvailable` are the real
 * functions exported from src/arsenal/index.ts; `scopeOk` is an optional in-handler target gate.
 */
export interface AdapterToolDeps {
  /** Same signature as `runSubprocess` in src/arsenal/index.ts. */
  runSubprocess: (
    command: string,
    args: string[],
    options?: { timeout?: number; maxOutput?: number }
  ) => Promise<SubprocessResult>;
  /** Same signature as `isToolAvailable` in src/arsenal/index.ts. */
  isToolAvailable: (command: string) => Promise<boolean>;
  /**
   * Optional per-target scope predicate. Receives the resolved target host/url the adapter would hit;
   * return false to refuse the call. When omitted, the in-handler scope check is skipped (the
   * Arsenal-level egress gate in execute() still applies at the engine boundary).
   */
  scopeOk?: (target: string) => boolean;
}

// =============================================================================
// SECURITY HELPERS
// =============================================================================

/**
 * Parse an alternative IPv4 representation (hex, octal, decimal, or shortened)
 * to its standard dot-decimal format. Returns null if invalid or not an alternative IP.
 */
function parseAlternativeIPv4(hostname: string): string | null {
  const parts = hostname.split('.');
  if (parts.length > 4 || parts.length === 0) return null;

  const numericParts: number[] = [];
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) return null;

    let val = -1;
    if (/^0x[0-9a-f]+$/i.test(trimmed)) {
      val = parseInt(trimmed, 16);
    } else if (/^0[0-7]+$/.test(trimmed)) {
      val = parseInt(trimmed, 8);
    } else if (/^\d+$/.test(trimmed)) {
      val = parseInt(trimmed, 10);
    } else {
      return null;
    }

    if (isNaN(val) || val < 0) return null;
    numericParts.push(val);
  }

  const len = numericParts.length;
  if (len === 4) {
    if (numericParts.some(x => x > 255)) return null;
    return numericParts.join('.');
  }
  if (len === 3) {
    if (numericParts[0] > 255 || numericParts[1] > 255 || numericParts[2] > 65535) return null;
    const p3 = numericParts[2];
    return `${numericParts[0]}.${numericParts[1]}.${(p3 >> 8) & 255}.${p3 & 255}`;
  }
  if (len === 2) {
    if (numericParts[0] > 255 || numericParts[1] > 16777215) return null;
    const p2 = numericParts[1];
    return `${numericParts[0]}.${(p2 >> 16) & 255}.${(p2 >> 8) & 255}.${p2 & 255}`;
  }
  if (len === 1) {
    if (numericParts[0] > 4294967295) return null;
    const p1 = numericParts[0];
    return `${(p1 >>> 24) & 255}.${(p1 >>> 16) & 255}.${(p1 >>> 8) & 255}.${p1 & 255}`;
  }

  return null;
}

/**
 * SSRF Protection: Detect restricted internal IP addresses and metadata endpoints.
 * Prevents access to localhost, private ranges, and cloud provider metadata services.
 * Used defensively by all HTTP-based tools to block SSRF attacks.
 */
export function isRestrictedInternalIP(hostname: string): boolean {
  let ip = hostname.toLowerCase().trim();

  // Strip scheme if present (e.g. http://, https://)
  ip = ip.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');

  // Strip path, query, and fragment (e.g. /path, ?query, #fragment)
  ip = ip.split('/')[0].split('?')[0].split('#')[0];

  // Strip userinfo prefix if present (e.g. user:pass@host or admin@host)
  if (ip.includes('@')) {
    ip = ip.slice(ip.lastIndexOf('@') + 1);
  }

  // Strip brackets for IPv6 / bracketed hosts (e.g. [::1]:8080 or [127.0.0.1])
  if (ip.startsWith('[')) {
    const end = ip.indexOf(']');
    if (end !== -1) {
      ip = ip.slice(1, end);
    } else {
      ip = ip.slice(1);
    }
  } else {
    // Strip port suffix for IPv4 / hostname / single-colon target if present
    const firstColon = ip.indexOf(':');
    const lastColon = ip.lastIndexOf(':');
    if (firstColon !== -1 && firstColon === lastColon) {
      const possiblePort = ip.slice(lastColon + 1);
      const portNum = Number(possiblePort);
      if (/^\d{1,5}$/.test(possiblePort) && Number.isInteger(portNum) && portNum >= 0 && portNum <= 65535) {
        ip = ip.slice(0, lastColon);
      }
    }
  }

  // Strip IPv6 zone indices (e.g., %eth0 or %25eth0)
  ip = ip.split('%')[0];

  // Strip trailing dot(s) for FQDNs (e.g. localhost., 127.0.0.1., 0x7f000001.)
  ip = ip.replace(/\.+$/, '');

  // Resolve alternative IPv4 representation (including hex, decimal, octal, and mapped IPv6)
  const ipv6PrefixRegex = /^(?:(?:0*:){1,5}|::)(?:ffff:(?:0:)?)?/i;
  const hasPrefix = ipv6PrefixRegex.test(ip);
  const potentialIp = hasPrefix ? ip.replace(ipv6PrefixRegex, '') : ip;
  const parsed = parseAlternativeIPv4(potentialIp);
  if (parsed) {
    ip = parsed;
  } else {
    // Fallback to legacy mapped/compatible regex
    ip = ip.replace(/^(?:(?:0*:){1,5}|::)(?:ffff:(?:0:)?)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i, '$1');
  }

  // Loopback and unspecified/wildcard addresses
  if (
    ip === 'localhost' ||
    ip.endsWith('.localhost') ||
    ip === 'localhost.localdomain' ||
    ip === '127.0.0.1' ||
    ip === '0.0.0.0' ||
    /^(?:0|:)*1$/i.test(ip) ||
    /^(?:0|:)+$/i.test(ip)
  ) return true;

  // Private IPv4 and local ranges
  if (/^0\./.test(ip)) return true; // 0.0.0.0/8 (local network/wildcard addresses)
  if (/^10\./.test(ip)) return true; // 10.0.0.0/8
  if (/^192\.168\./.test(ip)) return true; // 192.168.0.0/16
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true; // 172.16.0.0/12

  // Link-local and metadata ranges
  if (/^169\.254\./.test(ip)) return true; // 169.254.0.0/16 (AWS metadata, APIPA)
  if (/^127\./.test(ip)) return true; // All of 127.0.0.0/8

  // IPv6 private ranges
  if (/^(fc00|fd00):/i.test(ip)) return true; // Unique local addresses
  if (/^fe80:/i.test(ip)) return true; // Link-local addresses

  return false;
}

// =============================================================================
// ARG TEMPLATES
// =============================================================================

/**
 * How a given adapter's binary consumes its target + which context parameter carries that target.
 *
 * `build(target, params)` returns the full argv for the subprocess. `targetParam` names the
 * ToolContext parameter the target is read from (falling back to `context.target.address`).
 * `defaultTimeoutMs` is the per-adapter subprocess timeout (scanners get longer budgets).
 */
interface ArgTemplate {
  targetParam: string;
  defaultTimeoutMs: number;
  build: (target: string, params: Record<string, unknown>) => string[];
}

const str = (v: unknown): string | undefined =>
  typeof v === 'string' && v.trim() ? v.trim() : undefined;

/**
 * Resolve the filesystem PATH a source/supply-chain scanner should run against (semgrep, gitleaks,
 * trivy, …). These adapters are non-networked and operate on a directory, defaulting to the working
 * dir (`.`). The subcommand + output flags in each template are HARDCODED — only this path is
 * tunable, and it is sanitised so it cannot smuggle a flag or an inherited URL past the gate:
 *   - a leading `-` would be reparsed as a scanner flag (arg injection) → fall back to `.`,
 *   - an http(s) URL (e.g. a networked mission target inherited via context.target.address) is not a
 *     scan path → fall back to `.`.
 */
const scanPath = (target: string, params: Record<string, unknown>): string => {
  const p = str(params.path) ?? str(params.target) ?? (target || undefined);
  if (!p || /^-/.test(p) || /^https?:\/\//i.test(p)) return '.';
  return p;
};

/**
 * Per-binary arg templates for the common command-ready adapters. Keyed by `adapter.binary` (the
 * process name), with `adapter.id` also accepted as a fallback key so callers can template by either.
 * Anything not listed here falls back to `DEFAULT_TEMPLATE` (pass the target as a positional arg).
 *
 * Templates are intentionally conservative — no intrusive flags are auto-added; risk stays where the
 * catalog put it and the Arsenal egress gate + optional scopeOk fence the target.
 */
const ARG_TEMPLATES: Record<string, ArgTemplate> = {
  nmap: {
    targetParam: 'target',
    defaultTimeoutMs: 120_000,
    // Scan flags are HARDCODED — never taken from an LLM-supplied string. A free-form `flags` param
    // word-split into argv is arbitrary-nmap-flag injection: `-oN`/`-oX` write attacker-chosen files,
    // `--script` runs arbitrary NSE, `-iL` reads an arbitrary file — none of which the scope gate
    // inspects. `ports` is the only tunable, accepted ONLY if it is a pure port spec (digits, commas,
    // dashes); anything else (spaces, letters, an injected flag) is dropped, not passed through.
    build: (target, params) => {
      const args = ['-sV', '-T4'];
      const ports = str(params.ports);
      if (ports && /^[0-9,-]+$/.test(ports)) args.push('-p', ports);
      args.push(target);
      return args;
    },
  },
  nuclei: {
    targetParam: 'url',
    defaultTimeoutMs: 300_000,
    build: (target, params) => {
      const severity = str(params.severity) ?? 'medium,high,critical';
      const tags = str(params.tags);
      const args = ['-target', target, '-severity', severity, '-silent', '-jsonl'];
      if (tags) args.push('-tags', tags);
      return args;
    },
  },
  ffuf: {
    targetParam: 'url',
    defaultTimeoutMs: 120_000,
    build: (target, params) => {
      const wordlist = str(params.wordlist) ?? '/usr/share/wordlists/dirb/common.txt';
      const mc = str(params.mc) ?? '200,301,302,403';
      return ['-u', target, '-w', wordlist, '-mc', mc, '-o', '/dev/stdout', '-of', 'json', '-s'];
    },
  },
  sqlmap: {
    targetParam: 'url',
    defaultTimeoutMs: 300_000,
    // Keep level/risk low unless the mission receipt explicitly permits intrusive testing.
    build: (target, params) => {
      const level = str(params.level) ?? '1';
      const risk = str(params.risk) ?? '1';
      return ['-u', target, '--batch', `--level=${level}`, `--risk=${risk}`];
    },
  },
  gobuster: {
    targetParam: 'url',
    defaultTimeoutMs: 120_000,
    build: (target, params) => {
      const mode = str(params.mode) ?? 'dir';
      const wordlist = str(params.wordlist) ?? '/usr/share/wordlists/dirb/common.txt';
      return [mode, '-u', target, '-w', wordlist, '-q'];
    },
  },
  nikto: {
    targetParam: 'url',
    defaultTimeoutMs: 300_000,
    build: (target) => ['-h', target],
  },
  httpx: {
    targetParam: 'url',
    defaultTimeoutMs: 60_000,
    build: (target) => ['-u', target, '-status-code', '-title', '-tech-detect', '-json', '-silent'],
  },
  naabu: {
    targetParam: 'host',
    defaultTimeoutMs: 120_000,
    build: (target, params) => {
      const topPorts = str(params.top_ports) ?? '100';
      return ['-host', target, '-top-ports', topPorts, '-silent'];
    },
  },
  katana: {
    targetParam: 'url',
    defaultTimeoutMs: 120_000,
    build: (target) => ['-u', target, '-jsonl', '-silent'],
  },
  subfinder: {
    targetParam: 'domain',
    defaultTimeoutMs: 120_000,
    build: (target) => ['-d', target, '-silent'],
  },
  dalfox: {
    targetParam: 'url',
    defaultTimeoutMs: 180_000,
    build: (target) => ['url', target, '--format', 'json', '--silence'],
  },
  dig: {
    targetParam: 'domain',
    defaultTimeoutMs: 30_000,
    build: (target, params) => {
      const type = str(params.type);
      const args = [target];
      if (type) args.push(type);
      args.push('+short');
      return args;
    },
  },
  host: {
    targetParam: 'domain',
    defaultTimeoutMs: 30_000,
    build: (target) => [target],
  },
  whois: {
    targetParam: 'domain',
    defaultTimeoutMs: 30_000,
    build: (target) => [target],
  },
  curl: {
    targetParam: 'url',
    defaultTimeoutMs: 30_000,
    build: (target, params) => {
      const method = str(params.method) ?? 'GET';
      const args = ['-s', '-i', '-X', method];
      const data = str(params.data);
      if (data) {
        // A `-d`/`--data` value whose first char is `@` (read a local file) or `<` (read stdin) turns
        // curl into a local-file-disclosure / exfil primitive — `-d @/etc/passwd` POSTs that file's
        // contents. `--data-raw` sends the body verbatim and disables @/< interpretation entirely; the
        // explicit reject is belt-and-braces so a caller can never smuggle a file read past the gates.
        if (/^[@<]/.test(data)) {
          throw new Error(`curl: refusing a data value starting with '${data[0]}' (would read a local file/stdin).`);
        }
        args.push('--data-raw', data);
      }
      args.push(target);
      return args;
    },
  },

  // ── Source / supply-chain scanners (non-networked, operate on a PATH) ───────────────────────────
  // Without these, each falls through to DEFAULT_TEMPLATE and spawns `<binary> <target>` — which for
  // a subcommand-driven scanner is a broken invocation (e.g. `semgrep .` never runs a scan, and with
  // no path it is `semgrep ''`). Templates mirror the catalog `commandHint` and hardcode the
  // subcommand + machine-readable output flags; the only tunable is the scan path (see scanPath).
  semgrep: {
    targetParam: 'path',
    defaultTimeoutMs: 300_000,
    build: (target, params) => ['scan', '--config', 'auto', '--json', scanPath(target, params)],
  },
  gitleaks: {
    targetParam: 'path',
    defaultTimeoutMs: 180_000,
    build: (target, params) => ['detect', '--source', scanPath(target, params), '--report-format', 'json', '--redact', '--no-banner'],
  },
  trufflehog: {
    targetParam: 'path',
    defaultTimeoutMs: 300_000,
    build: (target, params) => ['filesystem', scanPath(target, params), '--json', '--no-update'],
  },
  trivy: {
    targetParam: 'path',
    defaultTimeoutMs: 300_000,
    build: (target, params) => ['fs', '--format', 'json', scanPath(target, params)],
  },
  syft: {
    targetParam: 'path',
    defaultTimeoutMs: 180_000,
    build: (target, params) => ['dir:' + scanPath(target, params), '-o', 'cyclonedx-json'],
  },
  grype: {
    targetParam: 'path',
    defaultTimeoutMs: 180_000,
    build: (target, params) => ['dir:' + scanPath(target, params), '-o', 'json'],
  },
  checkov: {
    targetParam: 'path',
    defaultTimeoutMs: 180_000,
    build: (target, params) => ['-d', scanPath(target, params), '-o', 'json'],
  },
};

/** Fallback for any mintable adapter without a bespoke template: pass the target as a positional arg. */
const DEFAULT_TEMPLATE: ArgTemplate = {
  targetParam: 'target',
  defaultTimeoutMs: 120_000,
  build: (target) => [target],
};

/** The parameter keys a target may arrive under, mirroring the Arsenal's SCOPE_TARGET_KEYS surface. */
const TARGET_PARAM_KEYS = ['url', 'target', 'host', 'hostname', 'domain', 'address', 'endpoint', 'base_url'];

function resolveTemplate(adapter: ToolAdapter): ArgTemplate {
  return ARG_TEMPLATES[adapter.binary] ?? ARG_TEMPLATES[adapter.id] ?? DEFAULT_TEMPLATE;
}

/**
 * Resolve the target string for an adapter call: the template's preferred param first, then the other
 * common target keys, then `context.target.address`. Returns undefined if none is present.
 */
function resolveTarget(template: ArgTemplate, context: ToolContext): string | undefined {
  const params = context.parameters || {};
  const preferred = str(params[template.targetParam]);
  if (preferred) return preferred;
  for (const k of TARGET_PARAM_KEYS) {
    const v = str(params[k]);
    if (v) return v;
  }
  return str(context.target?.address);
}

// =============================================================================
// FACTORY
// =============================================================================

/** True only for adapters that may be minted as callable tools (safe_command / receipt_required). */
export function isMintable(adapter: ToolAdapter): boolean {
  return adapter.execution === 'safe_command' || adapter.execution === 'receipt_required';
}

/**
 * Turn one catalogued adapter into a callable `CustomTool`.
 *
 * Returns `null` for `execution === 'catalog_only'` (metasploit, hydra) and `execution ===
 * 'import_only'` (bloodhound) — those are NEVER minted, so they cannot be reached through generic
 * command execution.
 */
export function adapterToCustomTool(adapter: ToolAdapter, deps: AdapterToolDeps): CustomTool | null {
  if (!isMintable(adapter)) return null; // catalog_only / import_only are never callable

  const template = resolveTemplate(adapter);

  const handler = async (context: ToolContext): Promise<ToolResult> => {
    // 1) Degrade (never throw) when the binary is absent — the model picks another tool.
    if (!(await deps.isToolAvailable(adapter.binary))) {
      return {
        success: false,
        error: `${adapter.name} (${adapter.binary}) is not installed. ${adapter.installHint}`,
      };
    }

    // 2) Resolve the target this call would hit.
    const target = resolveTarget(template, context);
    if (adapter.networked && !target) {
      return { success: false, error: `${adapter.name} requires a target (${template.targetParam}).` };
    }

    // 2b) Refuse an option-looking target: a value starting with '-' gets reparsed by the tool as a
    //     FLAG rather than a target (curl `-K`/`-o`, nikto/whois/host positional, the default
    //     positional template) — argument injection that slips past the scope gate, which only
    //     inspects hosts. Reject it at this single choke point, before any argv is built or spawned.
    if (target && /^-/.test(target)) {
      return {
        success: false,
        error: `${adapter.name}: refusing option-looking target '${target}' (leading '-' is not a valid host/URL).`,
      };
    }

    // 3) In-handler scope belt-and-braces: refuse an out-of-scope target BEFORE spawning anything.
    if (target && deps.scopeOk && !deps.scopeOk(target)) {
      return {
        success: false,
        error: `SCOPE DENIED: target '${target}' is not in the authorized scope — ${adapter.binary} refused before execution.`,
      };
    }

    // 4) Build argv from the per-adapter template and run the subprocess with a per-adapter timeout.
    //    A template may REFUSE a dangerous param (e.g. curl `-d @file` local-file read) by throwing —
    //    convert that into a clean failure result, never an unhandled rejection.
    let argv: string[];
    try {
      argv = template.build(target ?? '', context.parameters || {});
    } catch (err) {
      return { success: false, error: `${adapter.name}: ${err instanceof Error ? err.message : String(err)}` };
    }
    const result = await deps.runSubprocess(adapter.binary, argv, { timeout: template.defaultTimeoutMs });

    if (result.exitCode !== 0) {
      return {
        success: false,
        error: `${adapter.binary} exited ${result.exitCode}: ${result.stderr || result.stdout || 'no output'}`,
        output: result.stdout || undefined,
      };
    }

    return { success: true, output: result.stdout };
  };

  return {
    name: toolNameFor(adapter),
    description: `${adapter.name}: ${adapter.notes} (Kali+ adapter; ${adapter.execution}, risk=${adapter.risk})`,
    category: adapter.category,
    // Carry the catalog risk onto the tool so Arsenal.execute()'s approval gate can see it: an
    // intrusive/credential/dangerous adapter is inert until approved, and warns on the hottest calls.
    riskTier: adapter.risk,
    parameters: [
      {
        name: template.targetParam,
        type: 'string',
        description: `Target for ${adapter.name} (${adapter.evidenceKinds.join(', ') || 'evidence'}).`,
        required: adapter.networked,
      },
    ],
    handler,
  };
}

/** The stable tool-name a given adapter mints as (used for de-dup against already-registered tools). */
export function toolNameFor(adapter: ToolAdapter): string {
  return `${adapter.id.replace(/[^a-z0-9]+/gi, '_')}_tool`;
}

/**
 * Map a list of adapters to callable `CustomTool`s, skipping:
 *  - non-mintable adapters (catalog_only / import_only → dropped),
 *  - any adapter whose minted tool-name is already present in `alreadyRegistered` (so the bespoke
 *    hand-written EXTERNAL_TOOLS like nmap_scan / nuclei_scan win and we don't double-register).
 */
export function buildAdapterTools(
  adapters: ToolAdapter[],
  deps: AdapterToolDeps,
  alreadyRegistered: ReadonlySet<string> = new Set()
): CustomTool[] {
  const tools: CustomTool[] = [];
  for (const adapter of adapters) {
    const tool = adapterToCustomTool(adapter, deps);
    if (!tool) continue; // catalog_only / import_only
    if (alreadyRegistered.has(tool.name)) continue; // don't shadow an existing registration
    tools.push(tool);
  }
  return tools;
}
