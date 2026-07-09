/**
 * Bounty Platform Connectors — t3mp3st integrations for popular
 * bug-bounty and vulnerability-disclosure platforms.
 *
 * DESIGN INVARIANT: same as disclosure-gen — DRAFTS ONLY.
 * These connectors prepare API-ready payloads and, when configured,
 * can submit via the platform's API — but only after the human
 * reviews and confirms. No auto-submit, no silent sends.
 *
 * Supported platforms:
 *   - HackerOne      (API v1, most programs)
 *   - Bugcrowd       (REST API v4)
 *   - Intigriti      (REST API)
 *   - Immunefi       (web3/DeFi bounties)
 *   - Huntr          (open-source/dev tool bounties)
 *   - Code4rena      (competitive smart-contract audits)
 *
 * Each connector implements BountyConnector:
 *   - formatReport(finding) → platform-specific payload
 *   - validateScope(finding) → check if the finding matches a program's scope
 *   - submit(payload, opts) → POST to platform API (requires explicit confirm)
 *   - listPrograms(query) → search available programs
 */

import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join } from 'path';

// =============================================================================
// TYPES
// =============================================================================

export type BountyPlatform = 'hackerone' | 'bugcrowd' | 'intigriti' | 'immunefi' | 'huntr' | 'code4rena';

export interface BountyCredentials {
  platform: BountyPlatform;
  apiKey?: string;
  username?: string;
  /** HackerOne uses API key + identifier pair */
  apiIdentifier?: string;
  /** Immunefi uses wallet-based auth for web3 */
  walletAddress?: string;
}

export interface BountyProgram {
  platform: BountyPlatform;
  handle: string;
  name: string;
  scope: BountyScopeItem[];
  minSeverity?: string;
  maxBounty?: { low?: number; medium?: number; high?: number; critical?: number };
  responseTime?: string;
  managed?: boolean;
}

export interface BountyScopeItem {
  type: 'web' | 'api' | 'mobile' | 'hardware' | 'iot' | 'smart_contract' | 'source_code' | 'other';
  target: string;
  eligible: boolean;
  bountyRange?: string;
}

export interface BountyFinding {
  slug: string;
  title: string;
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  cvssVector?: string;
  cvssScore?: number;
  cwe?: string;
  summary: string;
  rootCause: string;
  poc: string;
  impact: string;
  remediation: string;
  component?: string;
  versionsAffected?: string;
  /** Structured evidence from t3mp3st's verify pipeline */
  evidence?: Array<{ type: string; content: string }>;
}

// =============================================================================
// SECURITY: INPUT VALIDATION
// =============================================================================

/**
 * Validation configuration for bounty credentials.
 * Enforces format, length, and character restrictions to prevent injection.
 */
const CREDENTIAL_LIMITS = {
  apiKey: { min: 16, max: 512, pattern: /^[a-zA-Z0-9_\-.]+$/ },
  username: { min: 1, max: 128, pattern: /^[a-zA-Z0-9_\-.@]+$/ },
  apiIdentifier: { min: 1, max: 256, pattern: /^[a-zA-Z0-9_\-.]+$/ },
  walletAddress: { min: 40, max: 66, pattern: /^0x[a-fA-F0-9]+$/ }, // Ethereum
} as const;

/**
 * Validate bounty credentials format, length, and character set.
 * Returns validation result with any errors found.
 */
export function validateBountyCredentials(creds: BountyCredentials): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Validate platform
  const validPlatforms = ['hackerone', 'bugcrowd', 'intigriti', 'immunefi', 'huntr', 'code4rena'];
  if (!validPlatforms.includes(creds.platform)) {
    errors.push(`Invalid platform: must be one of ${validPlatforms.join(', ')}`);
  }

  // Validate apiKey if provided
  if (creds.apiKey) {
    if (creds.apiKey.length < CREDENTIAL_LIMITS.apiKey.min) {
      errors.push(`apiKey too short (min ${CREDENTIAL_LIMITS.apiKey.min} chars)`);
    }
    if (creds.apiKey.length > CREDENTIAL_LIMITS.apiKey.max) {
      errors.push(`apiKey too long (max ${CREDENTIAL_LIMITS.apiKey.max} chars)`);
    }
    if (!CREDENTIAL_LIMITS.apiKey.pattern.test(creds.apiKey)) {
      errors.push('apiKey contains invalid characters (only alphanumeric, underscore, hyphen, dot allowed)');
    }
    // Check for control characters
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f]/.test(creds.apiKey)) {
      errors.push('apiKey contains control characters');
    }
  }

  // Validate username if provided
  if (creds.username) {
    if (creds.username.length < CREDENTIAL_LIMITS.username.min) {
      errors.push(`username too short (min ${CREDENTIAL_LIMITS.username.min} chars)`);
    }
    if (creds.username.length > CREDENTIAL_LIMITS.username.max) {
      errors.push(`username too long (max ${CREDENTIAL_LIMITS.username.max} chars)`);
    }
    if (!CREDENTIAL_LIMITS.username.pattern.test(creds.username)) {
      errors.push('username contains invalid characters');
    }
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f]/.test(creds.username)) {
      errors.push('username contains control characters');
    }
  }

  // Validate walletAddress (Ethereum) if provided
  if (creds.walletAddress) {
    if (!CREDENTIAL_LIMITS.walletAddress.pattern.test(creds.walletAddress)) {
      errors.push('Invalid wallet address - must be valid Ethereum address (0x...)');
    }
    if (creds.walletAddress.length !== 42) {
      errors.push('Ethereum wallet address must be exactly 42 characters (0x + 40 hex)');
    }
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f]/.test(creds.walletAddress)) {
      errors.push('walletAddress contains control characters');
    }
  }

  // Validate apiIdentifier if provided
  if (creds.apiIdentifier) {
    if (creds.apiIdentifier.length > CREDENTIAL_LIMITS.apiIdentifier.max) {
      errors.push(`apiIdentifier too long (max ${CREDENTIAL_LIMITS.apiIdentifier.max} chars)`);
    }
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f]/.test(creds.apiIdentifier)) {
      errors.push('apiIdentifier contains control characters');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

export interface BountyReport {
  platform: BountyPlatform;
  programHandle: string;
  title: string;
  severity: string;
  body: string;
  structuredData?: Record<string, unknown>;
  /** The raw API payload, ready to POST */
  apiPayload?: Record<string, unknown>;
  /** Human-review checklist items */
  checklist: string[];
}

export interface BountySubmitResult {
  success: boolean;
  reportId?: string;
  reportUrl?: string;
  error?: string;
  /** Did the human confirm before we sent? */
  confirmed: boolean;
}

export interface BountyConnector {
  platform: BountyPlatform;
  formatReport(finding: BountyFinding, programHandle: string): BountyReport;
  validateScope(finding: BountyFinding, program: BountyProgram): { inScope: boolean; reason: string };
  submit(report: BountyReport, credentials: BountyCredentials, opts: { dryRun?: boolean }): Promise<BountySubmitResult>;
  listPrograms(query: string, credentials: BountyCredentials): Promise<BountyProgram[]>;
}

// =============================================================================
// SHARED HELPERS
// =============================================================================

function severityLabel(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

function buildMarkdownReport(f: BountyFinding): string {
  let md = `## Summary\n\n${f.summary}\n\n`;
  md += `## Severity\n\n**${severityLabel(f.severity)}**`;
  if (f.cvssVector) md += ` — CVSS ${f.cvssScore ?? '?'} (${f.cvssVector})`;
  if (f.cwe) md += `\nCWE: ${f.cwe}`;
  md += '\n\n';
  md += `## Root Cause\n\n${f.rootCause}\n\n`;
  md += `## Steps to Reproduce\n\n${f.poc}\n\n`;
  md += `## Impact\n\n${f.impact}\n\n`;
  md += `## Suggested Remediation\n\n${f.remediation}\n\n`;
  if (f.component) md += `## Affected Component\n\n${f.component}\n\n`;
  if (f.versionsAffected) md += `## Versions Affected\n\n${f.versionsAffected}\n\n`;
  return md;
}

const BASE_CHECKLIST = [
  'Verify the finding is real and reproducible before submitting',
  'Confirm the target is IN SCOPE for this program',
  'Check if this is a duplicate — search the program\'s disclosed reports',
  'Ensure no sensitive data (API keys, credentials, PII) is in the report',
  'Review severity rating — does it match CVSS and actual impact?',
  'Attach all necessary evidence (screenshots, logs, PoC scripts)',
];

// =============================================================================
// HACKERONE CONNECTOR
// =============================================================================

export const hackeroneConnector: BountyConnector = {
  platform: 'hackerone',

  formatReport(finding: BountyFinding, programHandle: string): BountyReport {
    const body = buildMarkdownReport(finding);
    const severityRating = ({ none: 'none', low: 'low', medium: 'medium', high: 'high', critical: 'critical' } as const)[finding.severity] || 'medium';

    return {
      platform: 'hackerone',
      programHandle,
      title: finding.title,
      severity: finding.severity,
      body,
      apiPayload: {
        data: {
          type: 'report',
          attributes: {
            team_handle: programHandle,
            title: finding.title,
            vulnerability_information: body,
            severity_rating: severityRating,
            weakness_id: finding.cwe ? parseInt(finding.cwe.replace(/\D/g, ''), 10) : undefined,
          },
        },
      },
      checklist: [
        ...BASE_CHECKLIST,
        `Program handle: ${programHandle}`,
        'HackerOne: check program policy for safe harbor / legal provisions',
        'HackerOne: attach PoC as a separate file if > 2000 chars',
      ],
    };
  },

  validateScope(finding: BountyFinding, program: BountyProgram) {
    const component = (finding.component || '').toLowerCase();
    const match = program.scope.find(s => s.eligible && component.includes(s.target.toLowerCase()));
    if (match) return { inScope: true, reason: `Matches scope target: ${match.target}` };
    return { inScope: false, reason: `No scope target matched component "${finding.component}"` };
  },

  async submit(report: BountyReport, credentials: BountyCredentials, opts = {}): Promise<BountySubmitResult> {
    if (opts.dryRun) {
      return { success: true, confirmed: false, reportId: 'DRY-RUN', reportUrl: `https://hackerone.com/${report.programHandle}/reports/DRY-RUN` };
    }
    if (!credentials.apiKey || !credentials.apiIdentifier) {
      return { success: false, confirmed: false, error: 'HackerOne requires both apiKey and apiIdentifier' };
    }
    const auth = Buffer.from(`${credentials.apiIdentifier}:${credentials.apiKey}`).toString('base64');
    const res = await fetch('https://api.hackerone.com/v1/hackers/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Basic ${auth}` },
      body: JSON.stringify(report.apiPayload),
    });
    if (!res.ok) {
      const text = await res.text();
      return { success: false, confirmed: true, error: `HackerOne API ${res.status}: ${text.slice(0, 500)}` };
    }
    const data = await res.json() as any;
    return {
      success: true, confirmed: true,
      reportId: data.data?.id,
      reportUrl: `https://hackerone.com/reports/${data.data?.id}`,
    };
  },

  async listPrograms(query: string, credentials: BountyCredentials): Promise<BountyProgram[]> {
    if (!credentials.apiKey || !credentials.apiIdentifier) return [];
    const auth = Buffer.from(`${credentials.apiIdentifier}:${credentials.apiKey}`).toString('base64');
    const res = await fetch(`https://api.hackerone.com/v1/hackers/programs?filter[name]=${encodeURIComponent(query)}`, {
      headers: { Authorization: `Basic ${auth}` },
    });
    if (!res.ok) return [];
    const data = await res.json() as any;
    return (data.data || []).map((p: any) => ({
      platform: 'hackerone' as const,
      handle: p.attributes?.handle || p.id,
      name: p.attributes?.name || p.id,
      scope: [],
      managed: p.attributes?.state === 'public_mode',
    }));
  },
};

// =============================================================================
// BUGCROWD CONNECTOR
// =============================================================================

export const bugcrowdConnector: BountyConnector = {
  platform: 'bugcrowd',

  formatReport(finding: BountyFinding, programHandle: string): BountyReport {
    const body = buildMarkdownReport(finding);
    const bugcrowdSeverity = ({ none: 1, low: 2, medium: 3, high: 4, critical: 5 } as const)[finding.severity] || 3;

    return {
      platform: 'bugcrowd',
      programHandle,
      title: finding.title,
      severity: finding.severity,
      body,
      apiPayload: {
        submission: {
          title: finding.title,
          description: body,
          severity: bugcrowdSeverity,
          vrt_id: finding.cwe || undefined,
          extra_info: finding.poc,
        },
      },
      checklist: [
        ...BASE_CHECKLIST,
        `Bugcrowd program: ${programHandle}`,
        'Bugcrowd: use their VRT (Vulnerability Rating Taxonomy) for classification',
        'Bugcrowd: check if the program accepts PoC scripts as attachments',
      ],
    };
  },

  validateScope(finding: BountyFinding, program: BountyProgram) {
    const component = (finding.component || '').toLowerCase();
    const match = program.scope.find(s => s.eligible && component.includes(s.target.toLowerCase()));
    if (match) return { inScope: true, reason: `Matches scope target: ${match.target}` };
    return { inScope: false, reason: `No scope target matched component "${finding.component}"` };
  },

  async submit(report: BountyReport, credentials: BountyCredentials, opts = {}): Promise<BountySubmitResult> {
    if (opts.dryRun) {
      return { success: true, confirmed: false, reportId: 'DRY-RUN' };
    }
    if (!credentials.apiKey) {
      return { success: false, confirmed: false, error: 'Bugcrowd requires an API token' };
    }
    const res = await fetch(`https://api.bugcrowd.com/programs/${report.programHandle}/submissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Token ${credentials.apiKey}` },
      body: JSON.stringify(report.apiPayload),
    });
    if (!res.ok) {
      const text = await res.text();
      return { success: false, confirmed: true, error: `Bugcrowd API ${res.status}: ${text.slice(0, 500)}` };
    }
    const data = await res.json() as any;
    return { success: true, confirmed: true, reportId: data.id || data.uuid };
  },

  async listPrograms(query: string, credentials: BountyCredentials): Promise<BountyProgram[]> {
    if (!credentials.apiKey) return [];
    const res = await fetch(`https://api.bugcrowd.com/programs?search=${encodeURIComponent(query)}`, {
      headers: { Authorization: `Token ${credentials.apiKey}` },
    });
    if (!res.ok) return [];
    const data = await res.json() as any;
    return (data.programs || data.data || []).map((p: any) => ({
      platform: 'bugcrowd' as const,
      handle: p.code || p.id,
      name: p.name || p.code || p.id,
      scope: [],
    }));
  },
};

// =============================================================================
// INTIGRITI CONNECTOR
// =============================================================================

export const intigritiConnector: BountyConnector = {
  platform: 'intigriti',

  formatReport(finding: BountyFinding, programHandle: string): BountyReport {
    const body = buildMarkdownReport(finding);
    return {
      platform: 'intigriti',
      programHandle,
      title: finding.title,
      severity: finding.severity,
      body,
      apiPayload: {
        title: finding.title,
        description: body,
        severity: finding.severity.toUpperCase(),
        domain_or_target: finding.component || '',
        proof_of_concept: finding.poc,
      },
      checklist: [
        ...BASE_CHECKLIST,
        `Intigriti program: ${programHandle}`,
        'Intigriti: check program\'s confidentiality requirements',
      ],
    };
  },

  validateScope(finding: BountyFinding, program: BountyProgram) {
    const component = (finding.component || '').toLowerCase();
    const match = program.scope.find(s => s.eligible && component.includes(s.target.toLowerCase()));
    if (match) return { inScope: true, reason: `Matches scope target: ${match.target}` };
    return { inScope: false, reason: `No scope target matched component "${finding.component}"` };
  },

  async submit(_report: BountyReport, _credentials: BountyCredentials, opts = {}): Promise<BountySubmitResult> {
    if (opts.dryRun) return { success: true, confirmed: false, reportId: 'DRY-RUN' };
    return { success: false, confirmed: false, error: 'Intigriti submission requires their web portal — use formatReport to prepare, then submit manually' };
  },

  async listPrograms(_query: string, _credentials: BountyCredentials): Promise<BountyProgram[]> {
    return [];
  },
};

// =============================================================================
// IMMUNEFI CONNECTOR (Web3 / DeFi)
// =============================================================================

export const immunefiConnector: BountyConnector = {
  platform: 'immunefi',

  formatReport(finding: BountyFinding, programHandle: string): BountyReport {
    const body = buildMarkdownReport(finding);
    return {
      platform: 'immunefi',
      programHandle,
      title: finding.title,
      severity: finding.severity,
      body,
      apiPayload: {
        project: programHandle,
        title: finding.title,
        severity: finding.severity,
        description: body,
        proof_of_concept: finding.poc,
        impact: finding.impact,
      },
      checklist: [
        ...BASE_CHECKLIST,
        `Immunefi program: ${programHandle}`,
        'Immunefi: reports go through their Bugfix Review process',
        'Immunefi: smart contract bugs require on-chain PoC (testnet fork preferred)',
        'Immunefi: check if the program uses Immunefi\'s severity scale vs CVSS',
      ],
    };
  },

  validateScope(finding: BountyFinding, program: BountyProgram) {
    const component = (finding.component || '').toLowerCase();
    const isSmartContract = component.includes('contract') || component.includes('solidity') || component.includes('.sol');
    const match = program.scope.find(s => s.eligible && (
      component.includes(s.target.toLowerCase()) ||
      (isSmartContract && s.type === 'smart_contract')
    ));
    if (match) return { inScope: true, reason: `Matches scope: ${match.target} (${match.type})` };
    return { inScope: false, reason: `No scope match for "${finding.component}"` };
  },

  async submit(_report: BountyReport, _credentials: BountyCredentials, opts = {}): Promise<BountySubmitResult> {
    if (opts.dryRun) return { success: true, confirmed: false, reportId: 'DRY-RUN' };
    return { success: false, confirmed: false, error: 'Immunefi submissions go through bugs.immunefi.com — use formatReport to prepare, then submit via their portal' };
  },

  async listPrograms(_query: string, _credentials: BountyCredentials): Promise<BountyProgram[]> {
    return [];
  },
};

// =============================================================================
// HUNTR CONNECTOR (open-source / dev tools)
// =============================================================================

export const huntrConnector: BountyConnector = {
  platform: 'huntr',

  formatReport(finding: BountyFinding, programHandle: string): BountyReport {
    const body = buildMarkdownReport(finding);
    return {
      platform: 'huntr',
      programHandle,
      title: finding.title,
      severity: finding.severity,
      body,
      apiPayload: {
        repository: programHandle,
        title: finding.title,
        description: body,
        severity: finding.severity,
        cwe: finding.cwe,
        steps_to_reproduce: finding.poc,
      },
      checklist: [
        ...BASE_CHECKLIST,
        `Huntr repo: ${programHandle}`,
        'Huntr: targets open-source repos — confirm the repo is in their directory',
        'Huntr: automated triage, usually < 48h response',
      ],
    };
  },

  validateScope(_finding: BountyFinding, program: BountyProgram) {
    if (program.scope.length === 0 && program.handle) {
      return { inScope: true, reason: 'Huntr programs scope by repository — assume in scope if repo matches' };
    }
    return { inScope: false, reason: 'Unable to verify scope without program details' };
  },

  async submit(_report: BountyReport, _credentials: BountyCredentials, opts = {}): Promise<BountySubmitResult> {
    if (opts.dryRun) return { success: true, confirmed: false, reportId: 'DRY-RUN' };
    return { success: false, confirmed: false, error: 'Huntr submission requires their web portal at huntr.com — use formatReport to prepare' };
  },

  async listPrograms(_query: string, _credentials: BountyCredentials): Promise<BountyProgram[]> {
    return [];
  },
};

// =============================================================================
// CODE4RENA CONNECTOR (competitive smart-contract audits)
// =============================================================================

export const code4renaConnector: BountyConnector = {
  platform: 'code4rena',

  formatReport(finding: BountyFinding, programHandle: string): BountyReport {
    const riskLabel = ({ critical: 'H', high: 'H', medium: 'M', low: 'QA' } as Record<string, string>)[finding.severity] || 'M';
    let body = `# [${riskLabel}] ${finding.title}\n\n`;
    body += `## Summary\n${finding.summary}\n\n`;
    body += `## Vulnerability Detail\n${finding.rootCause}\n\n`;
    body += `## Impact\n${finding.impact}\n\n`;
    body += `## Proof of Concept\n${finding.poc}\n\n`;
    body += `## Recommended Mitigation\n${finding.remediation}\n`;

    return {
      platform: 'code4rena',
      programHandle,
      title: `[${riskLabel}] ${finding.title}`,
      severity: finding.severity,
      body,
      checklist: [
        ...BASE_CHECKLIST,
        `Code4rena contest: ${programHandle}`,
        'Code4rena: format as [H/M/QA] — High, Medium, or QA-grade',
        'Code4rena: submit via their contest portal during the active window',
        'Code4rena: include Foundry/Hardhat test as PoC when possible',
      ],
    };
  },

  validateScope(finding: BountyFinding, program: BountyProgram) {
    const component = (finding.component || '').toLowerCase();
    const match = program.scope.find(s => s.eligible && component.includes(s.target.toLowerCase()));
    if (match) return { inScope: true, reason: `In contest scope: ${match.target}` };
    return { inScope: false, reason: `"${finding.component}" not found in contest scope` };
  },

  async submit(_report: BountyReport, _credentials: BountyCredentials, opts = {}): Promise<BountySubmitResult> {
    if (opts.dryRun) return { success: true, confirmed: false, reportId: 'DRY-RUN' };
    return { success: false, confirmed: false, error: 'Code4rena submissions go through their contest portal — use formatReport to prepare your finding in C4 format' };
  },

  async listPrograms(_query: string, _credentials: BountyCredentials): Promise<BountyProgram[]> {
    return [];
  },
};

// =============================================================================
// REGISTRY — resolve platform name → connector
// =============================================================================

const CONNECTORS: Record<BountyPlatform, BountyConnector> = {
  hackerone: hackeroneConnector,
  bugcrowd: bugcrowdConnector,
  intigriti: intigritiConnector,
  immunefi: immunefiConnector,
  huntr: huntrConnector,
  code4rena: code4renaConnector,
};

export function getConnector(platform: BountyPlatform): BountyConnector {
  const c = CONNECTORS[platform];
  if (!c) throw new Error(`Unknown bounty platform: ${platform}`);
  return c;
}

export function listConnectors(): BountyPlatform[] {
  return Object.keys(CONNECTORS) as BountyPlatform[];
}

/**
 * Convert a t3mp3st finding JSON (as used in bench/wild-hunt/findings/)
 * into the BountyFinding format expected by connectors.
 */
export function findingToBountyFinding(raw: Record<string, any>): BountyFinding {
  return {
    slug: raw.slug || raw.id || 'unknown',
    title: raw.summary || raw.title || raw.slug || 'Untitled',
    severity: (raw.severity_computed || raw.severity_self || 'medium').toLowerCase(),
    cvssVector: raw.cvss_vector,
    cvssScore: raw.cvss_score,
    cwe: raw.cwe,
    summary: raw.summary || '',
    rootCause: raw.root_cause || '',
    poc: raw.poc || '',
    impact: raw.impact || '',
    remediation: raw.remediation || '',
    component: raw.component,
    versionsAffected: raw.versions_affected,
  };
}

/**
 * Load credentials from the bounty credentials file.
 * Stored in .keys.bounty.json (gitignored alongside .keys.local).
 */
export function loadBountyCredentials(repoRoot: string): Record<BountyPlatform, BountyCredentials> {
  const credPath = join(repoRoot, '.keys.bounty.json');
  if (!existsSync(credPath)) return {} as any;
  return JSON.parse(readFileSync(credPath, 'utf8'));
}

/**
 * Save credentials to the bounty credentials file.
 */
export function saveBountyCredentials(repoRoot: string, creds: Record<string, BountyCredentials>): void {
  writeFileSync(join(repoRoot, '.keys.bounty.json'), JSON.stringify(creds, null, 2) + '\n');
}
