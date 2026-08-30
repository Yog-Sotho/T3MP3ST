import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

const serverSource = readFileSync(join(process.cwd(), 'src/server.ts'), 'utf8');

function routeBlock(startMarker: string, endMarker: string): string {
  const start = serverSource.indexOf(startMarker);
  expect(start, `missing route marker ${startMarker}`).toBeGreaterThanOrEqual(0);
  const end = serverSource.indexOf(endMarker, start);
  expect(end, `missing end marker ${endMarker}`).toBeGreaterThan(start);
  return serverSource.slice(start, end);
}

describe('local API authorization hardening invariants', () => {
  it('/api/events does not grant wildcard CORS and rejects foreign browser origins before opening SSE', () => {
    const route = routeBlock("app.get('/api/events'", '// =============================================================================\n// API ENDPOINTS - HEALTH & STATUS');

    expect(route).not.toMatch(/Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/);
    expect(route).toMatch(/const\s+origin\s*=\s*_?req\.get\(['"]origin['"]\)/);
    expect(route).toMatch(/origin\s*&&\s*!isLoopbackOrigin\(origin\)/);
    expect(route).toMatch(/Access-Control-Allow-Origin['"]\]\s*=\s*origin/);
  });

  it('/api/tools/execute binds approval to the parsed command target, not a caller-supplied target override', () => {
    const route = routeBlock("app.post('/api/tools/execute'", "app.post('/api/tools/recon'");

    expect(route).not.toMatch(/body\.target\s*\|\|\s*inferCommandTarget\(parsed\)/);
    expect(route).toMatch(/resolveCommandExecutionTarget\(body, parsed\)/);
    expect(route).toMatch(/guardAction\(body,\s*['"]command_execution['"],\s*targetResolution\.target/);
  });

  it('Admiral live launch re-checks every General-produced execution target before mission bring-up', () => {
    const route = routeBlock("app.post('/api/admiral/launch'", '// =============================================================================\n// BOUNTY PLATFORM INTEGRATIONS');

    expect(route).toMatch(/ensureExecTargetsWithinApprovedTarget\(execConfig\.targets, brief\.target\)/);
    expect(route).toMatch(/outOfScopeTargets\.length/);
    expect(route.indexOf('ensureExecTargetsWithinApprovedTarget(execConfig.targets, brief.target)'))
      .toBeLessThan(route.indexOf('bringUpMissionFromPlan(execConfig, generalConfig)'));
  });

  it('parseCommand function contains flag-injection and local-file-read hardening blocks', () => {
    const block = routeBlock('function parseCommand(', 'function inferCommandTarget(');

    expect(block).toMatch(/dangerousFlags/);
    expect(block).toMatch(/bin === 'curl'/);
    expect(block).toMatch(/\/\^\[@<\]\/\.test/);
    expect(block).toMatch(/gdb:\s*\/\^\(-ex\|-iex\|-x\|-ix\|--command\|--eval-command\|--init-command\|--init-eval-command\)\$\//);
    expect(block).toMatch(/r2:\s*\/\^\(-c\|-i\)\$\//);
    expect(block).toMatch(/file:\s*\/\^\(-f\|--files-from\)\$\//);
    expect(block).toMatch(/sqlmap:\s*\/\^\(--file-read\|--file-write\|--file-dest\|--os-cmd\|--os-shell\|--os-pwn\|--sql-shell\|--sql-file\|--config\)\$\//);
    expect(block).toMatch(/nikto:\s*\/\^\(-config\|-mutate-options\)\$\//);
    expect(block).toMatch(/ffuf:\s*\/\^\(-o\|-of\|-od\|-w\|-config\|-request\|-request-proto\|-input-cmd\)\$\//);
    expect(block).toMatch(/gobuster:\s*\/\^\(-o\|-p\|-w\|-c\|--config\|-s\)\$\//);
    expect(block).toMatch(/nuclei:\s*\/\^\(-o\|--output\|-t\|--templates\|-tfile\|-config\|--report-config|-code\|-profile\|-e\|--exclude-templates\|-f\|--file\)\$\//);
    expect(block).toMatch(/feroxbuster:\s*\/\^\(-o\|--output\|-w\|--wordlist\|-c\|--config\|-D\|--dont-scan\)\$\//);
    expect(block).toMatch(/httpx:\s*\/\^\(-o\|--output\|-oa\|-oD\|--output-dir\|-c\|--config\|-r\|--resolvers\|-l\|--list\|-sr\|-srd\)\$\//);
    expect(block).toMatch(/subfinder:\s*\/\^\(-o\|--output\|-oD\|--output-dir\|-dL\|--list\|-c\|--config\|-r\|--resolvers\)\$\//);
    expect(block).toMatch(/katana:\s*\/\^\(-o\|--output\|-oD\|--output-dir\|-c\|--config\|-r\|--resolvers\|-u\|--list\|-sr\|-srd\)\$\//);
    expect(block).toMatch(/naabu:\s*\/\^\(-o\|--output\|-oD\|--output-dir\|-c\|--config\|-r\|--resolvers\|-l\|--list\)\$\//);
  });

  it('/api/tools/recon blocks option-looking targets and restricts internal/loopback IPs', () => {
    const route = routeBlock("app.post('/api/tools/recon'", "app.get('/api/tools'");

    expect(route).toMatch(/targetHost\.startsWith\(['"]-['"]\)/);
    expect(route).toMatch(/isRestrictedInternalIP\(targetHost\)/);
  });
});
