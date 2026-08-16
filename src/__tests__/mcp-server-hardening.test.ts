import { describe, expect, it } from 'vitest';
import { handleToolCall } from '../mcp-server.js';

describe('MCP server security_recon tool hardening', () => {
  it('blocks option-looking targets (flag injection)', async () => {
    const rawResult = await handleToolCall('security_recon', { target: '-iLpasswd' });
    const res = JSON.parse(rawResult);
    expect(res.error).toMatch(/option-looking target/);
  });

  it('blocks SSRF targets (localhost / loopback)', async () => {
    const targets = [
      'localhost',
      '127.0.0.1',
      '127.0.0.2',
      '0.0.0.0',
      '::1',
      '::ffff:127.0.0.1',
      '2130706433', // 127.0.0.1 in decimal
      '0x7f000001', // 127.0.0.1 in hex
      '0177.0.0.1',  // 127.0.0.1 in octal
    ];

    for (const target of targets) {
      const rawResult = await handleToolCall('security_recon', { target });
      const res = JSON.parse(rawResult);
      expect(res.error, `Expected target ${target} to be blocked for SSRF`).toMatch(/SSRF DENIED/);
    }
  });

  it('blocks private / link-local addresses', async () => {
    const targets = [
      '10.0.0.1',
      '192.168.1.1',
      '172.16.0.1',
      '169.254.169.254', // AWS metadata
      'fc00::1',
      'fe80::1',
    ];

    for (const target of targets) {
      const rawResult = await handleToolCall('security_recon', { target });
      const res = JSON.parse(rawResult);
      expect(res.error, `Expected target ${target} to be blocked for SSRF`).toMatch(/SSRF DENIED/);
    }
  });
});
