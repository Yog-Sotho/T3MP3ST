import { describe, it, expect } from 'vitest';
import { validateBountyCredentials, type BountyCredentials } from '../integrations/bounty.js';
import { isRestrictedInternalIP } from '../arsenal/adapter-tools.js';

// =============================================================================
// validateBountyCredentials
// =============================================================================

describe('validateBountyCredentials', () => {
  function creds(overrides: Partial<BountyCredentials> = {}): BountyCredentials {
    return { platform: 'hackerone', ...overrides };
  }

  describe('platform validation', () => {
    it('accepts all supported platforms', () => {
      const platforms = ['hackerone', 'bugcrowd', 'intigriti', 'immunefi', 'huntr', 'code4rena'] as const;
      for (const platform of platforms) {
        expect(validateBountyCredentials({ platform }).valid).toBe(true);
      }
    });

    it('rejects an unknown platform', () => {
      const result = validateBountyCredentials({ platform: 'evil' as any });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('Invalid platform'))).toBe(true);
    });
  });

  describe('apiKey validation', () => {
    it('accepts a valid apiKey', () => {
      expect(validateBountyCredentials(creds({ apiKey: 'abc123-abc123-abc123' })).valid).toBe(true);
    });

    it('rejects apiKey that is too short', () => {
      const result = validateBountyCredentials(creds({ apiKey: 'short' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('too short'))).toBe(true);
    });

    it('rejects apiKey that is too long', () => {
      const result = validateBountyCredentials(creds({ apiKey: 'a'.repeat(513) }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('too long'))).toBe(true);
    });

    it('rejects apiKey with invalid characters', () => {
      const result = validateBountyCredentials(creds({ apiKey: 'valid-key!injection<script>' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('invalid characters'))).toBe(true);
    });

    it('rejects apiKey containing a newline (control character)', () => {
      const result = validateBountyCredentials(creds({ apiKey: 'validkey12345678\ninjected' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('control characters'))).toBe(true);
    });

    it('rejects apiKey containing a null byte', () => {
      const result = validateBountyCredentials(creds({ apiKey: 'validkey12345678\x00poison' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('control characters'))).toBe(true);
    });

    it('accepts apiKey with dots and hyphens', () => {
      expect(validateBountyCredentials(creds({ apiKey: 'my-key.token_v2-0000000000' })).valid).toBe(true);
    });
  });

  describe('username validation', () => {
    it('accepts a valid username', () => {
      expect(validateBountyCredentials(creds({ username: 'hunter@example.com' })).valid).toBe(true);
    });

    it('rejects username with control characters', () => {
      const result = validateBountyCredentials(creds({ username: 'user\rname' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('control characters'))).toBe(true);
    });

    it('rejects username with shell metacharacters', () => {
      const result = validateBountyCredentials(creds({ username: 'user;rm -rf /' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('invalid characters'))).toBe(true);
    });

    it('rejects username exceeding max length', () => {
      const result = validateBountyCredentials(creds({ username: 'u'.repeat(129) }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('too long'))).toBe(true);
    });
  });

  describe('walletAddress validation', () => {
    it('accepts a valid Ethereum address', () => {
      expect(validateBountyCredentials(creds({ walletAddress: '0xAbCd1234567890AbCd1234567890AbCd12345678' })).valid).toBe(true);
    });

    it('rejects address without 0x prefix', () => {
      const result = validateBountyCredentials(creds({ walletAddress: 'AbCd1234567890AbCd1234567890AbCd12345678Ab' }));
      expect(result.valid).toBe(false);
    });

    it('rejects address of wrong length', () => {
      const result = validateBountyCredentials(creds({ walletAddress: '0xdeadbeef' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('42 characters'))).toBe(true);
    });

    it('rejects address with control characters', () => {
      const addr = '0x' + 'a'.repeat(38) + '\n' + 'b';
      const result = validateBountyCredentials(creds({ walletAddress: addr }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('control characters'))).toBe(true);
    });
  });

  describe('apiIdentifier validation', () => {
    it('accepts a valid apiIdentifier', () => {
      expect(validateBountyCredentials(creds({ apiIdentifier: 'user-at-hackerone' })).valid).toBe(true);
    });

    it('rejects apiIdentifier exceeding max length', () => {
      const result = validateBountyCredentials(creds({ apiIdentifier: 'x'.repeat(257) }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('too long'))).toBe(true);
    });

    it('rejects apiIdentifier with control characters', () => {
      const result = validateBountyCredentials(creds({ apiIdentifier: 'legit\x01poison' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('control characters'))).toBe(true);
    });
  });

  describe('multi-field', () => {
    it('accumulates multiple errors', () => {
      const result = validateBountyCredentials({
        platform: 'unknown' as any,
        apiKey: 'short',
        username: 'u'.repeat(200),
      });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThanOrEqual(3);
    });

    it('passes with no optional fields provided', () => {
      expect(validateBountyCredentials({ platform: 'bugcrowd' }).valid).toBe(true);
    });
  });
});

// =============================================================================
// isRestrictedInternalIP
// =============================================================================

describe('isRestrictedInternalIP', () => {
  describe('loopback addresses', () => {
    it('blocks localhost', () => expect(isRestrictedInternalIP('localhost')).toBe(true));
    it('blocks 127.0.0.1', () => expect(isRestrictedInternalIP('127.0.0.1')).toBe(true));
    it('blocks the full 127.0.0.0/8 range', () => expect(isRestrictedInternalIP('127.99.0.1')).toBe(true));
    it('blocks ::1', () => expect(isRestrictedInternalIP('::1')).toBe(true));
    it('blocks [::1]', () => expect(isRestrictedInternalIP('[::1]')).toBe(true));
  });

  describe('RFC 1918 private ranges', () => {
    it('blocks 10.0.0.1', () => expect(isRestrictedInternalIP('10.0.0.1')).toBe(true));
    it('blocks 10.255.255.255', () => expect(isRestrictedInternalIP('10.255.255.255')).toBe(true));
    it('blocks 192.168.1.1', () => expect(isRestrictedInternalIP('192.168.1.1')).toBe(true));
    it('blocks 172.16.0.1', () => expect(isRestrictedInternalIP('172.16.0.1')).toBe(true));
    it('blocks 172.31.255.255', () => expect(isRestrictedInternalIP('172.31.255.255')).toBe(true));
    it('does NOT block 172.15.0.1 (outside range)', () => expect(isRestrictedInternalIP('172.15.0.1')).toBe(false));
    it('does NOT block 172.32.0.1 (outside range)', () => expect(isRestrictedInternalIP('172.32.0.1')).toBe(false));
  });

  describe('link-local and metadata', () => {
    it('blocks AWS metadata endpoint 169.254.169.254', () => expect(isRestrictedInternalIP('169.254.169.254')).toBe(true));
    it('blocks APIPA 169.254.0.1', () => expect(isRestrictedInternalIP('169.254.0.1')).toBe(true));
  });

  describe('IPv6 private ranges', () => {
    it('blocks fc00:: unique local', () => expect(isRestrictedInternalIP('fc00::1')).toBe(true));
    it('blocks fd00:: unique local', () => expect(isRestrictedInternalIP('fd00::1')).toBe(true));
    it('blocks fe80:: link-local', () => expect(isRestrictedInternalIP('fe80::1')).toBe(true));
    it('is case-insensitive for IPv6', () => expect(isRestrictedInternalIP('FE80::1')).toBe(true));
  });

  describe('public addresses (should not block)', () => {
    it('allows 8.8.8.8', () => expect(isRestrictedInternalIP('8.8.8.8')).toBe(false));
    it('allows 1.1.1.1', () => expect(isRestrictedInternalIP('1.1.1.1')).toBe(false));
    it('allows example.com', () => expect(isRestrictedInternalIP('example.com')).toBe(false));
    it('allows 203.0.113.1', () => expect(isRestrictedInternalIP('203.0.113.1')).toBe(false));
    it('allows 2001:db8::1 (documentation prefix)', () => expect(isRestrictedInternalIP('2001:db8::1')).toBe(false));
  });
});
