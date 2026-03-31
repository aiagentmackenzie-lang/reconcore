// tests/unit/recon.test.js
'use strict';

const {
  enumerateDnsRecords,
  reverseDns,
  getNameservers,
  enumerateSubdomains,
} = require('../../src/recon');
const { ScopeGuard } = require('../../src/core/scope-guard');

// Mock data for testing
const mockScope = {
  engagementId: 'ENG-TEST-001',
  client: 'Test Corp',
  authorizedBy: 'Test User',
  testingWindow: {
    start: new Date(Date.now() - 86400000).toISOString(),
    end: new Date(Date.now() + 86400000).toISOString(),
  },
  targets: {
    domains: ['example.com'],
    cidr: [],
  },
};

describe('Recon Module', () => {
  describe('enumerateDnsRecords', () => {
    test('should return empty array for non-existent domain', async () => {
      const records = await enumerateDnsRecords('this-definitely-does-not-exist-12345.com', ['A']);
      expect(records).toEqual([]);
    });

    test('should return A record for existing domain', async () => {
      const records = await enumerateDnsRecords('example.com', ['A']);
      expect(records.length).toBeGreaterThan(0);
      expect(records[0].type).toBe('A');
      expect(Array.isArray(records[0].values)).toBe(true);
    });

    test('should return multiple record types', async () => {
      const records = await enumerateDnsRecords('example.com', ['A', 'TXT']);
      expect(records.some(r => r.type === 'A')).toBe(true);
    });
  });

  describe('reverseDns', () => {
    test('should return string or null for IP', async () => {
      const hostname = await reverseDns('93.184.216.34');
      expect(typeof hostname === 'string' || hostname === null).toBe(true);
    });

    test('should return null for unroutable IP', async () => {
      const hostname = await reverseDns('192.0.2.1');
      expect(hostname).toBeNull();
    });
  });

  describe('getNameservers', () => {
    test('should return array for domain', async () => {
      const ns = await getNameservers('example.com');
      expect(Array.isArray(ns)).toBe(true);
    });
  });

  describe('enumerateSubdomains', () => {
    test('should enumerate subdomains from wordlist', async () => {
      const guard = new ScopeGuard(mockScope);
      const findings = await enumerateSubdomains('example.com', guard, {
        wordlistPath: './wordlists/subdomains-top100.txt',
        concurrency: 5,
      });

      expect(findings).toBeInstanceOf(Array);
      // example.com should have a base record
      expect(findings.some(f => f.isBase)).toBe(true);
    }, 10000);

    test('should respect scope boundaries', async () => {
      const guard = new ScopeGuard(mockScope);
      // Should not throw for in-scope domain
      const result = await enumerateSubdomains('example.com', guard, {
        concurrency: 1,
        timeout: 1000,
      });
      expect(Array.isArray(result)).toBe(true);
    }, 10000);
  });
});
