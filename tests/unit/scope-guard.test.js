// tests/unit/scope-guard.test.js
'use strict';

const { ScopeGuard, ScopeViolationError } = require('../../src/core/scope-guard');

describe('ScopeGuard', () => {
  const validScope = {
    engagementId: 'ENG-TEST-001',
    client: 'Test Corp',
    authorizedBy: 'Test User, test@test.com',
    testingWindow: {
      start: new Date(Date.now() - 86400000).toISOString(), // Yesterday
      end: new Date(Date.now() + 86400000).toISOString(),   // Tomorrow
    },
    targets: {
      domains: ['example.com', 'test.example.com'],
      cidr: ['203.0.113.0/24'],
    },
  };

  describe('constructor', () => {
    test('should initialize with valid config', () => {
      const guard = new ScopeGuard(validScope);
      expect(guard.sessionId).toBeDefined();
      expect(guard.sessionId).toHaveLength(12);
    });

    test('should throw on missing required fields', () => {
      const requiredFields = ['engagementId', 'client', 'authorizedBy', 'testingWindow', 'targets'];
      
      for (const field of requiredFields) {
        const invalidScope = { ...validScope };
        delete invalidScope[field];
        
        expect(() => new ScopeGuard(invalidScope)).toThrow(
          `scope.json is missing required field: "${field}"`
        );
      }
    });

    test('should throw when outside testing window', () => {
      const expiredScope = {
        ...validScope,
        testingWindow: {
          start: '2020-01-01T00:00:00Z',
          end: '2020-01-02T00:00:00Z',
        },
      };
      
      expect(() => new ScopeGuard(expiredScope)).toThrow('Outside authorized testing window');
    });
  });

  describe('assertInScope', () => {
    let guard;

    beforeEach(() => {
      guard = new ScopeGuard(validScope);
    });

    test('should allow exact domain match', async () => {
      await expect(guard.assertInScope('example.com')).resolves.toBeUndefined();
    });

    test('should allow subdomain of allowed domain', async () => {
      await expect(guard.assertInScope('www.example.com')).resolves.toBeUndefined();
    });

    test('should allow IP in CIDR range', async () => {
      await expect(guard.assertInScope('203.0.113.50')).resolves.toBeUndefined();
    });

    test('should throw ScopeViolationError for out-of-scope domain', async () => {
      await expect(guard.assertInScope('evil.com')).rejects.toThrow(ScopeViolationError);
    });

    test('should throw for private addresses not in scope', async () => {
      await expect(guard.assertInScope('192.168.1.1')).rejects.toThrow(ScopeViolationError);
      await expect(guard.assertInScope('10.0.0.1')).rejects.toThrow(ScopeViolationError);
      await expect(guard.assertInScope('127.0.0.1')).rejects.toThrow(ScopeViolationError);
    });

    test('should be case-insensitive for domains', async () => {
      await expect(guard.assertInScope('EXAMPLE.COM')).resolves.toBeUndefined();
      await expect(guard.assertInScope('WWW.Example.Com')).resolves.toBeUndefined();
    });

    test('should trim whitespace from host', async () => {
      await expect(guard.assertInScope('  example.com  ')).resolves.toBeUndefined();
    });
  });

  describe('excludedHosts', () => {
    test('should deny explicitly excluded hosts', async () => {
      const scopeWithExclusions = {
        ...validScope,
        excludedHosts: ['prod-db.example.com'],
      };
      const guard = new ScopeGuard(scopeWithExclusions);

      await expect(guard.assertInScope('prod-db.example.com')).rejects.toThrow(ScopeViolationError);
    });

    test('should deny subdomains of excluded hosts', async () => {
      const scopeWithExclusions = {
        ...validScope,
        excludedHosts: ['prod-db.example.com'],
      };
      const guard = new ScopeGuard(scopeWithExclusions);

      await expect(guard.assertInScope('replica.prod-db.example.com')).rejects.toThrow(ScopeViolationError);
    });

    test('should allow in-scope hosts when excludedHosts is empty', async () => {
      const scopeNoExclusions = {
        ...validScope,
        excludedHosts: [],
      };
      const guard = new ScopeGuard(scopeNoExclusions);

      await expect(guard.assertInScope('example.com')).resolves.toBeUndefined();
      await expect(guard.assertInScope('www.example.com')).resolves.toBeUndefined();
    });

    test('should be case-insensitive for excluded hosts', async () => {
      const scopeWithExclusions = {
        ...validScope,
        excludedHosts: ['PROD-DB.EXAMPLE.COM'],
      };
      const guard = new ScopeGuard(scopeWithExclusions);

      await expect(guard.assertInScope('prod-db.example.com')).rejects.toThrow(ScopeViolationError);
    });
  });

  describe('ScopeViolationError', () => {
    test('should have correct name property', () => {
      const error = new ScopeViolationError('test message');
      expect(error.name).toBe('ScopeViolationError');
      expect(error.message).toBe('test message');
    });
  });
});
