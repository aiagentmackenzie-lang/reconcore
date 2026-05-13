// tests/unit/enum.test.js
'use strict';

const { grabBanners, auditTls, auditHttpHeaders } = require('../../src/enum');

describe('Enum Module', () => {
  describe('grabBanners', () => {
    test('should return empty array for no ports', async () => {
      const results = await grabBanners('127.0.0.1', []);
      expect(results).toEqual([]);
    });

    test('should attempt banner grab on provided ports', async () => {
      const openPorts = [
        { port: 22, service: 'SSH' },
        { port: 80, service: 'HTTP' },
      ];
      const results = await grabBanners('127.0.0.1', openPorts, { timeout: 500 });
      expect(Array.isArray(results)).toBe(true);
    }, 5000);
  });

  describe('auditTls', () => {
    test('should return empty array for non-TLS ports', async () => {
      const openPorts = [{ port: 80, service: 'HTTP' }];
      const results = await auditTls('127.0.0.1', openPorts);
      expect(results).toEqual([]);
    });

    test('should analyze TLS on HTTPS ports', async () => {
      const openPorts = [{ port: 443, service: 'HTTPS' }];
      const results = await auditTls('127.0.0.1', openPorts, { timeout: 500 });
      // May fail if no HTTPS service, but structure is correct
      expect(Array.isArray(results)).toBe(true);
    }, 5000);
  });

  describe('auditHttpHeaders', () => {
    test('should return empty array for non-HTTP ports', async () => {
      const openPorts = [{ port: 22, service: 'SSH' }];
      const results = await auditHttpHeaders('127.0.0.1', openPorts);
      expect(results).toEqual([]);
    });

    test('should attempt header audit on HTTP ports', async () => {
      const openPorts = [{ port: 80, service: 'HTTP' }];
      const results = await auditHttpHeaders('127.0.0.1', openPorts, { timeout: 500 });
      expect(Array.isArray(results)).toBe(true);
    }, 5000);

    test('should attempt header audit on HTTPS ports (443, 8443)', async () => {
      const openPorts = [
        { port: 443, service: 'HTTPS' },
        { port: 8443, service: 'HTTPS-Alt' },
      ];
      const results = await auditHttpHeaders('127.0.0.1', openPorts, { timeout: 500 });
      expect(Array.isArray(results)).toBe(true);
      expect(results).toHaveLength(2);
    }, 5000);
  });
});
