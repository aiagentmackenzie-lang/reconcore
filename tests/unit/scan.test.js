// tests/unit/scan.test.js
'use strict';

const { scanPorts, SERVICE_MAP, detectService } = require('../../src/scan');

describe('Scan Module', () => {
  describe('SERVICE_MAP', () => {
    test('should contain common ports', () => {
      expect(SERVICE_MAP[22]).toEqual({ name: 'SSH', cpe: 'cpe:2.3:a:openbsd:openssh:*' });
      expect(SERVICE_MAP[80]).toEqual({ name: 'HTTP', cpe: 'cpe:2.3:a:*:http_server:*' });
      expect(SERVICE_MAP[443]).toEqual({ name: 'HTTPS', cpe: 'cpe:2.3:a:*:https:*' });
    });

    test('should have 24 service mappings', () => {
      expect(Object.keys(SERVICE_MAP).length).toBe(24);
    });

    test('should map previously missing CLI default ports', () => {
      expect(SERVICE_MAP[23]).toHaveProperty('name', 'Telnet');
      expect(SERVICE_MAP[139]).toHaveProperty('name', 'NetBIOS');
      expect(SERVICE_MAP[993]).toHaveProperty('name', 'IMAPS');
      expect(SERVICE_MAP[995]).toHaveProperty('name', 'POP3S');
    });
  });

  describe('scanPorts', () => {
    test('should return empty array for non-routable IP', async () => {
      const results = await scanPorts('192.0.2.1', [22, 80], {
        timeout: 500,
        concurrency: 2,
        ratePerSecond: 10,
      });
      expect(results).toEqual([]);
    }, 5000);

    test('should scan multiple ports', async () => {
      // Scan localhost SSH port (likely closed but testable)
      const results = await scanPorts('127.0.0.1', [22, 80, 443], {
        timeout: 500,
        concurrency: 3,
        ratePerSecond: 10,
      });
      expect(Array.isArray(results)).toBe(true);
      // Results depend on local services
    }, 5000);
  });

  describe('detectService', () => {
    test('should return detection result structure', async () => {
      const result = await detectService('127.0.0.1', 22, 'SSH', {
        timeout: 500,
      });

      expect(result).toHaveProperty('port');
      expect(result).toHaveProperty('service');
      expect(result).toHaveProperty('banner');
      expect(result).toHaveProperty('version');
      expect(result).toHaveProperty('detected');
    }, 3000);
  });
});
