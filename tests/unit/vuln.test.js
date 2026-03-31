// tests/unit/vuln.test.js
'use strict';

const { matchVulnerabilities, NvdClient, mapToAttck } = require('../../src/vuln');
const { calculateSeverity, buildSeverityMatrix } = require('../../src/report');

describe('Vuln Module', () => {
  describe('NvdClient', () => {
    test('should create client with default options', () => {
      const client = new NvdClient();
      expect(client).toBeInstanceOf(NvdClient);
    });

    test('should create client with API key', () => {
      const client = new NvdClient({ apiKey: 'test-key' });
      expect(client).toBeInstanceOf(NvdClient);
    });
  });

  describe('mapToAttck', () => {
    test('should return TTPs for known services', () => {
      const ttps = mapToAttck('SSH', 22);
      expect(ttps.length).toBeGreaterThan(0);
      expect(ttps[0]).toHaveProperty('tactic');
      expect(ttps[0]).toHaveProperty('technique');
    });

    test('should return default TTP for unknown service', () => {
      const ttps = mapToAttck('UnknownService', 1234);
      expect(ttps.length).toBe(1);
      expect(ttps[0].tactic).toBe('Discovery');
    });
  });

  describe('calculateSeverity', () => {
    test('should calculate CRITICAL for 9.0+', () => {
      const result = calculateSeverity(9.5);
      expect(result.label).toBe('CRITICAL');
      expect(result.color).toBe('#8B0000');
    });

    test('should calculate HIGH for 7.0-8.9', () => {
      const result = calculateSeverity(7.5);
      expect(result.label).toBe('HIGH');
    });

    test('should calculate MEDIUM for 4.0-6.9', () => {
      const result = calculateSeverity(5.5);
      expect(result.label).toBe('MEDIUM');
    });

    test('should calculate LOW for 0.1-3.9', () => {
      const result = calculateSeverity(2.5);
      expect(result.label).toBe('LOW');
    });

    test('should calculate NONE for 0.0', () => {
      const result = calculateSeverity(0.0);
      expect(result.label).toBe('NONE');
    });
  });

  describe('buildSeverityMatrix', () => {
    test('should build matrix from findings', () => {
      const findings = [
        { cvss: { severity: { label: 'CRITICAL' } } },
        { cvss: { severity: { label: 'HIGH' } } },
        { cvss: { severity: { label: 'HIGH' } } },
      ];
      const matrix = buildSeverityMatrix(findings);

      expect(matrix.CRITICAL).toBe(1);
      expect(matrix.HIGH).toBe(2);
      expect(matrix.total).toBe(3);
    });

    test('should handle empty findings', () => {
      const matrix = buildSeverityMatrix([]);
      expect(matrix.total).toBe(0);
    });
  });

  describe('matchVulnerabilities', () => {
    test('should return empty array for no ports', async () => {
      const findings = await matchVulnerabilities([], []);
      expect(findings).toEqual([]);
    });

    test('should skip ports without CPE', async () => {
      const openPorts = [{ port: 12345, service: 'Unknown', cpe: null }];
      const findings = await matchVulnerabilities(openPorts, []);
      expect(findings).toEqual([]);
    });
  });
});
