// tests/unit/report.test.js
'use strict';

const { generateReport } = require('../../src/report');
const fs = require('node:fs/promises');
const path = require('node:path');

describe('Report Module', () => {
  const mockEngagementData = {
    scope: {
      engagementId: 'ENG-TEST-001',
      client: 'Test Corp',
      authorizedBy: 'Test User',
    },
    sessionId: 'abc123',
    subdomains: [],
    openPorts: [],
    banners: [],
    tlsFindings: [],
    headerFindings: [],
    vulnFindings: [],
  };

  const outputDir = path.join(__dirname, '../../test-reports');

  afterAll(async () => {
    // Cleanup test reports
    try {
      await fs.rm(outputDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('generateReport', () => {
    test('should generate reports with no findings', async () => {
      const result = await generateReport(mockEngagementData, outputDir);

      expect(result).toHaveProperty('jsonPath');
      expect(result).toHaveProperty('mdPath');
      expect(result).toHaveProperty('htmlPath');
      expect(result).toHaveProperty('report');

      // Verify JSON report structure
      expect(result.report.meta.tool).toBe('ReconCore v1.0');
      expect(result.report.executive.totalFindings).toBe(0);
      expect(result.report.executive.riskScore).toBe(0);
    });

    test('should generate reports with findings', async () => {
      const dataWithFindings = {
        ...mockEngagementData,
        vulnFindings: [
          {
            cveId: 'CVE-2021-44228',
            service: 'Java',
            port: 8080,
            description: 'Log4Shell RCE vulnerability',
            cvss: {
              baseScore: 10.0,
              severity: { label: 'CRITICAL', color: '#8B0000', baseScore: 10.0 },
              vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            },
            attck: [{ tactic: 'Execution', tacticId: 'TA0002', technique: 'Command and Scripting Interpreter', techniqueId: 'T1059' }],
            references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
            remediation: 'Upgrade to Log4j 2.15.0 or later',
          },
        ],
      };

      const result = await generateReport(dataWithFindings, outputDir);

      expect(result.report.executive.totalFindings).toBe(1);
      expect(result.report.executive.severityMatrix.CRITICAL).toBe(1);
      expect(result.report.vulnerabilities).toHaveLength(1);

      // Check that files were written
      const jsonContent = await fs.readFile(result.jsonPath, 'utf8');
      const reportData = JSON.parse(jsonContent);
      expect(reportData.meta.engagementId).toBe('ENG-TEST-001');
    });

    test('should create output directory if it does not exist', async () => {
      const newOutputDir = path.join(outputDir, 'nested', 'reports');
      const result = await generateReport(mockEngagementData, newOutputDir);
      expect(result).toBeDefined();
    });
  });
});
