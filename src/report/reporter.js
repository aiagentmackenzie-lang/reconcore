// src/report/reporter.js
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { buildSeverityMatrix } = require('./cvss');
const logger = require('../core/logger');

/**
 * Build and persist a structured engagement report.
 *
 * @param {object} engagementData
 * @param {string} outputDir - Directory to write report files
 */
async function generateReport(engagementData, outputDir = './reports') {
  const {
    scope,
    sessionId,
    subdomains,
    openPorts,
    banners,
    tlsFindings,
    headerFindings,
    vulnFindings,
  } = engagementData;

  await fs.mkdir(outputDir, { recursive: true });

  const severityMatrix = buildSeverityMatrix(vulnFindings);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportName = `${scope.engagementId}-${timestamp}`;

  const report = {
    meta: {
      tool:           'ReconCore v1.0',
      engagementId:   scope.engagementId,
      client:         scope.client,
      authorizedBy:   scope.authorizedBy,
      sessionId,
      generatedAt:    new Date().toISOString(),
      methodology:    ['PTES', 'OWASP WSTG', 'MITRE ATT&CK v15'],
    },
    executive: {
      totalFindings:  vulnFindings.length,
      severityMatrix,
      riskScore:      computeEngagementRiskScore(vulnFindings),
      topFindings:    vulnFindings.slice(0, 3).map(f => ({
        cve:      f.cveId,
        severity: f.cvss.severity.label,
        service:  f.service,
        port:     f.port,
      })),
    },
    recon: {
      subdomains,
      totalDiscovered: subdomains.length,
    },
    scan: {
      openPorts,
      banners,
      tlsFindings,
      securityHeaders: headerFindings,
    },
    vulnerabilities: vulnFindings,
  };

  // JSON report (for CI/CD pipeline integration and SIEM ingestion)
  const jsonPath = path.join(outputDir, `${reportName}.json`);
  await fs.writeFile(jsonPath, JSON.stringify(report, null, 2), 'utf8');
  logger.info(`[REPORT] JSON report written: ${jsonPath}`);

  // Markdown report (for JIRA, Confluence, GitHub Issues)
  const mdPath = path.join(outputDir, `${reportName}.md`);
  await fs.writeFile(mdPath, buildMarkdownReport(report), 'utf8');
  logger.info(`[REPORT] Markdown report written: ${mdPath}`);

  // HTML report
  const htmlPath = path.join(outputDir, `${reportName}.html`);
  await fs.writeFile(htmlPath, buildHtmlReport(report), 'utf8');
  logger.info(`[REPORT] HTML report written: ${htmlPath}`);

  console.log('\n');
  console.log('╔═══════════════════════════════════════════════╕');
  console.log('║         RECONCORE — ENGAGEMENT REPORT      ║');
  console.log('╠═══════════════════════════════════════════════╣');
  console.log(`║  Engagement   : ${scope.engagementId.padEnd(26)}║`);
  console.log(`║  Session ID   : ${sessionId.padEnd(26)}║`);
  console.log(`║  Total Vulns  : ${String(vulnFindings.length).padEnd(26)}║`);
  console.log('╠═══════════════════════════════════════════════╣');
  console.log(`║  CRITICAL     : ${String(severityMatrix.CRITICAL).padEnd(26)}║`);
  console.log(`║  HIGH         : ${String(severityMatrix.HIGH).padEnd(26)}║`);
  console.log(`║  MEDIUM       : ${String(severityMatrix.MEDIUM).padEnd(26)}║`);
  console.log(`║  LOW          : ${String(severityMatrix.LOW).padEnd(26)}║`);
  console.log('╠═══════════════════════════════════════════════╣');
  console.log(`║  Reports saved to: ${outputDir.padEnd(23)}║`);
  console.log('╚═══════════════════════════════════════════════╝');
  console.log('\n');

  return { jsonPath, mdPath, htmlPath, report };
}

/**
 * Build Markdown report.
 * @private
 */
function buildMarkdownReport(report) {
  const { meta, executive, vulnerabilities } = report;
  const lines = [
    `# Security Assessment Report — ${meta.engagementId}`,
    ``,
    `**Client:** ${meta.client}  `,
    `**Authorized by:** ${meta.authorizedBy}  `,
    `**Generated:** ${meta.generatedAt}  `,
    `**Methodology:** ${meta.methodology.join(', ')}`,
    ``,
    `---`,
    ``,
    `## Executive Summary`,
    ``,
    `| Severity | Count |`,
    `|----------|-------|`,
    `| 🔴 Critical | ${executive.severityMatrix.CRITICAL} |`,
    `| 🟠 High     | ${executive.severityMatrix.HIGH} |`,
    `| 🟡 Medium   | ${executive.severityMatrix.MEDIUM} |`,
    `| 🟢 Low      | ${executive.severityMatrix.LOW} |`,
    `| **Total**   | **${executive.severityMatrix.total}** |`,
    ``,
    `**Engagement Risk Score:** ${executive.riskScore}/10`,
    ``,
    `---`,
    ``,
    `## Vulnerability Findings`,
    ``,
    ...vulnerabilities.map((v, i) => [
      `### ${i + 1}. [${v.cvss.severity.label}] ${v.cveId} — ${v.service} (Port ${v.port})`,
      ``,
      `**CVSS v3.1 Base Score:** ${v.cvss.baseScore} | **Vector:** \`${v.cvss.vector}\``,
      ``,
      `**Description:** ${v.description}`,
      ``,
      `**MITRE ATT&CK TTPs:**`,
      ...v.attck.map(t => `- ${t.tactic} (${t.tacticId}) → ${t.technique} (\`${t.techniqueId}\`)`),
      ``,
      `**Remediation:** ${v.remediation}`,
      ``,
      `**References:** ${v.references.join(', ')}`,
      ``,
      `---`,
      ``,
    ].join('\n')),
  ];

  return lines.join('\n');
}

/**
 * Build HTML report.
 * @private
 */
function buildHtmlReport(report) {
  const { meta, executive, vulnerabilities } = report;

  const css = `
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; color: #333; }
    h1 { color: #dc2626; border-bottom: 2px solid #dc2626; padding-bottom: 10px; }
    h2 { color: #374151; margin-top: 30px; }
    table { border-collapse: collapse; width: 100%; margin: 20px 0; }
    th, td { border: 1px solid #e5e7eb; padding: 12px; text-align: left; }
    th { background: #f3f4f6; font-weight: 600; }
    .severity-critical { color: #991b1b; background: #fee2e2; }
    .severity-high { color: #7f1d1d; background: #fecaca; }
    .severity-medium { color: #92400e; background: #fef3c7; }
    .severity-low { color: #065f46; background: #d1fae5; }
    .finding { margin: 20px 0; padding: 20px; border: 1px solid #e5e7eb; border-radius: 8px; }
    .finding-header { font-size: 1.1em; font-weight: 600; margin-bottom: 10px; }
    .meta { color: #6b7280; margin-bottom: 20px; }
    .risk-score { font-size: 2em; font-weight: 700; text-align: center; padding: 20px; background: #f3f4f6; border-radius: 8px; }
  `;

  const vulnerabilityHtml = vulnerabilities.map((v, i) => `
    <div class="finding severity-${v.cvss.severity.label.toLowerCase()}">
      <div class="finding-header">${i + 1}. [${v.cvss.severity.label}] ${v.cveId} — ${v.service} (Port ${v.port})</div>
      <p><strong>CVSS v3.1 Base Score:</strong> ${v.cvss.baseScore} | <strong>Vector:</strong> ${v.cvss.vector}</p>
      <p>${v.description}</p>
      <p><strong>Remediation:</strong> ${v.remediation}</p>
    </div>
  `).join('');

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Assessment Report — ${meta.engagementId}</title>
  <style>${css}</style>
</head>
<body>
  <h1>⚠️ Security Assessment Report</h1>
  <div class="meta">
    <p><strong>Client:</strong> ${meta.client}</p>
    <p><strong>Authorized by:</strong> ${meta.authorizedBy}</p>
    <p><strong>Generated:</strong> ${meta.generatedAt}</p>
    <p><strong>Methodology:</strong> ${meta.methodology.join(', ')}</p>
  </div>

  <h2>Executive Summary</h2>
  <div class="risk-score">Engagement Risk Score: ${executive.riskScore}/10</div>

  <table>
    <thead>
      <tr><th>Severity</th><th>Count</th></tr>
    </thead>
    <tbody>
      <tr class="severity-critical"><td>Critical</td><td>${executive.severityMatrix.CRITICAL}</td></tr>
      <tr class="severity-high"><td>High</td><td>${executive.severityMatrix.HIGH}</td></tr>
      <tr class="severity-medium"><td>Medium</td><td>${executive.severityMatrix.MEDIUM}</td></tr>
      <tr class="severity-low"><td>Low</td><td>${executive.severityMatrix.LOW}</td></tr>
    </tbody>
  </table>

  <h2>Vulnerability Findings (${vulnerabilities.length})</h2>
  ${vulnerabilityHtml}

  <footer>
    <p>Generated by ReconCore v1.0 — ${meta.tool}</p>
  </footer>
</body>
</html>
  `;
}

/**
 * Compute a normalized engagement-level risk score (0–10) based on CVSS distribution.
 * @private
 */
function computeEngagementRiskScore(findings) {
  if (!findings.length) return 0;

  const weightedSum = findings.reduce((sum, f) => {
    const score = f.cvss?.baseScore ?? 0;
    return sum + score;
  }, 0);

  return Math.min(10, parseFloat((weightedSum / findings.length).toFixed(1)));
}

module.exports = { generateReport };
