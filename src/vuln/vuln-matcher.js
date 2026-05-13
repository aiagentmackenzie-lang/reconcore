// src/vuln/vuln-matcher.js
'use strict';

const { NvdClient } = require('./nvd-client');
const logger = require('../core/logger');
const { calculateSeverity } = require('../report/cvss');
const { mapToAttck } = require('./attck-mapper');

/**
 * Match discovered services to CVEs via NVD API v2.
 * Returns findings enriched with CVSS v3.1 scores and ATT&CK mappings.
 *
 * @param {PortResult[]} openPorts - Output from scanPorts()
 * @param {BannerResult[]} banners  - Output from grabBanners()
 * @param {object} options
 * @param {string} [options.nvdApiKey] - NVD API key (strongly recommended — rate limits apply)
 * @returns {Promise<VulnFinding[]>}
 */
async function matchVulnerabilities(openPorts, banners, options = {}) {
  const { nvdApiKey } = options;
  const findings = [];

  const nvdClient = new NvdClient({ apiKey: nvdApiKey });

  for (const portResult of openPorts) {
    if (!portResult.cpe) continue;

    const banner = banners.find(b => b.port === portResult.port);
    const version = banner?.version ?? null;

    logger.info(`[VULN] Querying NVD for ${portResult.service}`, {
      port: portResult.port,
      cpe: portResult.cpe,
    });

    try {
      const cves = await queryCvesForService(portResult.service, version, nvdClient);

      for (const cve of cves) {
        const cvss = extractCvssV3(cve);
        if (!cvss) continue;

        const severity = calculateSeverity(cvss.baseScore);
        const attckTtps = mapToAttck(portResult.service, portResult.port);

        findings.push({
          cveId:       cve.id,
          service:     portResult.service,
          port:        portResult.port,
          description: cve.descriptions?.find(d => d.lang === 'en')?.value ?? 'No description available.',
          cvss: {
            version:     '3.1',
            baseScore:   cvss.baseScore,
            severity,
            vector:      cvss.vectorString,
            exploitability: cvss.exploitabilityScore,
            impact:      cvss.impactScore,
          },
          attck: attckTtps,
          references: (cve.references ?? []).slice(0, 3).map(r => r.url),
          remediation: extractRemediation(cve),
        });
      }
    } catch (err) {
      logger.warn(`[VULN] NVD query failed for ${portResult.service}`, { error: err.message });
    }
  }

  // Sort by CVSS base score descending — critical findings surface first
  findings.sort((a, b) => b.cvss.baseScore - a.cvss.baseScore);

  logger.info(`[VULN] Vulnerability matching complete`, { findingCount: findings.length });

  return findings;
}

/**
 * Query NVD for CVEs matching a service.
 * @private
 */
async function queryCvesForService(serviceName, version, nvdClient) {
  const keyword = version ? `${serviceName} ${version}` : serviceName;
  return nvdClient.searchByKeyword(keyword, 10);
}

/**
 * Extract CVSS v3.1 metrics from CVE data.
 * @private
 */
function extractCvssV3(cve) {
  const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  if (!metrics) return null;
  return {
    baseScore:          metrics.baseScore,
    vectorString:       metrics.vectorString,
    exploitabilityScore: cve.metrics.cvssMetricV31[0].exploitabilityScore,
    impactScore:        cve.metrics.cvssMetricV31[0].impactScore,
  };
}

/**
 * Extract remediation info from CVE references.
 * @private
 */
function extractRemediation(cve) {
  const patchRef = cve.references?.find(r =>
    r.tags?.includes('Patch') || r.tags?.includes('Vendor Advisory')
  );
  return patchRef
    ? `Apply vendor patch. See: ${patchRef.url}`
    : 'Review vendor advisories and apply available patches promptly.';
}

module.exports = { matchVulnerabilities };
