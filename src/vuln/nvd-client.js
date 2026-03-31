// src/vuln/nvd-client.js
'use strict';

const https = require('node:https');
const logger = require('../core/logger');

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_API_BASE_1_0 = 'https://services.nvd.nist.gov/rest/json/cves/1.0';

/**
 * NIST NVD API v2 client for CVE lookups.
 *
 * @param {object} options
 * @param {string} [options.apiKey] - NVD API key (recommended for higher rate limits)
 * @param {number} [options.timeout] - Request timeout in ms
 */
class NvdClient {
  #apiKey;
  #timeout;

  constructor(options = {}) {
    this.#apiKey = options.apiKey || null;
    this.#timeout = options.timeout || 30000;
  }

  /**
   * Search for CVEs by keyword (service name and version).
   *
   * @param {string} keyword - Search keyword (e.g., "OpenSSH 8.2")
   * @param {number} resultsPerPage - Number of results (max 100)
   * @returns {Promise<Array>} CVE items
   */
  async searchByKeyword(keyword, resultsPerPage = 10) {
    const encodedKeyword = encodeURIComponent(keyword);
    const url = `${NVD_API_BASE}?keywordSearch=${encodedKeyword}&resultsPerPage=${resultsPerPage}`;

    logger.info(`[NVD] Searching for: ${keyword}`);

    try {
      const data = await this.#httpGet(url);
      const vulnerabilities = data.vulnerabilities || [];
      return vulnerabilities.map(v => v.cve);
    } catch (err) {
      logger.warn(`[NVD] Search failed: ${err.message}`);
      return [];
    }
  }

  /**
   * Get CVE details by ID.
   *
   * @param {string} cveId - CVE ID (e.g., "CVE-2021-44228")
   * @returns {Promise<object|null>} CVE data
   */
  async getCveById(cveId) {
    const url = `${NVD_API_BASE}?cveId=${cveId}`;

    logger.info(`[NVD] Fetching CVE: ${cveId}`);

    try {
      const data = await this.#httpGet(url);
      return data.vulnerabilities?.[0]?.cve || null;
    } catch (err) {
      logger.warn(`[NVD] CVE fetch failed: ${err.message}`);
      return null;
    }
  }

  /**
   * Search for CVEs by CPE (Common Platform Enumeration).
   *
   * @param {string} cpe - CPE string
   * @param {number} resultsPerPage - Number of results
   * @returns {Promise<Array>} CVE items
   */
  async searchByCpe(cpe, resultsPerPage = 10) {
    const encodedCpe = encodeURIComponent(cpe);
    const url = `${NVD_API_BASE}?cpeName=${encodedCpe}&resultsPerPage=${resultsPerPage}`;

    logger.info(`[NVD] Searching by CPE: ${cpe}`);

    try {
      const data = await this.#httpGet(url);
      return (data.vulnerabilities || []).map(v => v.cve);
    } catch (err) {
      logger.warn(`[NVD] CPE search failed: ${err.message}`);
      return [];
    }
  }

  /**
   * Make HTTP GET request to NVD API.
   * @private
   */
  #httpGet(url) {
    return new Promise((resolve, reject) => {
      const options = {
        headers: {
          'User-Agent': 'ReconCore/1.0 (authorized security assessment)',
        },
      };

      if (this.#apiKey) {
        options.headers.apiKey = this.#apiKey;
      }

      const req = https.get(url, options, res => {
        let data = '';

        res.on('data', chunk => {
          data += chunk;
        });

        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve(parsed);
          } catch (e) {
            reject(new Error(`Invalid JSON from NVD: ${e.message}`));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(this.#timeout, () => {
        req.destroy();
        reject(new Error('NVD API timeout'));
      });
    });
  }
}

module.exports = { NvdClient };
