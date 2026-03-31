// src/enum/http-headers.js
'use strict';

const http = require('node:http');
const https = require('node:https');
const logger = require('../core/logger');

/**
 * Security headers to check per OWASP Secure Headers Project.
 * @see https://owasp.org/www-project-secure-headers/
 */
const SECURITY_HEADERS = {
  'strict-transport-security': {
    required: true,
    recommendation: 'max-age=31536000; includeSubDomains',
    description: 'HSTS - Forces HTTPS connections',
  },
  'content-security-policy': {
    required: true,
    recommendation: "default-src 'self'",
    description: 'CSP - Prevents XSS and injection attacks',
  },
  'x-content-type-options': {
    required: true,
    recommendation: 'nosniff',
    description: 'Prevents MIME type sniffing',
  },
  'x-frame-options': {
    required: true,
    recommendation: 'DENY or SAMEORIGIN',
    description: 'Prevents clickjacking',
  },
  'x-xss-protection': {
    required: false,
    recommendation: '0',
    description: 'Legacy XSS protection (deprecated, should be disabled)',
  },
  'referrer-policy': {
    required: true,
    recommendation: 'strict-origin-when-cross-origin',
    description: 'Controls referrer information',
  },
  'permissions-policy': {
    required: true,
    recommendation: 'geolocation=(), microphone=()',
    description: 'Controls browser features',
  },
};

/**
 * Audit HTTP security headers on web ports.
 *
 * @param {string} host - Target host
 * @param {Array} openPorts - Array of {port, service} from port scan
 * @param {object} options
 * @param {number} options.timeout - Request timeout
 * @returns {Promise<Array>} Header audit findings
 */
async function auditHttpHeaders(host, openPorts, options = {}) {
  const { timeout = 10000 } = options;
  const results = [];

  // Filter for HTTP ports
  const httpPorts = openPorts.filter(p =>
    ['HTTP', 'HTTP-Alt'].includes(p.service) ||
    [80, 8080].includes(p.port)
  );

  if (httpPorts.length === 0) {
    logger.info('[ENUM] No HTTP ports to audit');
    return results;
  }

  logger.info('[ENUM] Starting HTTP header audit', { host, portCount: httpPorts.length });

  for (const portInfo of httpPorts) {
    try {
      const finding = await analyzeHeaders(host, portInfo.port, timeout);
      results.push(finding);
      logger.info(`[ENUM] HTTP headers analyzed for port ${portInfo.port}`, {
        missingHeaders: finding.missing.length,
      });
    } catch (err) {
      logger.debug(`[ENUM] HTTP header audit failed for ${portInfo.port}`, { error: err.message });
      results.push({
        port: portInfo.port,
        error: err.message,
      });
    }
  }

  logger.info('[ENUM] HTTP header audit complete', { findings: results.length });
  return results;
}

/**
 * Analyze headers for a single HTTP endpoint.
 * @private
 */
function analyzeHeaders(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const isHttps = port === 443 || port === 8443;
    const protocol = isHttps ? https : http;
    const options = {
      hostname: host,
      port,
      path: '/',
      method: 'HEAD',
      timeout: timeoutMs,
      rejectUnauthorized: false,
    };

    const req = protocol.request(options, res => {
      const headers = res.headers;
      const present = [];
      const missing = [];
      const values = {};

      // Check each security header
      for (const [header, config] of Object.entries(SECURITY_HEADERS)) {
        const headerValue = headers[header] || headers[header.toLowerCase()];
        if (headerValue) {
          present.push(header);
          values[header] = headerValue;
        } else if (config.required) {
          missing.push({
            header,
            description: config.description,
            recommendation: config.recommendation,
          });
        }
      }

      // Check for server header disclosure
      const serverInfo = headers.server || headers['x-powered-by'];

      resolve({
        port,
        statusCode: res.statusCode,
        headers: values,
        present,
        missing,
        serverDisclosure: serverInfo || null,
        score: calculateHeaderScore(present, missing),
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    req.end();
  });
}

/**
 * Calculate security score based on headers.
 * @private
 */
function calculateHeaderScore(present, missing) {
  const total = Object.keys(SECURITY_HEADERS).filter(h => SECURITY_HEADERS[h].required).length;
  const score = ((present.length / total) * 100).toFixed(0);
  return {
    percentage: parseInt(score),
    grade: score >= 80 ? 'A' : score >= 60 ? 'B' : score >= 40 ? 'C' : 'F',
  };
}

module.exports = { auditHttpHeaders };
