// src/enum/tls.js
'use strict';

const tls = require('node:tls');
const net = require('node:net');
const logger = require('../core/logger');

// Known weak cipher suites (OWASP recommendation)
// Note: 'SHA1' targets legacy SHA-1 specifically;
// modern SHA-256/SHA-384 ciphers must NOT be flagged.
const WEAK_CIPHERS = [
  'DES',
  '3DES',
  'RC4',
  'MD5',
  'SHA1',
  'NULL',
  'EXPORT',
  'anon',
];

/**
 * Audit TLS certificates and configuration on HTTPS ports.
 *
 * @param {string} host - Target host
 * @param {Array} openPorts - Array of {port, service} from port scan
 * @param {object} options
 * @param {number} options.timeout - TLS connect timeout
 * @returns {Promise<Array>} TLS findings
 */
async function auditTls(host, openPorts, options = {}) {
  const { timeout = 10000 } = options;
  const results = [];

  // Filter for TLS-capable ports
  const tlsPorts = openPorts.filter(p =>
    ['HTTPS', 'HTTPS-Alt'].includes(p.service) ||
    [443, 8443].includes(p.port)
  );

  if (tlsPorts.length === 0) {
    logger.info('[ENUM] No TLS ports to audit');
    return results;
  }

  logger.info('[ENUM] Starting TLS audit', { host, portCount: tlsPorts.length });

  for (const portInfo of tlsPorts) {
    try {
      const finding = await analyzeTls(host, portInfo.port, timeout);
      results.push(finding);
      logger.info(`[ENUM] TLS analyzed for port ${portInfo.port}`, {
        subject: finding.certificate?.subject,
        valid: finding.certificate?.valid,
      });
    } catch (err) {
      logger.debug(`[ENUM] TLS audit failed for ${portInfo.port}`, { error: err.message });
      results.push({
        port: portInfo.port,
        error: err.message,
        secure: false,
      });
    }
  }

  logger.info('[ENUM] TLS audit complete', { findings: results.length });
  return results;
}

/**
 * Analyze TLS configuration for a single port.
 * @private
 */
function analyzeTls(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let settled = false;

    const settle = (result, isError = false) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (isError) reject(result);
      else resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => settle(new Error('TLS timeout'), true));
    socket.on('error', err => settle(err, true));

    const tlsSocket = tls.connect({
      host,
      port,
      socket,
      rejectUnauthorized: false,
      servername: host,
    }, () => {
      const cert = tlsSocket.getPeerCertificate(true);
      const cipher = tlsSocket.getCipher();

      const finding = {
        port,
        protocol: cipher?.version || 'unknown',
        cipher: cipher?.name || 'unknown',
        secure: isSecureProtocol(cipher?.version) && !isWeakCipher(cipher?.name),
        certificate: {
          subject: cert.subject?.CN || cert.subject?.O || 'unknown',
          issuer: cert.issuer?.O || 'unknown',
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          valid: cert.valid_from && cert.valid_to ? isCertificateValid(cert) : null,
          expiresIn: cert.valid_to ? daysUntilExpiry(cert.valid_to) : null,
          fingerprint: cert.fingerprint,
          serialNumber: cert.serialNumber,
          altNames: cert.subjectaltname ? cert.subjectaltname.split(', ') : [],
        },
      };

      tlsSocket.end();
      settle(finding);
    });

    tlsSocket.on('error', err => settle(err, true));
  });
}

/**
 * Check if protocol version is secure.
 * @private
 */
function isSecureProtocol(version) {
  if (!version) return false;
  // TLS 1.2 and above are considered secure
  return version !== 'TLSv1' && version !== 'TLSv1.1' && version !== 'SSLv3';
}

/**
 * Check if cipher is weak.
 * Uses exact/prefix matching against known-weak tokens.
 * Modern ciphers containing SHA256, SHA384, GCM, CHACHA20 are NOT weak.
 * @private
 */
function isWeakCipher(cipherName) {
  if (!cipherName) return true;
  return WEAK_CIPHERS.some(weak => cipherName.includes(weak));
}

/**
 * Check if certificate is currently valid.
 * @private
 */
function isCertificateValid(cert) {
  const now = new Date();
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  return now >= validFrom && now <= validTo;
}

/**
 * Calculate days until certificate expiry.
 * @private
 */
function daysUntilExpiry(validTo) {
  const now = new Date();
  const expiry = new Date(validTo);
  return Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
}

module.exports = { auditTls };
