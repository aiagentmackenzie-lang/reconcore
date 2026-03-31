// src/scan/service-detect.js
'use strict';

const net = require('node:net');
const logger = require('../core/logger');

/**
 * Service version fingerprinting via banner grabbing and protocol probes.
 * Sends protocol-specific probes to elicit version information.
 *
 * @param {string} host - Target host
 * @param {number} port - Port to probe
 * @param {string} service - Service name hint from port mapping
 * @param {object} options
 * @param {number} options.timeout - Probe timeout in ms
 * @returns {Promise<object>} Service detection result
 */
async function detectService(host, port, service, options = {}) {
  const { timeout = 5000 } = options;

  logger.info(`[SCAN] Detecting service version on ${port}`, { host, service });

  // Protocol-specific probes
  const probes = {
    FTP: () => sendProbe(host, port, '', timeout),
    SSH: () => sendProbe(host, port, '', timeout),
    SMTP: () => sendProbe(host, port, 'EHLO reconcore.local\r\n', timeout),
    HTTP: () => sendProbe(host, port, 'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n', timeout),
    HTTPS: () => sendTlsProbe(host, port, timeout),
  };

  const probeFn = probes[service] || (() => sendProbe(host, port, '', timeout));

  try {
    const banner = await probeFn();
    const version = parseVersion(banner, service);

    return {
      port,
      service,
      banner: banner.slice(0, 500), // Limit banner size
      version,
      detected: true,
    };
  } catch (err) {
    logger.debug(`[SCAN] Service detection failed for ${port}`, { error: err.message });
    return {
      port,
      service,
      banner: null,
      version: null,
      detected: false,
    };
  }
}

/**
 * Send a TCP probe and return the banner.
 * @private
 */
function sendProbe(host, port, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let data = '';
    let settled = false;

    const settle = (result, isError = false) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (isError) reject(result);
      else resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.on('data', chunk => {
      data += chunk.toString('utf-8');
      // Close after receiving data
      if (data.length > 0 && !settled) {
        settle(data);
      }
    });
    socket.on('connect', () => {
      if (payload) {
        socket.write(payload);
      }
    });
    socket.on('timeout', () => settle(new Error('Timeout'), true));
    socket.on('error', err => settle(err, true));
    socket.on('close', () => {
      if (!settled) settle(data);
    });

    socket.connect(port, host);
  });
}

/**
 * Send TLS probe (simplified - in production would use tls module).
 * @private
 */
async function sendTlsProbe(host, port, timeoutMs) {
  // Simplified - real implementation would use tls.connect
  // and extract certificate info
  const tls = require('node:tls');

  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port,
      rejectUnauthorized: false,
      servername: host,
    }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      resolve(`TLS Certificate: ${cert.subject?.CN || 'unknown'}, Issuer: ${cert.issuer?.O || 'unknown'}`);
    });

    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('TLS timeout'));
    });
    socket.on('error', reject);
  });
}

/**
 * Parse version information from banner.
 * @private
 */
function parseVersion(banner, service) {
  const patterns = {
    SSH: /SSH-(\d+\.\d+)-([^\s]+)/,
    HTTP: /Server:\s*([^\r\n]+)/i,
    FTP: /(\d{3})[\s-]([^\r\n]+)/,
    SMTP: /(\d{3})[\s-]([^\r\n]+)/,
  };

  const pattern = patterns[service];
  if (pattern) {
    const match = banner.match(pattern);
    if (match) {
      return match[1] || match[2] || null;
    }
  }

  return null;
}

/**
 * Detect services for multiple open ports.
 *
 * @param {string} host - Target host
 * @param {Array} openPorts - Array of port scan results
 * @param {object} options
 * @returns {Promise<Array>} Service detection results
 */
async function detectServices(host, openPorts, options = {}) {
  const results = [];

  for (const portInfo of openPorts) {
    const detection = await detectService(host, portInfo.port, portInfo.service, options);
    results.push(detection);
  }

  return results;
}

module.exports = {
  detectService,
  detectServices,
};
