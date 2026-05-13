// src/enum/banner.js
'use strict';

const net = require('node:net');
const logger = require('../core/logger');

/**
 * Grab banners from open TCP ports.
 * Sends protocol-appropriate probes and captures responses.
 *
 * @param {string} host - Target host
 * @param {Array} openPorts - Array of {port, service} from port scan
 * @param {object} options
 * @param {number} options.timeout - Banner grab timeout in ms
 * @returns {Promise<Array>} Banner results
 */
async function grabBanners(host, openPorts, options = {}) {
  const { timeout = 5000 } = options;
  const results = [];

  logger.info('[ENUM] Starting banner grab', { host, portCount: openPorts.length });

  for (const portInfo of openPorts) {
    try {
      const banner = await grabBanner(host, portInfo.port, portInfo.service, timeout);
      if (banner) {
        const version = parseVersionFromBanner(banner, portInfo.service);
        results.push({
          port: portInfo.port,
          service: portInfo.service,
          banner: banner.slice(0, 1000), // Limit size
          version,
          timestamp: new Date().toISOString(),
        });
        logger.info(`[ENUM] Banner grabbed from port ${portInfo.port}`, {
          service: portInfo.service,
          bannerPreview: banner.slice(0, 100),
        });
      }
    } catch (err) {
      logger.debug(`[ENUM] Failed to grab banner from ${portInfo.port}`, { error: err.message });
    }
  }

  logger.info('[ENUM] Banner grab complete', { bannersFound: results.length });
  return results;
}

/**
 * Grab banner from a single port.
 * @private
 */
function grabBanner(host, port, service, timeoutMs) {
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

    // Protocol-specific probes
    const probes = {
      FTP: 'USER anonymous\r\n',
      SMTP: 'EHLO reconcore\r\n',
      HTTP: 'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
      HTTPS: '', // TLS handled separately
      SSH: '',   // SSH sends banner immediately
    };

    const probe = probes[service] || '';

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      if (probe) {
        socket.write(probe);
      }
    });

    socket.on('data', chunk => {
      data += chunk.toString('utf-8');
      // Close after receiving data
      if (data.length > 0 && !settled) {
        settle(data);
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

module.exports = { grabBanners };

/**
 * Parse version information from a raw banner string.
 * Handles common service banners: SSH, HTTP Server header, FTP, SMTP.
 *
 * @param {string} banner - Raw banner text
 * @param {string} service - Service name hint
 * @returns {string|null} Extracted version string or null
 */
function parseVersionFromBanner(banner, service) {
  if (!banner) return null;

  const patterns = {
    SSH: /SSH-[\d.]+-([^\s\r\n]+)/,
    HTTP: /Server:\s*([^\r\n]+)/i,
    FTP: /\d{3}[\s-]([^\r\n]*(?:\d+\.\d+[\d.]*\S))/,
    SMTP: /\d{3}[\s-]([^\r\n]*(?:\d+\.\d+[\d.]*\S))/,
  };

  // Try service-specific pattern first
  const pattern = patterns[service];
  if (pattern) {
    const match = banner.match(pattern);
    if (match && match[1]) {
      return match[1].trim();
    }
  }

  // Generic version pattern as fallback
  const genericMatch = banner.match(/(\S+?)[\s\/v]+(\d+(?:\.\d+)+(?:[\w.-]*)?)/);
  if (genericMatch) {
    return `${genericMatch[1]} ${genericMatch[2]}`.trim();
  }

  return null;
}
