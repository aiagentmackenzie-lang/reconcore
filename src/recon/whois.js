// src/recon/whois.js
'use strict';

const net = require('node:net');
const logger = require('../core/logger');

/**
 * WHOIS lookup for a domain or IP.
 * Note: This is a basic implementation. Production use may require
 * recursive WHOIS server following and parsing.
 *
 * @param {string} query - Domain or IP to lookup
 * @returns {Promise<object>} WHOIS data
 */
async function whoisLookup(query) {
  const whoisServers = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'app': 'whois.nic.google',
  };

  // Determine WHOIS server based on TLD
  const tld = query.split('.').pop();
  const server = whoisServers[tld] || 'whois.iana.org';

  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let data = '';

    socket.setTimeout(10000);

    socket.on('connect', () => {
      socket.write(`${query}\r\n`);
    });

    socket.on('data', chunk => {
      data += chunk.toString();
    });

    socket.on('close', () => {
      const parsed = parseWhoisData(data);
      resolve({
        query,
        server,
        raw: data,
        parsed,
      });
    });

    socket.on('error', reject);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('WHOIS timeout'));
    });

    socket.connect(43, server);
  });
}

/**
 * Parse WHOIS response data into key-value pairs.
 * @private
 */
function parseWhoisData(data) {
  const result = {};
  const lines = data.split('\n');

  for (const line of lines) {
    const match = line.match(/^([^:]+):\s*(.+)$/);
    if (match) {
      const [, key, value] = match;
      const trimmedKey = key.trim().toLowerCase().replace(/\s+/g, '_');
      if (!result[trimmedKey]) {
        result[trimmedKey] = [];
      }
      result[trimmedKey].push(value.trim());
    }
  }

  return result;
}

/**
 * Get ASN information for an IP address.
 * Uses Team Cymru's DNS-based ASN lookup.
 *
 * @param {string} ip - IP address to lookup
 * @returns {Promise<object|null>} ASN data
 */
async function asnLookup(ip) {
  const dns = require('node:dns').promises;

  try {
    // Team Cymru format: IP reversed + .origin.asn.cymru.com
    const reversed = ip.split('.').reverse().join('.');
    const query = `${reversed}.origin.asn.cymru.com`;

    const [txtRecord] = await dns.resolveTxt(query);
    if (!txtRecord || !txtRecord[0]) return null;

    const parts = txtRecord[0].split(' | ');
    return {
      asn: parts[0]?.trim(),
      cidr: parts[1]?.trim(),
      country: parts[2]?.trim(),
      registry: parts[3]?.trim(),
      allocationDate: parts[4]?.trim(),
      organization: parts[5]?.trim(),
    };
  } catch {
    return null;
  }
}

module.exports = {
  whoisLookup,
  asnLookup,
};
