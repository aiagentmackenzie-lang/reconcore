// src/recon/dns.js
'use strict';

const dns = require('node:dns').promises;
const logger = require('../core/logger');

/**
 * DNS record enumeration for a given host.
 * Resolves multiple record types in parallel.
 *
 * @param {string} host - Hostname to query
 * @param {string[]} types - DNS record types to resolve (A, AAAA, MX, TXT, CNAME, NS, SOA)
 * @returns {Promise<Array<{type: string, values: string[]}>>}
 */
async function enumerateDnsRecords(host, types = ['A', 'AAAA', 'MX', 'TXT']) {
  const records = [];

  await Promise.allSettled(
    types.map(async type => {
      try {
        const result = await dns.resolve(host, type);
        records.push({
          type,
          values: Array.isArray(result) ? result.flat() : [result],
        });
        logger.debug(`[DNS] ${type} record for ${host}: ${JSON.stringify(result)}`);
      } catch (err) {
        // NXDOMAIN / ENODATA are expected for non-existent records
        if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
          logger.debug(`[DNS] Error resolving ${type} for ${host}: ${err.code}`);
        }
      }
    })
  );

  return records.sort((a, b) => a.type.localeCompare(b.type));
}

/**
 * Reverse DNS lookup for IP addresses.
 *
 * @param {string} ip - IP address to lookup
 * @returns {Promise<string|null>} Hostname or null if not found
 */
async function reverseDns(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    return hostnames[0] || null;
  } catch {
    return null;
  }
}

/**
 * Get nameservers for a domain.
 *
 * @param {string} domain - Domain to query
 * @returns {Promise<string[]>} Array of nameserver hostnames
 */
async function getNameservers(domain) {
  try {
    const nsRecords = await dns.resolveNs(domain);
    return nsRecords;
  } catch {
    return [];
  }
}

/**
 * Get SOA record for a domain.
 *
 * @param {string} domain - Domain to query
 * @returns {Promise<object|null>} SOA record data
 */
async function getSoaRecord(domain) {
  try {
    const soa = await dns.resolveSoa(domain);
    return soa;
  } catch {
    return null;
  }
}

module.exports = {
  enumerateDnsRecords,
  reverseDns,
  getNameservers,
  getSoaRecord,
};
