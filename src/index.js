// src/index.js
'use strict';

/**
 * ReconCore — Professional penetration testing suite
 * Programmatic API entry point
 *
 * @example
 * const { ScopeGuard, scanPorts, generateReport } = require('reconcore');
 */

// Core modules
const { ScopeGuard, ScopeViolationError, RateLimiter, logger } = require('./core');

// Recon modules
const {
  enumerateDnsRecords,
  reverseDns,
  getNameservers,
  getSoaRecord,
  enumerateSubdomains,
  whoisLookup,
  asnLookup,
} = require('./recon');

// Scan modules
const { scanPorts, SERVICE_MAP, detectService, detectServices } = require('./scan');

// Enum modules
const { grabBanners, auditTls, auditHttpHeaders } = require('./enum');

// Vuln modules
const { matchVulnerabilities, NvdClient, mapToAttck } = require('./vuln');

// Report modules
const { calculateSeverity, buildSeverityMatrix, SEVERITY_RATINGS, generateReport } = require('./report');

module.exports = {
  // Core
  ScopeGuard,
  ScopeViolationError,
  RateLimiter,
  logger,

  // Recon
  enumerateDnsRecords,
  reverseDns,
  getNameservers,
  getSoaRecord,
  enumerateSubdomains,
  whoisLookup,
  asnLookup,

  // Scan
  scanPorts,
  SERVICE_MAP,
  detectService,
  detectServices,

  // Enum
  grabBanners,
  auditTls,
  auditHttpHeaders,

  // Vuln
  matchVulnerabilities,
  NvdClient,
  mapToAttck,

  // Report
  calculateSeverity,
  buildSeverityMatrix,
  SEVERITY_RATINGS,
  generateReport,
};
