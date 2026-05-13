// src/core/scope-guard.js
'use strict';

const { createHash } = require('node:crypto');
const net = require('node:net');
const dns = require('node:dns').promises;
const logger = require('./logger');

/**
 * ScopeGuard — enforces engagement scope at the I/O layer.
 *
 * Design principle: fail closed. If a target cannot be validated
 * as in-scope, all operations against it are refused and logged.
 */
class ScopeGuard {
  #scope;
  #allowedHosts;
  #allowedCidrs;
  #excludedHosts;
  #sessionId;

  constructor(scopeConfig) {
    this.#validateConfig(scopeConfig);
    this.#scope = scopeConfig;
    this.#allowedHosts = new Set(scopeConfig.targets.domains ?? []);
    this.#allowedCidrs = scopeConfig.targets.cidr ?? [];
    this.#excludedHosts = new Set(
      (scopeConfig.excludedHosts ?? []).map(h => h.toLowerCase().trim())
    );
    this.#sessionId = createHash('sha256')
      .update(`${scopeConfig.engagementId}:${Date.now()}`)
      .digest('hex')
      .slice(0, 12);

    logger.info('ScopeGuard initialized', {
      sessionId: this.#sessionId,
      engagementId: scopeConfig.engagementId,
      domainCount: this.#allowedHosts.size,
      cidrCount: this.#allowedCidrs.length,
      excludedCount: this.#excludedHosts.size,
    });
  }

  /**
   * Assert that a host is within the authorized scope.
   * Throws a ScopeViolationError if not — callers must not
   * catch and suppress this error.
   *
   * @param {string} host - Hostname or IP address to validate
   * @throws {ScopeViolationError}
   */
  async assertInScope(host) {
    const normalized = host.toLowerCase().trim();

    // Check exclusions first — fail closed: excluded hosts are never in scope
    if (this.#excludedHosts.has(normalized)) {
      this.#logViolation(normalized, 'Host explicitly excluded from scope');
      throw new ScopeViolationError(
        `Host "${normalized}" is explicitly excluded from scope. ` +
        `Engagement: ${this.#scope.engagementId}`
      );
    }

    // Check subdomain-level exclusions
    for (const excluded of this.#excludedHosts) {
      if (normalized === excluded || normalized.endsWith(`.${excluded}`)) {
        this.#logViolation(normalized, 'Host excluded (subdomain of excluded host)');
        throw new ScopeViolationError(
          `Host "${normalized}" falls under excluded scope "${excluded}". ` +
          `Engagement: ${this.#scope.engagementId}`
        );
      }
    }

    // Direct domain match
    if (this.#allowedHosts.has(normalized)) return;

    // Subdomain of allowed domain
    for (const domain of this.#allowedHosts) {
      if (normalized.endsWith(`.${domain}`)) return;
    }

    // IP resolution then CIDR check
    if (net.isIP(normalized)) {
      if (this.#isIpInCidrs(normalized)) return;
    } else {
      try {
        const { address } = await dns.lookup(normalized);
        if (this.#isIpInCidrs(address)) return;
      } catch {
        // DNS failure is not a scope pass
      }
    }

    // Explicitly deny private/reserved ranges unless listed
    if (this.#isPrivateAddress(normalized)) {
      this.#logViolation(normalized, 'Private address not in explicit scope');
      throw new ScopeViolationError(
        `Host "${normalized}" resolves to a private address not in scope. ` +
        `Add it explicitly to config/scope.json if authorized.`
      );
    }

    this.#logViolation(normalized, 'Host not in scope');
    throw new ScopeViolationError(
      `Host "${normalized}" is not within authorized scope. ` +
      `Engagement: ${this.#scope.engagementId}`
    );
  }

  get sessionId() { return this.#sessionId; }

  #validateConfig(config) {
    const required = ['engagementId', 'client', 'authorizedBy', 'testingWindow', 'targets'];
    for (const field of required) {
      if (!config[field]) {
        throw new Error(`scope.json is missing required field: "${field}"`);
      }
    }
    const now = new Date();
    const start = new Date(config.testingWindow.start);
    const end = new Date(config.testingWindow.end);
    if (now < start || now > end) {
      throw new Error(
        `Outside authorized testing window. ` +
        `Authorized: ${config.testingWindow.start} → ${config.testingWindow.end}`
      );
    }
  }

  #isIpInCidrs(ip) {
    for (const cidr of this.#allowedCidrs) {
      if (this.#ipInCidr(ip, cidr)) return true;
    }
    return false;
  }

  #ipInCidr(ip, cidr) {
    const [range, bits] = cidr.split('/');
    const mask = ~((1 << (32 - parseInt(bits, 10))) - 1);
    const ipInt = ip.split('.').reduce((acc, o) => ((acc << 8) | parseInt(o, 10)), 0);
    const rangeInt = range.split('.').reduce((acc, o) => ((acc << 8) | parseInt(o, 10)), 0);
    return (ipInt & mask) === (rangeInt & mask);
  }

  #isPrivateAddress(host) {
    const privateRanges = [/^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^127\./, /^::1$/];
    return privateRanges.some(r => r.test(host));
  }

  #logViolation(host, reason) {
    logger.warn('SCOPE_VIOLATION', {
      sessionId: this.#sessionId,
      host,
      reason,
      timestamp: new Date().toISOString(),
    });
  }
}

class ScopeViolationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScopeViolationError';
  }
}

module.exports = { ScopeGuard, ScopeViolationError };
