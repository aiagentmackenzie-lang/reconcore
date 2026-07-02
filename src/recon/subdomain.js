// src/recon/subdomain.js
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { RateLimiter } = require('../core/rate-limiter');
const logger = require('../core/logger');
const { enumerateDnsRecords } = require('./dns');

/**
 * Subdomain enumeration via DNS resolution against a wordlist.
 * Uses adaptive rate limiting to avoid triggering DNS-based defenses.
 */
async function enumerateSubdomains(domain, scopeGuard, options = {}) {
  const {
    wordlistPath = path.join(__dirname, '../../wordlists/subdomains-top100.txt'),
    concurrency = 20,
    recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT'],
    timeout = 3000,
  } = options;

  const wordlist = await loadWordlist(wordlistPath);
  const limiter = new RateLimiter({ requestsPerSecond: concurrency });
  const findings = [];

  logger.info('[RECON] Starting subdomain enumeration', {
    domain,
    wordlistSize: wordlist.length,
    concurrency,
  });

  // Base domain DNS record enumeration
  const baseRecords = await enumerateDnsRecords(domain, recordTypes);
  if (baseRecords.length) {
    findings.push({ host: domain, records: baseRecords, isBase: true });
  }

  // Concurrent subdomain resolution with rate limiting
  const tasks = wordlist.map(word => async () => {
    const candidate = `${word}.${domain}`;

    try {
      await scopeGuard.assertInScope(candidate);
    } catch {
      return; // Skip out-of-scope candidates silently
    }

    await limiter.acquire();

    try {
      const records = await Promise.race([
        enumerateDnsRecords(candidate, ['A', 'AAAA', 'CNAME']),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeout)),
      ]);

      if (records.length) {
        findings.push({ host: candidate, records });
        logger.info(`[RECON] Subdomain found: ${candidate}`, { records });
      }
    } catch (err) {
      if (err.code !== 'ENOTFOUND' && err.message !== 'timeout') {
        logger.debug(`[RECON] DNS error for ${candidate}`, { error: err.code });
      }
    } finally {
      limiter.release();
    }
  });

  // Run with bounded concurrency
  await runConcurrent(tasks, concurrency);

  logger.info(`[RECON] Subdomain enumeration complete`, {
    domain,
    discovered: findings.length,
  });

  return findings;
}

/**
 * Load wordlist from file.
 * @private
 */
async function loadWordlist(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    return content.split('\n').map(l => l.trim()).filter(Boolean);
  } catch (err) {
    logger.warn(`[RECON] Failed to load wordlist: ${filePath}`, { error: err.message });
    return [];
  }
}

/**
 * Run tasks with bounded concurrency.
 * @private
 */
async function runConcurrent(tasks, concurrency) {
  let index = 0;

  async function worker() {
    while (index < tasks.length) {
      const taskIndex = index++;
      await tasks[taskIndex]();
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, worker);
  await Promise.all(workers);
}

module.exports = { enumerateSubdomains };
