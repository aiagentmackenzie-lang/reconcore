#!/usr/bin/env node
// src/cli/index.js
'use strict';

const { Command } = require('commander');
const path = require('node:path');
const fs = require('node:fs');

const { ScopeGuard } = require('../core/scope-guard');
const { enumerateSubdomains } = require('../recon/subdomain');
const { scanPorts } = require('../scan/port-scanner');
const { grabBanners } = require('../enum/banner');
const { auditTls } = require('../enum/tls');
const { auditHttpHeaders } = require('../enum/http-headers');
const { matchVulnerabilities } = require('../vuln/vuln-matcher');
const { generateReport } = require('../report/reporter');
const logger = require('../core/logger');

const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 139, 143, 389,
  443, 445, 993, 995, 1433, 1521, 3306, 3389,
  5432, 5900, 6379, 8080, 8443, 27017,
];

const program = new Command();

program
  .name('reconcore')
  .description('ReconCore — Professional penetration testing suite (authorized use only)')
  .version('1.0.0');

program
  .command('scan <target>')
  .description('Run a full-scope engagement against an authorized target')
  .requiredOption('-s, --scope <path>', 'Path to scope.json (required)', './config/scope.json')
  .option('-m, --mode <mode>', 'Scan mode: full | recon | scan | vuln', 'full')
  .option('-p, --ports <ports>', 'Comma-separated ports or "common"', 'common')
  .option('-o, --output <dir>', 'Output directory for reports', './reports')
  .option('--nvd-key <key>', 'NIST NVD API key (recommended for higher rate limits)')
  .option('--concurrency <n>', 'Max concurrent probes', '50')
  .option('--timeout <ms>', 'Per-probe timeout in ms', '1000')
  .action(async (target, options) => {
    console.log('\n  ⚔️  ReconCore v1.0 — Authorized Security Assessment\n');

    // 1. Load and validate scope
    const scopePath = path.resolve(options.scope);
    if (!fs.existsSync(scopePath)) {
      console.error(`[ERROR] scope.json not found at: ${scopePath}`);
      console.error(`        Copy config/scope.example.json → config/scope.json and fill it in.`);
      process.exit(1);
    }

    let scopeConfig;
    try {
      scopeConfig = JSON.parse(fs.readFileSync(scopePath, 'utf8'));
    } catch (err) {
      console.error(`[ERROR] Invalid scope.json: ${err.message}`);
      process.exit(1);
    }

    // 2. Initialize ScopeGuard — this validates the testing window
    let scopeGuard;
    try {
      scopeGuard = new ScopeGuard(scopeConfig);
    } catch (err) {
      console.error(`[SCOPE ERROR] ${err.message}`);
      process.exit(1);
    }

    // 3. Validate target is in scope before any I/O
    try {
      await scopeGuard.assertInScope(target);
    } catch (err) {
      console.error(`[SCOPE VIOLATION] ${err.message}`);
      process.exit(1);
    }

    const concurrency = parseInt(options.concurrency, 10);
    const timeout = parseInt(options.timeout, 10);
    const ports = options.ports === 'common'
      ? DEFAULT_PORTS
      : options.ports.split(',').map(Number).filter(Boolean);

    const engagementData = {
      scope: scopeConfig,
      sessionId: scopeGuard.sessionId,
      subdomains: [],
      openPorts: [],
      banners: [],
      tlsFindings: [],
      headerFindings: [],
      vulnFindings: [],
    };

    try {
      // Phase 1: Reconnaissance
      if (['full', 'recon'].includes(options.mode)) {
        console.log('[1/5] Reconnaissance — subdomain enumeration...');
        engagementData.subdomains = await enumerateSubdomains(target, scopeGuard, { concurrency });
        console.log(`      ✓ ${engagementData.subdomains.length} subdomains discovered`);
      }

      // Phase 2: Scanning
      if (['full', 'scan'].includes(options.mode)) {
        console.log('[2/5] Scanning — port and service discovery...');
        engagementData.openPorts = await scanPorts(target, ports, { concurrency, timeout });
        console.log(`      ✓ ${engagementData.openPorts.length} open ports found`);
      }

      // Phase 3: Enumeration
      if (['full'].includes(options.mode)) {
        console.log('[3/5] Enumeration — banners, TLS, HTTP headers...');
        const httpPorts = engagementData.openPorts.filter(p => [80, 443, 8080, 8443].includes(p.port));

        engagementData.banners = await grabBanners(target, engagementData.openPorts);
        engagementData.tlsFindings = await auditTls(target, engagementData.openPorts);
        engagementData.headerFindings = await auditHttpHeaders(target, httpPorts);
        console.log(`      ✓ ${engagementData.banners.length} banners grabbed`);
      }

      // Phase 4: Vulnerability Matching
      if (['full', 'vuln'].includes(options.mode)) {
        console.log('[4/5] Vulnerability analysis — CVE/CVSS matching...');
        engagementData.vulnFindings = await matchVulnerabilities(
          engagementData.openPorts,
          engagementData.banners,
          { nvdApiKey: options.nvdKey }
        );
        console.log(`      ✓ ${engagementData.vulnFindings.length} CVEs matched`);
      }

      // Phase 5: Reporting
      console.log('[5/5] Generating engagement report...');
      await generateReport(engagementData, options.output);

    } catch (err) {
      if (err.name === 'ScopeViolationError') {
        console.error(`\n[SCOPE VIOLATION] ${err.message}`);
        process.exit(1);
      }
      logger.error('Engagement error', { error: err.message, stack: err.stack });
      console.error(`\n[ERROR] ${err.message}`);
      process.exit(1);
    }
  });

program.parse(process.argv);
