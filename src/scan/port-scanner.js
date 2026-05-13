// src/scan/port-scanner.js
'use strict';

const net = require('node:net');
const { RateLimiter } = require('../core/rate-limiter');
const logger = require('../core/logger');

// Common service CPE mappings for vulnerability matching
const SERVICE_MAP = {
  21:   { name: 'FTP',         cpe: 'cpe:2.3:a:*:ftp_server:*' },
  22:   { name: 'SSH',         cpe: 'cpe:2.3:a:openbsd:openssh:*' },
  23:   { name: 'Telnet',      cpe: 'cpe:2.3:a:*:telnet:*' },
  25:   { name: 'SMTP',        cpe: 'cpe:2.3:a:*:smtp:*' },
  53:   { name: 'DNS',         cpe: 'cpe:2.3:a:isc:bind:*' },
  80:   { name: 'HTTP',        cpe: 'cpe:2.3:a:*:http_server:*' },
  110:  { name: 'POP3',        cpe: 'cpe:2.3:a:*:pop3:*' },
  139:  { name: 'NetBIOS',     cpe: 'cpe:2.3:a:microsoft:netbios:*' },
  143:  { name: 'IMAP',        cpe: 'cpe:2.3:a:*:imap:*' },
  389:  { name: 'LDAP',        cpe: 'cpe:2.3:a:*:ldap:*' },
  443:  { name: 'HTTPS',       cpe: 'cpe:2.3:a:*:https:*' },
  445:  { name: 'SMB',         cpe: 'cpe:2.3:a:microsoft:smb:*' },
  993:  { name: 'IMAPS',      cpe: 'cpe:2.3:a:*:imaps:*' },
  995:  { name: 'POP3S',      cpe: 'cpe:2.3:a:*:pop3s:*' },
  1433: { name: 'MSSQL',       cpe: 'cpe:2.3:a:microsoft:sql_server:*' },
  1521: { name: 'Oracle DB',   cpe: 'cpe:2.3:a:oracle:database_server:*' },
  3306: { name: 'MySQL',       cpe: 'cpe:2.3:a:mysql:mysql:*' },
  3389: { name: 'RDP',         cpe: 'cpe:2.3:a:microsoft:rdp:*' },
  5432: { name: 'PostgreSQL',  cpe: 'cpe:2.3:a:postgresql:postgresql:*' },
  5900: { name: 'VNC',         cpe: 'cpe:2.3:a:realvnc:vnc:*' },
  6379: { name: 'Redis',       cpe: 'cpe:2.3:a:redis:redis:*' },
  8080: { name: 'HTTP-Alt',    cpe: 'cpe:2.3:a:*:http_server:*' },
  8443: { name: 'HTTPS-Alt',   cpe: 'cpe:2.3:a:*:https:*' },
  27017:{ name: 'MongoDB',     cpe: 'cpe:2.3:a:mongodb:mongodb:*' },
};

/**
 * Concurrent TCP port scanner with configurable timeout and rate limiting.
 *
 * @param {string} host          - Target hostname or IP (scope-validated by caller)
 * @param {number[]} ports       - Ports to scan
 * @param {object} options
 * @param {number} options.concurrency    - Max simultaneous probes (default: 50)
 * @param {number} options.timeout        - Per-port connect timeout ms (default: 1000)
 * @param {number} options.ratePerSecond  - Max new connections/sec (default: 100)
 * @returns {Promise<PortResult[]>}
 */
async function scanPorts(host, ports, options = {}) {
  const { concurrency = 50, timeout = 1000, ratePerSecond = 100 } = options;
  const limiter = new RateLimiter({ requestsPerSecond: ratePerSecond });
  const results = [];

  logger.info('[SCAN] Starting port scan', { host, portCount: ports.length, concurrency });

  const tasks = ports.map(port => async () => {
    await limiter.acquire();

    try {
      const result = await probePort(host, port, timeout);
      if (result.state === 'open') {
        const service = SERVICE_MAP[port] ?? { name: 'Unknown', cpe: null };
        const finding = { port, state: 'open', service: service.name, cpe: service.cpe };
        results.push(finding);
        logger.info(`[SCAN] Open port: ${port}/${service.name}`, { host });
      }
    } finally {
      limiter.release();
    }
  });

  await runConcurrent(tasks, concurrency);

  logger.info('[SCAN] Port scan complete', { host, openPorts: results.length });

  return results.sort((a, b) => a.port - b.port);
}

/**
 * Single port TCP probe. Returns state as 'open', 'closed', or 'filtered'.
 */
function probePort(host, port, timeoutMs) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let settled = false;

    const settle = state => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, state });
    };

    socket.setTimeout(timeoutMs);
    socket.on('connect', () => settle('open'));
    socket.on('timeout', () => settle('filtered'));
    socket.on('error', err =>
      settle(err.code === 'ECONNREFUSED' ? 'closed' : 'filtered')
    );

    socket.connect(port, host);
  });
}

async function runConcurrent(tasks, concurrency) {
  let index = 0;
  async function worker() {
    while (index < tasks.length) {
      await tasks[index++]();
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, worker));
}

module.exports = { scanPorts, SERVICE_MAP };
