# ReconCore v1.0

**Professional penetration testing suite — authorized use only**

ReconCore is a Node.js-based reconnaissance and vulnerability assessment toolkit designed for authorized penetration testing engagements. It provides structured, auditable security assessments compliant with PTES, OWASP WSTG, and MITRE ATT&CK v15 methodologies.

## ⚠️ Legal Notice

This tool is intended **exclusively for authorized security assessments**. You must have:

- Explicit written authorization from the asset owner
- A signed Rules of Engagement (RoE)
- A defined scope document (`config/scope.json`)

Unauthorized use against systems you do not own or lack permission to test is **illegal**. The authors accept no liability for misuse.

## Installation

```bash
git clone <repository-url>
cd reconcore
npm install
```

Requires **Node.js ≥ 20.0.0**.

## Quick Start

### 1. Configure Scope

Copy the example scope file and customize it:

```bash
cp config/scope.example.json config/scope.json
```

Edit `config/scope.json` with your engagement details:

```json
{
  "engagementId": "ENG-2025-0042",
  "client": "Acme Corporation",
  "authorizedBy": "Jane Smith, CISO",
  "testingWindow": {
    "start": "2025-11-01T08:00:00Z",
    "end": "2025-11-07T20:00:00Z"
  },
  "targets": {
    "domains": ["acme.example", "api.acme.example"],
    "cidr": ["203.0.113.0/28"]
  },
  "excludedHosts": ["prod-db.acme.example"],
  "maxConcurrency": 50,
  "ratePerSecond": 100
}
```

> **Important:** The `testingWindow` must encompass the current date/time. Out-of-window tests will be rejected.

### 2. Run an Assessment

```bash
# Full engagement (all phases)
npx reconcore scan target.example.com --scope ./config/scope.json

# Reconnaissance only
npx reconcore scan target.example.com --scope ./config/scope.json --mode recon

# Port scanning only
npx reconcore scan target.example.com --scope ./config/scope.json --mode scan

# Vulnerability assessment only (requires previous scan data)
npx reconcore scan target.example.com --scope ./config/scope.json --mode vuln

# Custom ports and output directory
npx reconcore scan target.example.com --scope ./config/scope.json \
  --ports 22,80,443,8080 --output ./reports/eng-0042
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-s, --scope <path>` | Path to scope.json (required) | `./config/scope.json` |
| `-m, --mode <mode>` | Scan mode: `full`, `recon`, `scan`, `vuln` | `full` |
| `-p, --ports <ports>` | Comma-separated ports or `"common"` | `common` |
| `-o, --output <dir>` | Output directory for reports | `./reports` |
| `--nvd-key <key>` | NIST NVD API key (recommended) | — |
| `--concurrency <n>` | Max concurrent probes | `50` |
| `--timeout <ms>` | Per-probe timeout in milliseconds | `1000` |

## Programmatic API

```js
const {
  ScopeGuard,
  scanPorts,
  enumerateSubdomains,
  enumerateDnsRecords,
  grabBanners,
  auditTls,
  auditHttpHeaders,
  matchVulnerabilities,
  generateReport,
  calculateSeverity,
} = require('reconcore');

// Enforce scope
const guard = new ScopeGuard(scopeConfig);
await guard.assertInScope('target.example.com');

// Scan
const openPorts = await scanPorts('target.example.com', [22, 80, 443]);

// Enumerate
const banners = await grabBanners('target.example.com', openPorts);
const tlsFindings = await auditTls('target.example.com', openPorts);

// Match CVEs
const vulns = await matchVulnerabilities(openPorts, banners, { nvdApiKey: '...' });

// Generate reports
await generateReport(engagementData, './reports');
```

## Architecture

```
src/
├── cli/           # CLI entry point (commander)
├── core/          # ScopeGuard, RateLimiter, Logger
├── enum/          # Banner grab, TLS audit, HTTP header audit
├── recon/         # DNS enumeration, subdomain brute, WHOIS
├── report/        # CVSS scoring, report generation (JSON/MD/HTML)
├── scan/          # TCP port scanner, service detection
└── vuln/          # NVD client, CVE matching, MITRE ATT&CK mapping
```

## Scope Enforcement

ReconCore enforces scope at the I/O layer via `ScopeGuard`:

- **Domain whitelist**: Only enumerated domains and their subdomains
- **CIDR ranges**: IP addresses must fall within authorized ranges
- **Excluded hosts**: Explicitly excluded assets are blocked even if they match allowed domains
- **Testing window**: Operations outside the authorized time range are refused
- **Private addresses**: RFC 1918/loopback IPs are blocked unless explicitly in scope
- **Audit logging**: All scope violations are logged with session ID and timestamp

## Vulnerability Scoring

- **CVSS v3.1** base scores mapped from NVD
- **Severity ratings**: CRITICAL (9.0–10.0), HIGH (7.0–8.9), MEDIUM (4.0–6.9), LOW (0.1–3.9), NONE (0.0)
- **MITRE ATT&CK v15** Enterprise TTP mapping per service

## Output

Reports are generated in three formats:

- **JSON** — for CI/CD pipeline integration and SIEM ingestion
- **Markdown** — for JIRA, Confluence, GitHub Issues
- **HTML** — for stakeholder distribution (includes CVSS scoring, severity matrix)

## Testing

```bash
npm test
```

## License

MIT — see [LICENSE](LICENSE) file.