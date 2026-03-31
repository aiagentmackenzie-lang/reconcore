# ⚔️ ReconCore — Professional Penetration Testing Suite

> **EDUCATIONAL AND AUTHORIZED USE ONLY**

A modular, PTES-aligned penetration testing framework built for authorized security assessments. This tool is designed for **cybersecurity education, research, and authorized penetration testing** only.

---

## ⚠️ LEGAL NOTICE

**This tool may only be used on systems for which you have explicit, documented written authorization.**

Using ReconCore against systems without authorization may violate:
- Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030 (USA)
- Computer Misuse Act 1990 (UK)
- Lei 12.737/2012 — Lei Carolina Dieckmann (Brazil)
- EU Directive on Attacks Against Information Systems (2013/40/EU)
- Similar laws in virtually every jurisdiction worldwide

**By using this software, you agree to:**
- Only use it on systems you own or have explicit written permission to test
- Take full responsibility for any misuse
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices

---

## 🎯 Purpose

This project was created for:
- **Cybersecurity education** — Learning PTES methodology, reconnaissance techniques, and vulnerability assessment
- **Security research** — Understanding attack surface discovery in controlled environments
- **Authorized testing** — Supporting legitimate penetration testing engagements with proper scope enforcement

---

## 🏛️ Methodology Alignment

| Module | Standard | Purpose |
|--------|----------|---------|
| Reconnaissance | PTES Phase 2 | Intelligence Gathering |
| Scanning | OWASP WSTG | Network Service Discovery |
| Enumeration | MITRE ATT&CK | Discovery (TA0007) |
| Vulnerability Analysis | CVSS v3.1 | Risk Scoring |

---

## 🚀 Installation

### Prerequisites
- Node.js >= 20.x
- npm >= 10.x

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/reconcore.git
cd reconcore

# Install dependencies
npm install

# Copy scope template
cp config/scope.example.json config/scope.json
```

---

## 🛡️ Scope Enforcement

ReconCore **requires** a scope configuration file before any scan will run. This is a safety feature to prevent accidental scanning of unauthorized targets.

The tool will **refuse to start** without:
- A valid `scope.json` file
- Properly defined testing window
- Explicitly authorized target domains/IPs

See `config/scope.example.json` for the required format.

---

## 📖 Usage

### Command Line
```bash
# Full engagement (all phases)
node src/cli/index.js scan authorized-target.example \
  --scope ./config/scope.json \
  --mode full

# Reconnaissance only
node src/cli/index.js scan authorized-target.example \
  --scope ./config/scope.json \
  --mode recon

# Port scan only
node src/cli/index.js scan authorized-target.example \
  --scope ./config/scope.json \
  --mode scan
```

### Programmatic API
```javascript
const { ScopeGuard, scanPorts, generateReport } = require('reconcore');

// Use in your own security tools
const guard = new ScopeGuard(scopeConfig);
await guard.assertInScope(target);
const results = await scanPorts(target, ports);
```

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Run scope enforcement tests (security-critical)
npm run test:scope
```

---

## 📁 Project Structure

```
reconcore/
├── src/
│   ├── core/          # ScopeGuard, rate limiting, logging
│   ├── recon/         # DNS, subdomain enumeration, WHOIS
│   ├── scan/          # Port scanning, service detection
│   ├── enum/          # Banner grabbing, TLS, HTTP headers
│   ├── vuln/          # CVE matching, CVSS, ATT&CK mapping
│   ├── report/        # JSON, Markdown, HTML report generation
│   ├── cli/           # Command-line interface
│   └── index.js       # Programmatic API entry
├── config/            # Scope configuration (not committed)
├── tests/             # Unit tests
└── wordlists/         # Subdomain and port lists
```

---

## 🔒 Security Features

- **Fail-closed scope enforcement** — No I/O without authorization
- **Rate limiting** — Prevents overwhelming target systems
- **Audit logging** — All operations logged with session IDs
- **Private IP blocking** — RFC 1918 addresses blocked unless explicitly scoped
- **Testing window validation** — Enforces engagement timeframes

---

## ⚖️ License

MIT License — See [LICENSE](LICENSE)

**Important:** This software is provided "as is" for educational and authorized testing purposes. The authors assume no liability for misuse or damage caused by this tool.

---

## 🙏 Acknowledgments

- PTES (Penetration Testing Execution Standard)
- OWASP Web Security Testing Guide
- MITRE ATT&CK Framework
- NIST NVD (National Vulnerability Database)
- FIRST CVSS Specification

---

## 📧 Contact

For questions about this educational project, please open an issue.

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
