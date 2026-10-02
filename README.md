<p align="center">
  <img src="assets/banner.png" alt="Phantom Recon Banner" width="800"/>
</p>

<h1 align="center">🔥 Phantom Recon</h1>

<p align="center">
  <strong>Advanced Penetration Testing & Reconnaissance Toolkit (v1.5.0)</strong>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge" alt="MIT License"/></a>
  <a href="#modules"><img src="https://img.shields.io/badge/modules-10+-red.svg?style=for-the-badge" alt="10+ Modules"/></a>
  <a href="#testing"><img src="https://img.shields.io/badge/tests-67%20passed-brightgreen.svg?style=for-the-badge" alt="67 Tests Passing"/></a>
  <a href="https://github.com/Tahir-Omicron/phantom-recon/stargazers"><img src="https://img.shields.io/github/stars/Tahir-Omicron/phantom-recon?style=for-the-badge&color=yellow" alt="Stars"/></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#whats-new-in-v150">What's New in v1.5.0</a> •
  <a href="#key-features">Key Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#modules">Modules & CLI</a> •
  <a href="#reporting-formats">Reporting Formats</a> •
  <a href="#testing">Testing</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## 🚀 What's New in v1.5.0

- 📧 **DNS Email Spoofing Defense (SPF & DMARC Audit)**:
  - Automated analysis of domain SPF policies (`+all` permissive critical flaw, `?all` neutral, `~all` softfail, `-all` strict).
  - DMARC policy inspection (`_dmarc.<domain>`) alerting on missing records and ineffective `p=none` policies that allow email forgery and BEC attacks.
- 🔐 **High-Fidelity DER Certificate Parsing (`cryptography.x509`)**:
  - Direct binary DER parsing resolving Python's standard `ssl.CERT_NONE` empty certificate dictionary limitation.
  - Extracts Subject, Issuer, Validity Period, Days Remaining, SANs, and Self-Signed indicators even on untrusted, expired, or private certificates.
- 🌐 **Cross-Site Tracing (XST / HTTP TRACE Method) Audit**:
  - Sends verifiable probe headers over HTTP `TRACE` to detect header reflection allowing `HttpOnly` cookie exfiltration (CVE-2004-2320).
- ⚡ **JavaScript Secrets & Hidden API Route Extractor**:
  - Automatically crawls and inspects client-side JavaScript bundles to extract hidden API endpoints (`/api/v1/...`, `/graphql`, `/rest/...`).
  - Scans for leaked developer tokens, including Google API keys (`AIza...`), AWS Access Keys (`AKIA...`), Slack Webhooks, and private RSA keys.
- 📋 **RFC 9116 `security.txt` Vulnerability Disclosure Parser**:
  - Scans `/.well-known/security.txt` and `/security.txt` to parse official bug bounty disclosure channels and contact points.
- ⏰ **Offset-Aware Timezone WHOIS Resilience**:
  - Eliminates naive/aware timezone subtraction crashes when processing domain expiration dates from major registrars.
- 🧪 **Expanded 67-Test Verification Suite**:
  - 67 passed automated unit tests validating 100% precision across all auditing and recon modules.

---

## 📖 About

**Phantom Recon** is a comprehensive, modular penetration testing and reconnaissance framework built in Python. Designed for security professionals, ethical hackers, and red team operators, it combines 10+ specialized modules into a single unified toolkit.

> ⚠️ **DISCLAIMER**: This tool is intended for **authorized security testing only**. Always obtain proper written authorization before testing any systems you do not own. Unauthorized access to computer systems is illegal. The developers assume no liability for misuse.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🛡️ **Zero False Positive Engine** | Soft-404 canary profiling, semantic regex matching, and dual-origin CORS reflection verification. |
| 🍪 **Cookie Security Auditor** | Identifies missing `Secure`, `HttpOnly`, and `SameSite` attributes on sensitive session cookies. |
| 🚨 **Subdomain Takeover Detector** | Detects dangling CNAME records pointing to unclaimed GitHub Pages, S3 buckets, and Heroku apps. |
| 🎨 **Enterprise Glassmorphism UI** | Dynamic SVG Security Score Gauge, live search, instant severity filtering, and 1-click cURL copy. |
| 🎯 **Exact Location Tracing** | Pinpoints exact affected parameters (`q`), response headers (`CSP`), or URL paths (`/.env`). |
| 🔗 **Clickable Jump Links** | Interactive direct reproduction URLs (`target="_blank"`) in both terminal and HTML reports. |
| 📋 **1-Click PoC cURL Reproduction** | One-click copyable `curl` commands with animated toast notifications for verification. |
| 🔍 **Port Scanning** | Multi-threaded TCP Connect and UDP scanning with service detection and banner grabbing. |
| 🌐 **Web Reconnaissance** | Technology stack fingerprinting, directory brute force, form detection, and JS discovery. |
| 📡 **DNS Enumeration** | Full DNS record lookup (`A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`), zone transfer, and wildcard detection. |
| 🔎 **Subdomain Discovery** | Multi-threaded brute force, Certificate Transparency (crt.sh) logs, and DNS resolution. |
| 🔐 **SSL/TLS Cryptographic Analysis** | Certificate validation, cipher enumeration, protocol inspection, and expiry warnings. |
| 🔑 **Brute Force Engine** | Rate-limited credential auditing for SSH, FTP, and HTTP Basic/Form authentication. |
| 🗺️ **Network Mapping** | Local host discovery, ARP scanning, and ICMP/TCP traceroute. |
| 📋 **WHOIS Registration Lookup** | Domain and IP registrar intelligence. |
| 📊 **Multi-Format Reporting** | HTML, CSV (Excel-ready), Markdown, JSON, and Plain Text deliverables. |

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Tahir-Omicron/phantom-recon.git
cd phantom-recon

# Install in development mode
pip install -e ".[dev]"

# Run your first port scan
phantom scan --target 192.168.1.1 --ports 1-1000

# Run a vulnerability audit with interactive HTML report
phantom vuln --url https://example.com --output audit_report.html

# Run the complete 8-step full reconnaissance pipeline
phantom full --target example.com --output full_report.html
```

---

## 📦 Installation

### Prerequisites

- **Python 3.9+** (tested on 3.9, 3.10, 3.11, 3.12)
- **pip** package manager
- **Git** for repository cloning
- **Nmap** *(optional, enhances port scanning speed)*

### Method 1: Install from Source (Recommended)

```bash
git clone https://github.com/Tahir-Omicron/phantom-recon.git
cd phantom-recon

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install package
pip install -e .

# Verify installation
phantom --version
```

### Method 2: Development Mode with Test Suite

```bash
git clone https://github.com/Tahir-Omicron/phantom-recon.git
cd phantom-recon
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS

# Install with development & testing dependencies
pip install -e ".[dev]"

# Run the test suite
pytest tests/ -v
```

---

## 🧩 Modules & CLI Reference

### 1. 🔍 Port Scanner (`phantom scan`)

Multi-threaded port scanner with service banner identification.

```bash
# Top 1000 ports
phantom scan --target 192.168.1.1

# Specific ports with 100 threads
phantom scan --target 10.0.0.1 --ports 22,80,443,8080 --threads 100

# UDP scanning
phantom scan --target 10.0.0.1 --type udp --ports 53,161
```

### 2. 🛡️ Vulnerability Scanner (`phantom vuln`)

Ultra-precision vulnerability scanner with zero false positives.

```bash
# Full precision vulnerability audit
phantom vuln --url https://example.com

# Direct export to interactive HTML dashboard
phantom vuln --url https://example.com --output report.html

# Export directly to CSV for Jira / Excel
phantom vuln --url https://example.com --format csv --output findings.csv

# Export directly to Markdown for Bug Bounty reports
phantom vuln --url https://example.com --format md --output report.md
```

**Verified Checks:**
- 🔴 **Sensitive File Disclosure**: `.env`, `.git/HEAD`, `.git/config`, `phpinfo.php`, `backup.sql`, `.DS_Store`
- 🔴 **Reflected XSS**: Real HTML-context reflection without encoding
- 🟠 **CORS Misconfigurations**: Dual-origin reflection, wildcard credential sharing, `Origin: null` trust
- 🟡 **Clickjacking**: Missing both `X-Frame-Options` and `frame-ancestors` on HTML pages
- 🟡 **Insecure Directory Listing**: Server-indexed `/uploads/`, `/static/`, `/backup/` paths
- 🟡 **Open Redirect**: Validated external redirection targets
- 🔵 **Cookie Security**: Missing `Secure`, `HttpOnly`, and `SameSite` flags
- 🔵 **Security Headers**: Missing `HSTS`, `CSP`, `X-Content-Type-Options`, `COOP`, `COEP`
- 🔵 **Information Disclosure**: Detailed server version leaks in headers

### 3. 🌐 Web Reconnaissance (`phantom recon`)

Web application fingerprinting and surface mapping.

```bash
# Full web reconnaissance
phantom recon --url https://example.com --full

# Technology stack fingerprinting only
phantom recon --url https://example.com --tech

# Directory path discovery
phantom recon --url https://example.com --dirs
```

### 4. 🔎 Subdomain Discovery (`phantom subdomain`)

Find subdomains and detect takeover risks.

```bash
# Brute force using built-in wordlist
phantom subdomain --domain example.com

# Certificate Transparency log search
phantom subdomain --domain example.com --ct-logs

# Custom wordlist with high concurrency
phantom subdomain --domain example.com --wordlist wordlists/subdomains.txt --threads 50
```

### 5. 📡 DNS Enumeration (`phantom dns`)

Enumerate DNS records and test for zone transfers.

```bash
# All DNS record types
phantom dns --domain example.com --type all

# Specific record types
phantom dns --domain example.com --type a,mx,ns,txt

# Test for DNS zone transfer (AXFR)
phantom dns --domain example.com --zone-transfer
```

### 6. 🔐 SSL/TLS Cryptographic Analysis (`phantom ssl`)

Inspect SSL/TLS certificate chains, protocols, and ciphers.

```bash
# Standard HTTPS inspection
phantom ssl --host example.com

# Custom port
phantom ssl --host example.com --port 8443
```

### 7. 🔑 Multi-Protocol Brute Force (`phantom brute`)

Rate-limited authentication auditing.

```bash
# SSH brute force
phantom brute --target 192.168.1.1 --service ssh --userlist users.txt --passlist passwords.txt

# FTP credential test
phantom brute --target ftp.example.com --service ftp --userlist users.txt --passlist passwords.txt

# HTTP Basic Auth test
phantom brute --target https://example.com/admin --service http --userlist users.txt --passlist passwords.txt
```

### 8. 🗺️ Network Mapper (`phantom network`)

Local network host discovery and traceroute.

```bash
# Host discovery across CIDR subnet
phantom network --target 192.168.1.0/24 --discover

# Route hop tracing
phantom network --target 8.8.8.8 --traceroute
```

### 9. 📋 WHOIS Intelligence (`phantom whois`)

Registrar, creation, expiration, and nameserver lookup.

```bash
phantom whois --target example.com
```

### 10. 📊 Multi-Format Report Generator (`phantom report`)

Convert scan data into professional reports.

```bash
# Generate Interactive HTML Dashboard
phantom report --input scan.json --format html --output report.html

# Generate Excel-ready CSV
phantom report --input scan.json --format csv --output report.csv

# Generate GitHub/Bug Bounty Markdown
phantom report --input scan.json --format md --output report.md

# Generate Plain Text
phantom report --input scan.json --format txt --output report.txt
```

### 11. 🎯 Master Recon Pipeline (`phantom full`)

Execute all 8 modules in sequence:

```bash
phantom full --target example.com --output phantom_report.html
```

**Pipeline Steps:**
1. WHOIS Lookup
2. DNS Enumeration
3. Subdomain Discovery & Takeover Inspection
4. Port Scanning & Service Identification
5. Web Application Reconnaissance (Tech stack, directories, forms)
6. Security Header Analysis
7. SSL/TLS Cryptographic Analysis
8. Ultra-Precision Vulnerability Scan (Zero False Positive)

---

## 📊 Reporting Formats

Phantom Recon offers enterprise reporting tailored for different stakeholders:

1. **Interactive HTML Dashboard**:
   - Cyberpunk dark glassmorphism aesthetic (`backdrop-filter: blur(24px)`).
   - SVG Dynamic Security Score Ring (0–100 calculated from findings).
   - Real-time client-side keyword search & severity filter buttons (`All`, `Critical`, `High`, `Medium`, `Low`, `Info`).
   - 1-click PoC cURL copy buttons with animated toast alerts.
   - In-browser **Export CSV**, **Export JSON**, and **Print / PDF** buttons.
2. **CSV Deliverable**:
   - Encoded in `UTF-8 with BOM` (`utf-8-sig`) so that Microsoft Excel, Google Sheets, Jira, and DefectDojo display characters cleanly.
   - Comprehensive columns: Title, Severity, CVSS, Location, Direct URL, PoC cURL, Evidence, Remediation.
3. **Markdown Report**:
   - Executive summary table, severity breakdown badges, and clean code blocks ready for GitHub issues and Bug Bounty reports.
4. **JSON & Plain Text**:
   - Machine-readable structured payloads for SIEM pipelines and CI/CD integration.

---

## 🧪 Testing

Phantom Recon features a rigorous test suite covering zero-false-positive guards, validators, parsers, and report generation:

```bash
pytest tests/ -v
```

```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1
collected 67 items

tests/test_scanner.py .............                                      [ 19%]
tests/test_validators.py ..............................                  [ 64%]
tests/test_vuln_scanner.py ........................                      [100%]

============================= 67 passed in 1.73s ==============================
```

---

## 🏗️ Project Architecture

```
phantom-recon/
├── 📄 pyproject.toml               # Build configuration & dependency definitions
├── 📄 README.md                    # Documentation & user guide
├── 📄 LICENSE                      # MIT License
├── 📄 CONTRIBUTING.md              # Contribution standards
├── 📄 SECURITY.md                  # Responsible disclosure policy
│
├── 🔥 phantom_recon/               # Core framework package
│   ├── __init__.py                 # Version & package exports (v1.5.0)
│   ├── cli.py                      # Click CLI entry point
│   │
│   ├── 🧠 core/                    # Specialized scanning engines
│   │   ├── scanner.py              # Multi-threaded TCP/UDP port scanner
│   │   ├── vuln_scanner.py         # Zero False Positive Vulnerability Scanner
│   │   ├── web_recon.py            # Web application reconnaissance & fingerprinting
│   │   ├── subdomain.py            # Subdomain discovery & takeover detection
│   │   ├── dns_enum.py             # DNS enumeration & zone transfer audit
│   │   ├── header_analyzer.py      # HTTP security header grader
│   │   ├── ssl_analyzer.py         # SSL/TLS cryptographic cipher inspector
│   │   ├── network.py              # ARP discovery & traceroute mapper
│   │   ├── brute.py                # Multi-protocol credential auditor
│   │   └── whois_lookup.py         # Domain & IP WHOIS intelligence
│   │
│   ├── 🛠️ utils/                   # Shared utilities
│   │   ├── logger.py               # Rich terminal formatting & tables
│   │   ├── validators.py           # Strict IP/CIDR/Domain/URL validators
│   │   └── config.py               # YAML configuration loader
│   │
│   └── 📊 reporting/               # Multi-format report generators
│       ├── report_generator.py     # HTML, CSV, Markdown, JSON, TXT engine
│       └── templates.py            # Dark glassmorphism dashboard template
│
├── 🧪 tests/                       # Automated test suite
│   ├── test_scanner.py             # Port scanner unit tests
│   ├── test_validators.py          # Input validator tests
│   └── test_vuln_scanner.py        # Zero false positive & reporting tests
│
└── 📁 wordlists/                   # Curated offline wordlists
    ├── subdomains.txt              # Subdomain discovery dictionary
    ├── directories.txt             # Web path enumeration dictionary
    └── credentials.txt             # Common default credentials dictionary
```

---

## 🤝 Contributing

Contributions are warmly welcomed! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests:

1. 🍴 Fork the repository: `https://github.com/Tahir-Omicron/phantom-recon`
2. 🔧 Create a feature branch: `git checkout -b feature/amazing-feature`
3. 💾 Commit changes: `git commit -m 'feat: add amazing feature'`
4. 📤 Push to your branch: `git push origin feature/amazing-feature`
5. 📬 Open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Legal Disclaimer

**Phantom Recon** is strictly developed for **authorized security assessments, penetration testing, and defensive auditing**. Conducting security scans against targets without prior written authorization is illegal. The developers assume no liability for misuse of this tool.

---

<p align="center">
  <strong>Built with ❤️ by <a href="https://github.com/Tahir-Omicron">Tahir</a></strong>
</p>

<p align="center">
  <sub>🔐 Hack Responsibly. Stay Ethical. 🔐</sub>
</p>
