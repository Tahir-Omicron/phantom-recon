<p align="center">
  <img src="assets/banner.png" alt="Phantom Recon Banner" width="800"/>
</p>

<h1 align="center">🔥 Phantom Recon</h1>

<p align="center">
  <strong>Advanced Penetration Testing & Reconnaissance Toolkit (v1.5.2)</strong>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge" alt="MIT License"/></a>
  <a href="#modules"><img src="https://img.shields.io/badge/modules-11+-red.svg?style=for-the-badge" alt="11+ Modules"/></a>
  <a href="#testing"><img src="https://img.shields.io/badge/tests-84%20passed-brightgreen.svg?style=for-the-badge" alt="84 Tests Passing"/></a>
  <a href="https://github.com/Tahir-Omicron/phantom-recon/stargazers"><img src="https://img.shields.io/github/stars/Tahir-Omicron/phantom-recon?style=for-the-badge&color=yellow" alt="Stars"/></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#whats-new-in-v152">What's New in v1.5.2</a> •
  <a href="#release-history">Release History</a> •
  <a href="#key-features">Key Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#modules">Modules & CLI</a> •
  <a href="#reporting-formats">Reporting Formats</a> •
  <a href="#testing">Testing</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## 🚀 What's New in v1.5.2

- 🛡️ **Web Application Firewall (WAF) & Cloud CDN Edge Proxy Detection**:
  - Automatically identifies whether target domains or resolved IP addresses belong to cloud security edge proxies (Cloudflare, Akamai, AWS CloudFront / AWS WAF, Imperva / Incapsula, Fastly, Sucuri CloudProxy, F5 BIG-IP, ModSecurity, Azure Front Door, Barracuda).
  - Precompiled IPv4 CIDR blocks allow instant zero-latency network matching before firing any network requests.
- ⚠️ **Edge Proxy Reconnaissance Protection ("Don't Hit a Wall")**:
  - Automatically warns operators when port scanning target IPs (`phantom scan`): prevents false-alarm scans where open ports (80, 443, 8080, 8443) belong to cloud Anycast edge nodes rather than the client's internal origin server.
- 🚨 **Unproxied Backend Origin IP Leakage Audit (WAF Bypass Vector)**:
  - Audits DNS MX records, SPF TXT `ip4:` declarations, and common unproxied subdomains (`mail`, `direct`, `origin`, `ftp`, `cpanel`, `dev`, `vpn`).
  - Flags direct backend server IPs that bypass cloud WAF inspection (CWE-200) as High-severity findings with reproducible cURL commands and firewall remediation guidance.
- 💻 **Dedicated CLI Command (`phantom waf`) & Full Pipeline Integration**:
  - Run standalone WAF audits with `phantom waf -t <target>`.
  - Upgraded master reconnaissance pipeline (`phantom full`) into a comprehensive **9-step audit**.
- 🧪 **Comprehensive Automated Verification (84 Tests Passing)**:
  - 84 automated unit tests verifying CIDR matching, HTTP fingerprinting, origin leakage discovery, and report generation.

---

## 📜 Release History & Changelog (v1.0.0 — v1.5.2)

| Version | Release Focus | Key Additions & Fixes |
| :--- | :--- | :--- |
| **v1.5.2** | **WAF/CDN & Origin IP Engine** | • Cloud WAF & CDN Edge Proxy detector across 10 major providers.<br>• Zero-request IPv4 CIDR matching for Cloudflare, Fastly, Imperva, Sucuri, Akamai.<br>• Port scanner warning when probing cloud Anycast edge nodes.<br>• Passive backend origin IP discovery via MX, SPF, and unproxied subdomains.<br>• New CLI command `phantom waf` & 9-step master pipeline.<br>• Expanded test suite to **84 passing tests**. |
| **v1.5.1** | **Precision Hardening & UX** | • Subdomain DMARC inheritance fallback (RFC 7489).<br>• Soft-404 guard on HTTP TRACE (XST) checking.<br>• Enhanced CLI outputs for DNS email defense and Web Recon JS secrets.<br>• Expanded test suite to **69 passing tests**. |
| **v1.5.0** | **Email Security, DER SSL & JS Recon** | • DNS Email Spoofing Defense (automated SPF & DMARC policy auditor).<br>• High-fidelity DER certificate binary parser (`cryptography.x509`) fixing Python `CERT_NONE` empty dictionary limitation.<br>• Cross-Site Tracing (XST / HTTP TRACE) detection.<br>• JavaScript crawler extracting hidden API routes and exposed credentials (Google API keys, AWS keys, Slack webhooks, RSA keys).<br>• RFC 9116 `security.txt` parser.<br>• Fixed WHOIS offset-aware timezone datetime subtraction crash. |
| **v1.4.0** | **Cookie Audits & Subdomain Takeover** | • Missing Cookie Security Audit (`Secure`, `HttpOnly`, `SameSite`).<br>• Subdomain Takeover detector across 6 cloud platforms (GitHub Pages, AWS S3, Heroku, Azure, Shopify, Zendesk).<br>• Advanced CORS `Origin: null` sandboxed iframe audit.<br>• Fixed Windows PowerShell UTF-8 charmap encoding crashes.<br>• Suppressed unverified TLS warnings for clean CLI output.<br>• Comprehensive documentation and README overhaul. |
| **v1.3.0** | **Enterprise Multi-Format Reporting** | • CSV report export with UTF-8 BOM for Microsoft Excel and Jira.<br>• GitHub-flavored Markdown report export for Bug Bounty triage.<br>• In-browser `Export CSV` and `Export JSON` buttons inside the HTML dashboard.<br>• Zero-false-positive directory listing detection (`/uploads/`, `/static/`, etc.) and backup SQL dump detection.<br>• Unified 8-step master reconnaissance pipeline (`phantom full`). |
| **v1.2.0** | **Zero-False-Positive Engine & UI** | • Zero-False-Positive architecture: Soft-404 canary profiling, semantic regex matching, and double-check reflection.<br>• Enterprise dark glassmorphism dashboard with dynamic SVG Security Health Gauge.<br>• Live search and instant severity filtering in HTML reports. |
| **v1.1.0** | **Exact Location Tracing & 1-Click PoC** | • Exact vulnerability location tracing (specific parameter, header, or URL path).<br>• Interactive direct jump links (`target="_blank"`) in CLI and HTML.<br>• 1-Click copyable PoC cURL reproduction commands with toast alerts. |
| **v1.0.0** | **Initial Foundation Release** | • Multi-threaded TCP Connect & UDP port scanner.<br>• Subdomain finder (DNS brute-force & Certificate Transparency logs).<br>• DNS record enumerator (A, AAAA, MX, NS, TXT, SOA) & zone transfer checker.<br>• SSL/TLS cipher & protocol inspector.<br>• HTTP security header grader (A-F).<br>• Network mapping (ping sweep & traceroute).<br>• Multi-protocol credential brute forcer (SSH, FTP, HTTP).<br>• WHOIS domain and IP intelligence lookup. |

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

Multi-threaded port scanner with service banner identification and WAF proxy detection.

```bash
# Top 1000 ports
phantom scan --target 192.168.1.1

# Specific ports with 100 threads
phantom scan --target 10.0.0.1 --ports 22,80,443,8080 --threads 100

# UDP scanning
phantom scan --target 10.0.0.1 --type udp --ports 53,161
```
> 💡 *Note: If the target IP belongs to a Cloud CDN/WAF proxy network (such as Cloudflare or Akamai), the scanner automatically prints a prominent notice warning you that port scanning targets Anycast edge nodes rather than internal backend origin hosts.*

### 2. 🛡️ WAF & Cloud CDN Detector and Origin IP Discovery (`phantom waf`)

Detects cloud security edge proxies and audits for direct unproxied backend origin IP leakage (WAF Bypass Vector).

```bash
# Audit target domain or URL for WAF and backend origin leakage
phantom waf --target example.com

# Audit target IP directly
phantom waf --target 104.16.132.229

# Export findings to interactive HTML dashboard
phantom waf --target example.com --output waf_report.html
```

**Key Capabilities:**
- ⚡ **Zero-Request IPv4 CIDR Matching**: Precompiled subnets for Cloudflare, Fastly, Imperva/Incapsula, Sucuri CloudProxy, and Akamai.
- 🔍 **Multi-Vendor Fingerprinting**: HTTP headers (`server`, `cf-ray`, `via`, `x-amz-cf-id`, `x-iinfo`, `x-sucuri-id`, `x-azure-ref`), session cookies, and challenge response signatures.
- 🚨 **Passive Origin Server Discovery (CWE-200)**: Audits DNS MX records, SPF TXT `ip4:` blocks, and unproxied subdomains (`mail`, `direct`, `origin`, `ftp`, `cpanel`, `dev`, `vpn`) for exposed direct backend IPs.

### 3. 🛡️ Vulnerability Scanner (`phantom vuln`)

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

### 4. 🌐 Web Reconnaissance (`phantom recon`)

Web application fingerprinting and surface mapping.

```bash
# Full web reconnaissance
phantom recon --url https://example.com --full

# Technology stack fingerprinting only
phantom recon --url https://example.com --tech

# Directory path discovery
phantom recon --url https://example.com --dirs
```

### 5. 🔎 Subdomain Discovery (`phantom subdomain`)

Find subdomains and detect takeover risks.

```bash
# Brute force using built-in wordlist
phantom subdomain --domain example.com

# Certificate Transparency log search
phantom subdomain --domain example.com --ct-logs

# Custom wordlist with high concurrency
phantom subdomain --domain example.com --wordlist wordlists/subdomains.txt --threads 50
```

### 6. 📡 DNS Enumeration (`phantom dns`)

Enumerate DNS records, SPF/DMARC anti-spoofing policies, and test for zone transfers.

```bash
# All DNS record types
phantom dns --domain example.com --type all

# Specific record types
phantom dns --domain example.com --type a,mx,ns,txt

# Test for DNS zone transfer (AXFR)
phantom dns --domain example.com --zone-transfer
```

### 7. 🔐 SSL/TLS Cryptographic Analysis (`phantom ssl`)

Inspect SSL/TLS certificate chains, protocols, and ciphers.

```bash
# Standard HTTPS inspection
phantom ssl --host example.com

# Custom port
phantom ssl --host example.com --port 8443
```

### 8. 🔑 Multi-Protocol Brute Force (`phantom brute`)

Rate-limited authentication auditing.

```bash
# SSH brute force
phantom brute --target 192.168.1.1 --service ssh --userlist users.txt --passlist passwords.txt

# FTP credential test
phantom brute --target ftp.example.com --service ftp --userlist users.txt --passlist passwords.txt

# HTTP Basic Auth test
phantom brute --target https://example.com/admin --service http --userlist users.txt --passlist passwords.txt
```

### 9. 🗺️ Network Mapper (`phantom network`)

Local network host discovery and traceroute.

```bash
# Host discovery across CIDR subnet
phantom network --target 192.168.1.0/24 --discover

# Route hop tracing
phantom network --target 8.8.8.8 --traceroute
```

### 10. 📋 WHOIS Intelligence (`phantom whois`)

Registrar, creation, expiration, and nameserver lookup.

```bash
phantom whois --target example.com
```

### 11. 📊 Multi-Format Report Generator (`phantom report`)

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

### 12. 🎯 Master Recon Pipeline (`phantom full`)

Execute all 9 specialized modules in sequence:

```bash
phantom full --target example.com --output phantom_report.html
```

**Pipeline Steps:**
1. WHOIS Lookup
2. DNS Enumeration
3. Subdomain Discovery & Takeover Inspection
4. WAF & Origin IP Leakage Audit (Edge proxy identification & bypass check)
5. Port Scanning & Service Identification
6. Web Application Reconnaissance (Tech stack, directories, forms)
7. Security Header Analysis
8. SSL/TLS Cryptographic Analysis
9. Ultra-Precision Vulnerability Scan (Zero False Positive)

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
collected 84 items

tests/test_scanner.py .............                                      [ 15%]
tests/test_validators.py ..............................                  [ 51%]
tests/test_vuln_scanner.py ..........................                    [ 82%]
tests/test_waf_detector.py ..............                                [100%]

============================= 84 passed in 2.89s ==============================
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
│   ├── __init__.py                 # Version & package exports (v1.5.2)
│   ├── cli.py                      # Click CLI entry point
│   │
│   ├── 🧠 core/                    # Specialized scanning engines
│   │   ├── scanner.py              # Multi-threaded TCP/UDP port scanner (with WAF proxy alert)
│   │   ├── waf_detector.py         # Cloud WAF/CDN detector & unproxied origin IP engine
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
│   ├── test_vuln_scanner.py        # Zero false positive & reporting tests
│   └── test_waf_detector.py        # WAF CIDR, signature & origin leak tests
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
