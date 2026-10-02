<p align="center">
  <img src="assets/banner.png" alt="Phantom Recon Banner" width="800"/>
</p>

<h1 align="center">🔥 Phantom Recon</h1>

<p align="center">
  <strong>Advanced Penetration Testing & Reconnaissance Toolkit (v2.1.0)</strong>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge" alt="MIT License"/></a>
  <a href="#modules"><img src="https://img.shields.io/badge/modules-19+-red.svg?style=for-the-badge" alt="19+ Modules"/></a>
  <a href="#testing"><img src="https://img.shields.io/badge/tests-181%20passed-brightgreen.svg?style=for-the-badge" alt="181 Tests Passing"/></a>
  <a href="https://github.com/Tahir-Omicron/phantom-recon/stargazers"><img src="https://img.shields.io/github/stars/Tahir-Omicron/phantom-recon?style=for-the-badge&color=yellow" alt="Stars"/></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#whats-new-in-v210">What's New in v2.1.0</a> •
  <a href="#release-history">Release History</a> •
  <a href="#key-features">Key Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#modules">Modules & CLI</a> •
  <a href="#reporting-formats">Reporting Formats</a> •
  <a href="#testing">Testing</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## 🚀 What's New in v2.1.0

- 🎨 **Favicon MurmurHash3 Technology Fingerprinting (`phantom favicon <url>`)**:
  - Pure Python 32-bit x86 signed `mmh3_32` implementation — 100% bit-for-bit identical to Shodan `http.favicon.hash:<hash>` and `httpx` without any external native C-extensions or compilation requirements!
  - MIME base64 standard encoding with 76-character chunking matching Shodan's algorithm.
  - Built-in verified signature database matching enterprise applications: Spring Boot, Jenkins, GitLab, Jira, Confluence, Grafana, Kibana, FortiGate VPN, GlobalProtect VPN, phpMyAdmin, Keycloak, and more.
  - Direct Shodan dork link generation for zero-request footprint intelligence.
- 🎯 **Subdomain Takeover & Dangling DNS Pointer Auditor (`phantom takeover <target>`)**:
  - Full parity with industry-standard takeover tools (Nuclei, Subjack, Subzy).
  - Multi-threaded DNS CNAME resolution and active HTTP deprovisioned fingerprint inspection across **17 major cloud / SaaS providers**:
    - GitHub Pages (`github.io`)
    - AWS S3 & CloudFront (`s3.amazonaws.com`, `cloudfront.net`)
    - Heroku (`herokuapp.com`)
    - Microsoft Azure (`azurewebsites.net`, `cloudapp.net`, `trafficmanager.net`)
    - Netlify & Vercel (`netlify.app`, `vercel.app`)
    - Fastly CDN & Shopify (`fastly.net`, `myshopify.com`)
    - Zendesk, Ghost, Surge.sh, Pantheon, WordPress.com, Webflow, Bitbucket, Unbounce.
  - Zero-false-positive design: verifies actual provider error response bodies before escalating to Critical severity.
- 📜 **RFC 9116 `security.txt` & Sensitive Surface Auditor (`phantom policy <url>`)**:
  - Standardized RFC 9116 vulnerability disclosure policy validation at `/.well-known/security.txt` and `/security.txt`.
  - Parses `Contact`, `Expires`, `Encryption`, `Preferred-Languages`, `Canonical`, and validates ISO 8601 expiry timestamps.
  - Sensitive Disallowed Path Auditor: extracts `Disallow` rules from `robots.txt` (`/admin`, `/backup`, `/staging`, `/internal`, `/console`), tests live accessibility (HTTP 200 vs 403), and flags information disclosure risks.
- ⚡ **15-Stage Master Autonomous Audit Pipeline (`phantom audit` & `phantom full`)**:
  - Expanded autonomous reconnaissance and vulnerability audit engine from 13 to **15 comprehensive stages**:
    - Stage 4: Subdomain Takeover & Dangling DNS Pointer Audit.
    - Stage 8: Web Application Stack & Favicon MMH3 Fingerprinting.
    - Stage 12: RFC 9116 Security.txt & Sensitive Robots/Sitemap Surface Audit.
- 📊 **Enhanced HTML Security Dashboard & Command Palette**:
  - Dedicated interactive UI cards for Favicon MMH3 hashes, Subdomain Takeover risks, and RFC 9116 compliance.
  - Interactive Command Palette (`phantom help`) updated with new operational categories.
- 🧪 **181 Automated Tests with 100% Pass Rate**:
  - 22 new comprehensive tests covering pure-Python MMH3, favicon extraction, takeover signatures, policy auditor, and CLI commands.

---

## 🚀 What's New in v2.0.0

- ⚡ **Single-Command Autonomous End-to-End Audit (`phantom audit <target>`)**:
  - Perform an exhaustive, start-to-finish reconnaissance and vulnerability assessment with a **single command** — no need to run individual tools separately!
  - Accepts raw target inputs (`example.com`, `https://example.com/app`, or `192.168.1.1`) with automated normalization into clean host and URL profiles.
  - Optional `--fast` flag for rapid triage or deep multi-threaded analysis.
- 🛡️ **Direct Terminal Vulnerability & Risk Matrix Table**:
  - Immediately upon completion, renders a magnificent unified findings table directly in the terminal:
    - Severity badge (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) + CVSS Score.
    - Architecture Category (`DevOps`, `Cloud`, `CMS`, `Network`, `API`, `Web App`, `DNS`, `Crypto`).
    - Finding / Vulnerability Name.
    - Exact Affected Location or URL link.
    - Technical Description & Real-World Impact (*Nədir & Təsiri*).
    - Actionable Remediation Guidance (*Düzəliş / Həll Yolu*).
- 🚨 **Perimeter Risky Services & Exposed Database Probing**:
  - Identifies dangerous services exposed to the public Internet:
    - **Port 23 (Telnet)**: Cleartext remote terminal daemon (Critical / CVSS 9.8).
    - **Port 6379 (Redis)**: Unauthenticated in-memory cache/database (Critical / CVSS 9.8).
    - **Port 445 (SMB)**: Direct file sharing exposure (High / CVSS 8.5).
    - **Port 1433/3306/5432/27017 (MSSQL, MySQL, Postgres, MongoDB)**: Exposed database engines.
    - **Port 21 (FTP)** & **Port 9200 (Elasticsearch)**.
- 🎯 **Consolidated Finding Aggregator & Deduplication**:
  - Aggregates findings from DNS spoofing, subdomain takeovers, unproxied origin IPs, open cloud buckets, perimeter services, CMS exposures, frontend source maps, and web vulnerabilities into a unified, deduplicated dataset sorted strictly by severity.
- 🧪 **Expanded Automated Test Suite (159 Passing Tests)**:
  - 16 new automated tests verifying target normalization, dangerous ports, autonomous auditor pipeline, findings table rendering, and CLI commands.
  - 100% test pass rate in under 4 seconds.

---

## 📜 Release History & Changelog (v1.0.0 — v2.1.0)

| Version | Release Focus | Key Additions & Fixes |
| :--- | :--- | :--- |
| **v2.1.0** | **Competitor Parity Upgrade: Favicon MMH3, Subdomain Takeover & RFC 9116 Policy** | • Pure-Python 32-bit MurmurHash3 engine for Shodan & Censys compatible favicon hashing (`phantom favicon`).<br>• Subdomain Takeover & Dangling DNS auditor across 17 cloud providers (`phantom takeover`).<br>• RFC 9116 `security.txt` & sensitive robots.txt/sitemap surface auditor (`phantom policy`).<br>• Master autonomous pipeline upgraded to 15 automated stages (`phantom audit` / `phantom full`).<br>• HTML dashboard updated with Favicon, Takeover, and RFC 9116 visual cards.<br>• Automated test suite expanded to **181 passing tests** (100% pass rate). |
| **v2.0.0** | **Single-Command Autonomous Audit, Direct Findings Table & Perimeter Risk Engine** | • Autonomous Master Audit Engine (`phantom audit <target>`) running end-to-end scans in 1 command.<br>• Direct unified terminal Vulnerability Matrix Table with severity, impact, and fixes.<br>• Automatic target normalization (domain, URL, IP).<br>• Perimeter database & risky service detection (Redis, Telnet, SMB, DBs).<br>• Modernized `phantom full` with unified engine.<br>• Expanded test suite to **159 passing tests**. |
| **v1.9.0** | **CMS & Framework Auditor, DevOps Manifests & JavaScript Source Maps** | • CMS & Framework Security Auditor (`phantom cms`) supporting WordPress, Laravel, Django, Next.js, Drupal, Joomla, and Spring Boot.<br>• WordPress REST API user enumeration, XML-RPC exposure, and debug log detection.<br>• Laravel log disclosure and exposed Telescope dashboard.<br>• Frontend JavaScript Source Map (`.js.map`) leakage discovery.<br>• DevOps infrastructure checks: `/docker-compose.yml`, `/terraform.tfstate`, `/Dockerfile`.<br>• Master pipeline expanded to 13 automated stages (`phantom full`).<br>• Expanded test suite to **143 passing tests**. |
| **v1.8.0** | **HTTP Methods Auditor, Security Score & Sleek Red Team Banner** | • HTTP Methods & Dangerous Verbs Auditor (`phantom methods`) for PUT, DELETE, TRACE, and WebDAV.<br>• Executive Security Health Score (0-100, A+ to F) with terminal gauge and category breakdown.<br>• Master pipeline expanded to 12 automated stages (`phantom full`).<br>• Streamlined, zero-wrap horizontal terminal ASCII banner and sleek pixel cyber banner asset.<br>• Expanded test suite to **125 passing tests**. |
| **v1.7.0** | **Multi-Cloud Auditor & Finding Matrix** | • Multi-Cloud Storage Auditor across AWS S3, GCP Storage, and Azure Blob (`phantom cloud`).<br>• Executive & Technical Vulnerability Matrix Table with exact descriptions, real-world impact, and remediation across HTML, Markdown, Text, and Terminal.<br>• Extended master pipeline (`phantom full`) to 11 automated stages.<br>• Interactive HTML filter synchronizes both the table matrix and card views.<br>• Expanded test suite to **107 passing tests**. |
| **v1.6.0** | **API Recon, Deep CSP & Rich CLI UX** | • Embedded repository banner asset (`assets/banner.png`).<br>• Interactive Command Palette & categorized matrix (`phantom help`).<br>• API reconnaissance engine discovering OpenAPI/Swagger, GraphQL & Actuator endpoints (`phantom api`).<br>• Deep Content-Security-Policy (CSP) evaluator (`'unsafe-inline'`, `'unsafe-eval'`).<br>• Upgraded master pipeline (`phantom full`) to 10 automated steps.<br>• Expanded test suite to **93 passing tests**. |
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
| 🖼️ **Repository Visual Branding** | High-definition repository banner and crisp identity asset (`assets/banner.png`). |
| ☁️ **Multi-Cloud Storage Auditor** | Audits AWS S3, Google Cloud Storage, and Azure Blob containers for public listing (`phantom cloud`). |
| 🛡️ **Vulnerability Findings Matrix** | Structured technical finding table with impact descriptions and remediations across all report formats. |
| 🧩 **CMS & Framework Auditor** | Fingerprints WordPress, Laravel, Next.js, Django, and detects exposed debug logs, XML-RPC, and user accounts (`phantom cms`). |
| 📜 **Source Map & DevOps Audit** | Discovers exposed JavaScript `.js.map` source files, `docker-compose.yml`, and `terraform.tfstate`. |
| 🚫 **HTTP Methods & Verbs Auditor** | Identifies risky verbs (`PUT`, `DELETE`, `TRACE/XST`, `WebDAV`) and method overrides (`phantom methods`). |
| 💻 **Rich Command Palette & Matrix** | Interactive categorized operational table and cheat sheet (`phantom help`) built for cybersecurity pros and students. |
| ⚡ **API & Schema Reconnaissance** | Discovers OpenAPI/Swagger JSON schemas, Swagger UI/ReDoc portals, GraphQL endpoints, and Spring Boot Actuators. |
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

# View the interactive command palette & cheat sheet
phantom help

# Audit CMS, frameworks, and exposed JavaScript source maps
phantom cms --url https://example.com

# Audit AWS S3, GCP Storage, and Azure Blob containers for public exposure
phantom cloud --target example.com

# Audit HTTP verbs and dangerous methods (PUT, DELETE, TRACE, WebDAV)
phantom methods --url https://example.com

# Run a vulnerability audit with interactive HTML report
phantom vuln --url https://example.com --output audit_report.html

# Run the complete 13-stage full reconnaissance pipeline
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
- 🔴 **Exposed API Schemas & Endpoints**: Swagger JSON, OpenAPI definitions, exposed Spring Boot Actuators
- 🔴 **Reflected XSS**: Real HTML-context reflection without encoding
- 🟠 **CORS Misconfigurations**: Dual-origin reflection, wildcard credential sharing, `Origin: null` trust
- 🟡 **Clickjacking**: Missing both `X-Frame-Options` and `frame-ancestors` on HTML pages
- 🟡 **Insecure Directory Listing**: Server-indexed `/uploads/`, `/static/`, `/backup/` paths
- 🟡 **Open Redirect**: Validated external redirection targets
- 🔵 **Cookie Security**: Missing `Secure`, `HttpOnly`, and `SameSite` flags
- 🔵 **Security Headers & Deep CSP**: Missing `HSTS`, `X-Content-Type-Options`, and unsafe CSP directives (`'unsafe-inline'`, `'unsafe-eval'`)
- 🔵 **Information Disclosure**: Detailed server version leaks in headers

### 4. 🚫 HTTP Methods & Dangerous Verbs Auditor (`phantom methods`)

Audits supported and advertised HTTP methods, probes dangerous verbs (PUT, DELETE, TRACE, WebDAV PROPFIND), and checks HTTP Method Override vulnerabilities with zero false positives.

```bash
# Audit target URL for dangerous HTTP methods
phantom methods --url https://example.com

# Audit with custom network timeout
phantom methods --url https://example.com --timeout 10
```

**Tested Verbs & Vulnerability Probes:**
- 🔴 **HTTP PUT (Arbitrary File Upload)**: Benign probe testing whether unauthenticated file creation is permitted, with immediate automated cleanup.
- 🟠 **HTTP DELETE (Resource Deletion)**: Validates if resource deletion endpoints are exposed without credentials.
- 🟡 **HTTP TRACE (Cross-Site Tracing / XST)**: Precision canary header echo verification (`CVE-2004-2320`).
- 🟡 **WebDAV PROPFIND**: Tests for active WebDAV extensions exposing internal file directories and XML multistatus trees.
- 🔵 **HTTP Method Override**: Probes backend support for `X-HTTP-Method-Override: PUT` and `X-Method-Override` headers.
- ⚪ **OPTIONS Discovery**: Parses advertised `Allow` and `Public` headers.

### 5. ☁️ Multi-Cloud Storage Auditor (`phantom cloud`)

Discovers exposed, publicly readable, or existing cloud storage buckets and containers across Amazon Web Services (AWS), Google Cloud Storage (GCS), and Microsoft Azure.

```bash
# Audit target domain or organization for cloud bucket exposure
phantom cloud --target example.com

# Audit with custom concurrency threads and custom wordlist
phantom cloud --target example.com --threads 25 --wordlist custom_words.txt

# Export results to HTML dashboard
phantom cloud --target example.com --output cloud_report.html
```

**Supported Cloud Providers & Validation:**
- 🟧 **Amazon Web Services (AWS) S3**: Audits `https://<bucket>.s3.amazonaws.com`. Evaluates `<ListBucketResult>` XML schemas, extracts sample keys, and detects HTTP 403 `AccessDenied` protected buckets.
- 🟦 **Google Cloud Storage (GCS)**: Audits `https://storage.googleapis.com/<bucket>`. Evaluates XML and JSON listing endpoints, extracts sample object keys, and verifies Public Access Prevention posture.
- 🔷 **Microsoft Azure Blob Storage**: Audits `https://<account>.blob.core.windows.net/<container>?restype=container&comp=list`. Checks `$root`, `public`, `backup`, `data`, and `media` containers.

### 6. ⚡ API & Schema Reconnaissance (`phantom api`)

Discovers exposed API schemas, interactive documentation portals, GraphQL endpoints, and Spring Boot Actuators.

```bash
# Discover exposed API schemas, documentation, and GraphQL
phantom api --url https://example.com

# Audit API with custom timeout and export to JSON
phantom api --url https://api.example.com --timeout 15 --output api_findings.json
```

**Discovered Endpoints & Capabilities:**
- 📜 **OpenAPI / Swagger Schemas**: `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/openapi.json`, `/api-docs`
- 🖥️ **Interactive Documentation Portals**: Swagger UI (`/swagger-ui.html`, `/docs`), ReDoc (`/redoc`)
- 🔮 **GraphQL Endpoints**: `/graphql`, `/api/graphql`, `/v1/graphql` (verified via active schema probe query `{__typename}`)
- ⚙️ **Spring Boot Actuators**: `/actuator/health`, `/actuator/env`, `/actuator/metrics`, `/actuator/beans`
- 🛡️ **Canary Soft-404 Validation**: Automatically profiles random endpoints (`/__phantom_canary_probe__`) to filter out false positives on Single Page Applications (SPAs).

### 7. 🧩 CMS & Framework Security Auditor (`phantom cms`)

Fingerprints modern web application frameworks and Content Management Systems, identifying debug logs, public user enumeration endpoints, administrative portals, and client-side source map disclosures.

```bash
# Audit target application for CMS vulnerabilities and source maps
phantom cms --url https://example.com

# Audit with custom network timeout
phantom cms --url https://example.com --timeout 10

# Audit and export findings to interactive HTML dashboard
phantom cms --url https://example.com --output cms_report.html
```

**Audited Technologies & Exposures:**
- 🌐 **Architecture Fingerprinting**: WordPress, Laravel, Django, Next.js, Drupal, Joomla, and Spring Boot.
- 👤 **WordPress REST API User Enumeration**: Queries `/wp-json/wp/v2/users` to harvest valid usernames and user IDs for credential brute-force defense.
- ⚡ **WordPress XML-RPC Exposure**: Verifies `/xmlrpc.php` access for amplified brute force and DDoS pingback vectors.
- 🪵 **Application Debug Logs**: Detects publicly accessible `/wp-content/debug.log` and Laravel `/storage/logs/laravel.log`.
- 🔭 **Laravel Telescope Dashboard**: Probes `/telescope` for unauthenticated monitoring access exposing sensitive request bodies and SQL queries.
- 🗺️ **Frontend JavaScript Source Maps (`.js.map`)**: Inspects script tags, locates production `.js.map` files, and verifies JSON schemas to uncover client-side source code, developer notes, and hidden internal API endpoints.
- 🔑 **Exposed Admin Portals**: Identifies accessible Django Admin (`/admin/login/`), Drupal (`/user/login`), and Joomla (`/administrator/`).

### 8. 🌐 Web Reconnaissance (`phantom recon`)

Web application fingerprinting and surface mapping.

```bash
# Full web reconnaissance
phantom recon --url https://example.com --full

# Technology stack fingerprinting only
phantom recon --url https://example.com --tech

# Directory path discovery
phantom recon --url https://example.com --dirs
```

### 9. 🔎 Subdomain Discovery (`phantom subdomain`)

Find subdomains and detect takeover risks.

```bash
# Brute force using built-in wordlist
phantom subdomain --domain example.com

# Certificate Transparency log search
phantom subdomain --domain example.com --ct-logs

# Custom wordlist with high concurrency
phantom subdomain --domain example.com --wordlist wordlists/subdomains.txt --threads 50
```

### 10. 📡 DNS Enumeration (`phantom dns`)

Enumerate DNS records, SPF/DMARC anti-spoofing policies, and test for zone transfers.

```bash
# All DNS record types
phantom dns --domain example.com --type all

# Specific record types
phantom dns --domain example.com --type a,mx,ns,txt

# Test for DNS zone transfer (AXFR)
phantom dns --domain example.com --zone-transfer
```

### 11. 🔐 SSL/TLS Cryptographic Analysis (`phantom ssl`)

Inspect SSL/TLS certificate chains, protocols, and ciphers.

```bash
# Standard HTTPS inspection
phantom ssl --host example.com

# Custom port
phantom ssl --host example.com --port 8443
```

### 12. 🔑 Multi-Protocol Brute Force (`phantom brute`)

Rate-limited authentication auditing.

```bash
# SSH brute force
phantom brute --target 192.168.1.1 --service ssh --userlist users.txt --passlist passwords.txt

# FTP credential test
phantom brute --target ftp.example.com --service ftp --userlist users.txt --passlist passwords.txt

# HTTP Basic Auth test
phantom brute --target https://example.com/admin --service http --userlist users.txt --passlist passwords.txt
```

### 13. 🗺️ Network Mapper (`phantom network`)

Local network host discovery and traceroute.

```bash
# Host discovery across CIDR subnet
phantom network --target 192.168.1.0/24 --discover

# Route hop tracing
phantom network --target 8.8.8.8 --traceroute
```

### 14. 📋 WHOIS Intelligence (`phantom whois`)

Registrar, creation, expiration, and nameserver lookup.

```bash
phantom whois --target example.com
```

### 15. 💻 Interactive Rich Command Palette (`phantom help`)

Renders a categorized command matrix and operational cheat sheet designed for fast triage:

```bash
# Launch interactive command palette
phantom help
```

### 16. 📊 Multi-Format Report Generator (`phantom report`)

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

### 17. 🎯 Subdomain Takeover & Dangling DNS Auditor (`phantom takeover`)

Audit target domain and subdomains for dangling CNAME pointers to abandoned cloud infrastructure across 17 major providers (AWS S3, GitHub Pages, Heroku, Azure, Netlify, Vercel, Shopify, Fastly, etc.):

```bash
# Audit target domain and automatically discover subdomains for takeover risks
phantom takeover example.com

# Multi-threaded takeover audit with custom concurrency
phantom takeover example.com --threads 25
```

### 18. 🎨 Favicon MurmurHash3 Technology Fingerprinting (`phantom favicon`)

Extract favicon, compute Shodan-compatible 32-bit signed MurmurHash3 (MMH3), MD5, and SHA256 hashes, and fingerprint underlying web platforms without triggering WAF alarms:

```bash
# Fingerprint technology stack from favicon hash
phantom favicon https://example.com

# Inspect specific portal or admin console
phantom favicon https://app.example.com:8443
```

### 19. 📜 RFC 9116 Security.txt & Sensitive Surface Auditor (`phantom policy`)

Audit compliance with RFC 9116 vulnerability disclosure policies and identify hidden administrative consoles disclosed in `robots.txt`:

```bash
# Audit security.txt and robots.txt disallowed paths
phantom policy https://example.com
```

### 20. ⚡ Autonomous Master Recon & Audit Pipeline (`phantom audit` / `phantom full`)

Execute all 15 specialized reconnaissance and vulnerability assessment phases in sequence with a single command:

```bash
# Single-command end-to-end audit with instant terminal findings table
phantom audit example.com

# Rapid triage mode
phantom audit example.com --fast

# Export complete audit results to interactive HTML dashboard
phantom audit example.com --output phantom_report.html
```

**Pipeline Steps (15 Automated Stages):**
1. WHOIS Intelligence & Domain Attribution
2. DNS Enumeration & Anti-Spoofing Policy Audit (SPF & DMARC)
3. Subdomain Discovery & Attack Surface Mapping
4. Subdomain Takeover & Dangling DNS Pointer Audit (17 Cloud Providers)
5. WAF Edge Detection & Backend Origin IP Leakage Audit
6. Cloud Storage & Bucket Exposure Audit (AWS S3, GCP Storage, Azure Blob)
7. Perimeter Port Scanning & Risky Database / Daemon Auditing (Redis, Telnet, SMB)
8. Web Application Stack & Favicon MMH3 Fingerprinting
9. API Schema & Documentation Reconnaissance (OpenAPI, GraphQL, Actuators)
10. CMS & Framework Security Audit (WordPress, Laravel, Django, .js.map source maps)
11. Security Header & Deep CSP Directive Analysis
12. RFC 9116 Security.txt & Sensitive Robots/Sitemap Surface Audit
13. SSL/TLS Protocol Inspection & Cryptographic Hygiene
14. HTTP Methods & Dangerous Verbs Audit (PUT, DELETE, TRACE, WebDAV)
15. Ultra-Precision Web Vulnerability Scan, Finding Explanation Matrix & Security Scorecard

---

## 📊 Reporting Formats

Phantom Recon offers enterprise reporting tailored for different stakeholders:

1. **Interactive HTML Dashboard**:
   - Cyberpunk dark glassmorphism aesthetic (`backdrop-filter: blur(24px)`).
   - SVG Dynamic Security Score Ring (0–100 calculated from findings).
   - **Executive & Technical Finding Matrix Table**: Full tabular breakdown detailing Vulnerability Name, Severity, Location, What It Is & Real-World Impact, and Remediation.
   - Synchronized live keyword search and instant severity filtering (`All`, `Critical`, `High`, `Medium`, `Low`, `Info`).
   - 1-click PoC cURL copy buttons with animated toast alerts.
   - In-browser **Export CSV**, **Export JSON**, and **Print / PDF** buttons.
2. **CSV Deliverable**:
   - Encoded in `UTF-8 with BOM` (`utf-8-sig`) so that Microsoft Excel, Google Sheets, Jira, and DefectDojo display characters cleanly.
   - Comprehensive columns: Title, Severity, CVSS, Location, Direct URL, PoC cURL, Evidence, Remediation.
3. **Markdown Report**:
   - Technical Vulnerability Matrix table, executive summary, severity breakdown badges, and clean code blocks ready for GitHub issues and Bug Bounty reports.
4. **JSON & Plain Text**:
   - Machine-readable structured payloads for SIEM pipelines and CI/CD integration, with ASCII finding tables in plain text format.

---

## 🧪 Testing

Phantom Recon features a rigorous test suite covering zero-false-positive guards, cloud auditors, validators, parsers, and report generation:

```bash
pytest tests/ -v
```

```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1
collected 181 items

tests/test_scanner.py .............                                      [  7%]
tests/test_v160_features.py .........                                    [ 12%]
tests/test_v170_features.py ..............                                [ 20%]
tests/test_v180_features.py ..................                            [ 30%]
tests/test_v190_features.py .................                             [ 39%]
tests/test_v200_features.py .................                             [ 49%]
tests/test_v210_features.py ......................                        [ 61%]
tests/test_validators.py ..............................                  [ 78%]
tests/test_vuln_scanner.py ..........................                    [ 92%]
tests/test_waf_detector.py ..............                                [100%]

============================= 181 passed in 5.57s =============================
```

---

## 🏗️ Project Architecture

```
phantom-recon/
├── 🖼️ assets/
│   └── banner.png                  # Official repository visual banner
├── 📄 pyproject.toml               # Build configuration & dependency definitions
├── 📄 README.md                    # Documentation & user guide
├── 📄 LICENSE                      # MIT License
├── 📄 CONTRIBUTING.md              # Contribution standards
├── 📄 SECURITY.md                  # Responsible disclosure policy
│
├── 🔥 phantom_recon/               # Core framework package
│   ├── __init__.py                 # Version & package exports (v1.7.0)
│   ├── cli.py                      # Click CLI entry point & PhantomGroup help formatter
│   │
│   ├── 🧠 core/                    # Specialized scanning engines
│   │   ├── cloud_auditor.py        # Multi-Cloud Storage Auditor (AWS S3, GCP Storage, Azure Blob)
│   │   ├── scanner.py              # Multi-threaded TCP/UDP port scanner (with WAF proxy alert)
│   │   ├── waf_detector.py         # Cloud WAF/CDN detector & unproxied origin IP engine
│   │   ├── api_scanner.py          # OpenAPI/Swagger, GraphQL & Actuator discovery engine
│   │   ├── vuln_scanner.py         # Zero False Positive Vulnerability Scanner & Matrix
│   │   ├── web_recon.py            # Web application reconnaissance & fingerprinting
│   │   ├── subdomain.py            # Subdomain discovery & takeover detection
│   │   ├── dns_enum.py             # DNS enumeration & zone transfer audit
│   │   ├── header_analyzer.py      # HTTP security header & Deep CSP grader
│   │   ├── ssl_analyzer.py         # SSL/TLS cryptographic cipher inspector
│   │   ├── network.py              # ARP discovery & traceroute mapper
│   │   ├── brute.py                # Multi-protocol credential auditor
│   │   └── whois_lookup.py         # Domain & IP WHOIS intelligence
│   │
│   ├── 🛠️ utils/                   # Shared utilities
│   │   ├── logger.py               # Rich terminal formatting, command palette & vuln matrix table
│   │   ├── validators.py           # Strict IP/CIDR/Domain/URL validators
│   │   └── config.py               # YAML configuration loader
│   │
│   └── 📊 reporting/               # Multi-format report generators
│       ├── report_generator.py     # HTML, CSV, Markdown, JSON, TXT engine
│       └── templates.py            # Dark glassmorphism dashboard template & finding matrix
│
├── 🧪 tests/                       # Automated test suite (107 unit tests)
│   ├── test_v170_features.py       # Cloud auditor, vulnerability matrix & CLI tests
│   ├── test_v160_features.py       # API scanner, CSP & command palette tests
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
