<p align="center">
  <img src="assets/banner.png" alt="Phantom Recon Banner" width="800"/>
</p>

<h1 align="center">🔥 Phantom Recon</h1>

<p align="center">
  <strong>Advanced Penetration Testing & Reconnaissance Toolkit</strong>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge" alt="MIT License"/></a>
  <a href="#modules"><img src="https://img.shields.io/badge/modules-10+-red.svg?style=for-the-badge" alt="10+ Modules"/></a>
  <a href="#contributing"><img src="https://img.shields.io/badge/contributions-welcome-orange.svg?style=for-the-badge" alt="Contributions Welcome"/></a>
  <a href="https://github.com/Tahir-Omicron/phantom-recon/stargazers"><img src="https://img.shields.io/github/stars/Tahir-Omicron/phantom-recon?style=for-the-badge&color=yellow" alt="Stars"/></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#whats-new-in-v120">What's New in v1.2.0</a> •
  <a href="#modules">Modules</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#screenshots">Screenshots</a> •
  <a href="#api-reference">API</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## 🚀 What's New in v1.2.0

- 🛡️ **Zero False Positive Engine**:
  - **Soft-404 Baseline Profiling**: Probes randomized canary endpoints to filter out SPAs and catch-all HTTP 200 handlers.
  - **Strict Semantic Regex Matching**: Validates genuine signatures for `.env` variables, Git index/HEAD refs, `phpinfo()`, and Apache status pages instead of generic status code triggers.
  - **Context-Aware XSS Validation**: Requires `text/html` context and ensures reflection is outside pure JSON/binary payloads.
  - **Dual-Origin CORS Verification**: Probes dynamic origin reflection against external hostile origins before flagging CORS misconfigurations.
  - **External-Only Redirect Detection**: Validates target host against external netlocs to ignore safe internal redirects.
- 🎨 **Enterprise Glassmorphism UI**:
  - **Dynamic SVG Security Score Gauge**: Circular visual health ring (0–100) calculated from severity-weighted findings.
  - **Live Client-Side Search & Filter Tabs**: Instant filtering by keywords and severity levels (Critical, High, Medium, Low, Info).
  - **1-Click PoC cURL Copy**: Click-to-copy verified reproduction commands with responsive toast notifications.
  - **Print & PDF Optimization**: Clean print stylesheets for executive security auditing deliverables.

---

## 📖 About

**Phantom Recon** is a comprehensive, modular penetration testing and reconnaissance framework built in Python. Designed for security professionals, ethical hackers, and red team operators, it combines 10+ specialized modules into a single unified CLI toolkit.

> ⚠️ **DISCLAIMER**: This tool is intended for **authorized security testing only**. Always obtain proper written authorization before testing any systems you do not own. Unauthorized access to computer systems is illegal. The developers assume no liability for misuse.

### ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🛡️ **Zero False Positive Engine** | Soft-404 canary profiling, semantik regex təsdiqləməsi və ikili origin testi |
| 🎨 **Enterprise Glassmorphism UI** | Dinamik SVG təhlükəsizlik şkalası, anlıq axtarış və cəld filtrasiya |
| 🎯 **Exact Location Tracing** | Dəqiq harada tapıldığı görünür: Parameter (`q`), Header (`CSP`), fayl yolu (`/.env`) |
| 🔗 **Clickable Jump Links** | Terminalda və HTML hesabatında birbaşa açılan linklər (`target="_blank"`) |
| 📋 **1-Click PoC cURL** | Tək kliklə kopyalanan hazır `curl` test əmri ilə anında təkrarlama |
| 🔍 **Port Scanning** | TCP SYN/Connect/UDP scanning with service detection and banner grabbing |
| 🌐 **Web Reconnaissance** | Technology fingerprinting, directory bruteforce, form detection |
| 📡 **DNS Enumeration** | Full record lookup, zone transfer, wildcard detection |
| 🔎 **Subdomain Discovery** | Brute force, Certificate Transparency, async resolution |
| 🛡️ **Vulnerability Scanning** | SQLi, Reflected XSS, CORS, Sensitive files (.env, .git), Open Redirect |
| 🔐 **SSL/TLS Analysis** | Certificate validation, cipher enumeration, protocol detection |
| 🔑 **Brute Force** | SSH, FTP, HTTP Auth/Form with rate limiting |
| 🗺️ **Network Mapping** | Host discovery, ARP scanning, traceroute |
| 📋 **WHOIS Lookup** | Domain/IP registration details |
| 📊 **Interactive HTML Reports** | Real-time copy buttons, toast notifications, CVSS 3.1 & Confidence ratings |

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Tahir-Omicron/phantom-recon.git
cd phantom-recon

# Install in development mode
pip install -e ".[dev]"

# Run your first scan
phantom scan --target 192.168.1.1 --ports 1-1000

# Full recon on a domain
phantom full --target example.com --output report.html
```

---

## 📦 Installation

### Prerequisites

- **Python 3.9+** (tested on 3.9, 3.10, 3.11, 3.12)
- **pip** package manager
- **Nmap** (optional, enhances port scanning)
- **Git** for cloning

### Method 1: Install from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/Tahir-Omicron/phantom-recon.git
cd phantom-recon

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install with all dependencies
pip install -e .

# Verify installation
phantom --help
```

### Method 2: Install with Dev Dependencies

```bash
# Clone and enter directory
git clone https://github.com/tahir/phantom-recon.git
cd phantom-recon

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS

# Install with development dependencies
pip install -e ".[dev]"

# Run tests to verify
pytest
```

### Method 3: Direct pip Install

```bash
pip install git+https://github.com/tahir/phantom-recon.git
```

### Optional: Install Nmap

For enhanced port scanning capabilities:

```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Windows — download from https://nmap.org/download.html
```

---

## 🧩 Modules

### 1. 🔍 Port Scanner (`phantom scan`)

Advanced multi-threaded port scanner with service detection.

```bash
# Basic scan (top 1000 ports)
phantom scan --target 192.168.1.1

# Scan specific ports
phantom scan --target 10.0.0.1 --ports 22,80,443,8080

# Scan port range with threading
phantom scan --target 10.0.0.1 --ports 1-65535 --threads 100

# UDP scan
phantom scan --target 10.0.0.1 --type udp --ports 53,67,68,161

# Scan with service detection
phantom scan --target example.com --ports 1-1000 --type connect
```

**Python API:**
```python
from phantom_recon import PortScanner

scanner = PortScanner(target="192.168.1.1", ports="1-1000", threads=50)
results = scanner.scan()

for port, info in results["ports"].items():
    if info["state"] == "open":
        print(f"Port {port}: {info['service']} - {info['banner']}")
```

**Output Example:**
```
╔══════════════════════════════════════════════════════╗
║  🔍 PORT SCAN RESULTS — 192.168.1.1                 ║
╠══════════╦══════════╦════════════╦═══════════════════╣
║ PORT     ║ STATE    ║ SERVICE    ║ BANNER            ║
╠══════════╬══════════╬════════════╬═══════════════════╣
║ 22/tcp   ║ open     ║ ssh        ║ OpenSSH 8.9       ║
║ 80/tcp   ║ open     ║ http       ║ nginx/1.24.0      ║
║ 443/tcp  ║ open     ║ https      ║ nginx/1.24.0      ║
║ 3306/tcp ║ open     ║ mysql      ║ MySQL 8.0.35      ║
╚══════════╩══════════╩════════════╩═══════════════════╝
```

---

### 2. 🌐 Web Reconnaissance (`phantom recon`)

Comprehensive web application reconnaissance.

```bash
# Full web recon
phantom recon --url https://example.com --full

# Technology detection only
phantom recon --url https://example.com --tech

# Directory bruteforce
phantom recon --url https://example.com --dirs --wordlist /path/to/wordlist.txt
```

**Python API:**
```python
from phantom_recon import WebRecon

recon = WebRecon(url="https://example.com")
results = recon.run_full_recon()

print(f"Technologies: {results['technologies']}")
print(f"Forms found: {len(results['forms'])}")
print(f"External links: {len(results['links']['external'])}")
```

**Capabilities:**
- 🔧 Technology stack fingerprinting (CMS, frameworks, JS libraries)
- 📁 robots.txt & sitemap.xml analysis
- 📝 Form detection with parameter extraction
- 🍪 Cookie security analysis (HttpOnly, Secure, SameSite)
- 📜 JavaScript file discovery
- 🔗 Link extraction (internal/external)

---

### 3. 📡 DNS Enumeration (`phantom dns`)

Full DNS record enumeration and analysis.

```bash
# All record types
phantom dns --domain example.com --type all

# Specific record types
phantom dns --domain example.com --type mx,ns,txt

# Attempt zone transfer
phantom dns --domain example.com --zone-transfer
```

**Python API:**
```python
from phantom_recon import DNSEnumerator

dns = DNSEnumerator(domain="example.com")
records = dns.enumerate_all()

print(f"A Records: {records['A']}")
print(f"MX Records: {records['MX']}")
print(f"NS Records: {records['NS']}")
print(f"TXT Records: {records['TXT']}")
```

**Supported Record Types:**
`A` · `AAAA` · `MX` · `NS` · `TXT` · `SOA` · `CNAME` · `SRV` · `PTR`

---

### 4. 🔎 Subdomain Discovery (`phantom subdomain`)

Find subdomains using multiple techniques.

```bash
# Brute force with built-in wordlist
phantom subdomain --domain example.com

# Use custom wordlist with threading
phantom subdomain --domain example.com --wordlist subdomains.txt --threads 50

# Certificate Transparency logs
phantom subdomain --domain example.com --ct-logs
```

**Python API:**
```python
from phantom_recon import SubdomainFinder

finder = SubdomainFinder(domain="example.com", threads=30)

# Brute force
subs = finder.brute_force()

# Certificate Transparency
ct_subs = finder.ct_search()

# Combined
all_subs = finder.find_all()
for sub in all_subs:
    print(f"{sub['subdomain']} -> {sub['ip']} [{sub['status_code']}]")
```

---

### 5. 🛡️ Vulnerability Scanner (`phantom vuln`)

Detect common web vulnerabilities.

```bash
# Full vulnerability scan with live location tracking
phantom vuln --url https://example.com

# Direct export to interactive HTML report with 1-click copy buttons
phantom vuln --url https://example.com -o report.html

# Deep scan mode
phantom vuln --url https://example.com --deep
```

**Python API:**
```python
from phantom_recon import VulnerabilityScanner

scanner = VulnerabilityScanner(url="https://example.com")
vulns = scanner.scan_all()

for vuln in vulns:
    print(f"[{vuln['severity'].upper()}] {vuln['title']}")
    print(f"  📍 Location:     {vuln['location']}")
    print(f"  🔗 Direct Link:  {vuln['poc_url']}")
    print(f"  💻 PoC cURL:     {vuln['reproduce_curl']}")
    print(f"  💡 Remediation:  {vuln['remediation']}\n")
```

**Features & Checks Performed:**

| Check | Exact Location Traced | Severity | CVSS | Direct PoC |
|-------|-----------------------|----------|------|------------|
| 🔴 **Sensitive Files** | `/.env`, `/.git/HEAD`, `/phpinfo.php`, `wp-config.bak` | Critical / High | 9.8 | 🔗 Clickable direct URL + cURL |
| 🔴 **Reflected XSS** | Param: `?q=`, `?id=`, etc. with unescaped markup | High | 7.2 | 🔗 Injected PoC URL + cURL |
| 🟠 **CORS Misconfig** | Header: `Origin` -> `Access-Control-Allow-Origin` | High / Crit | 7.1-8.8 | 💻 cURL with reflected Origin |
| 🟡 **Open Redirect** | Param: `?redirect=`, `?url=`, `?goto=` | Medium | 6.1 | 🔗 Clickable canary redirect URL |
| 🟡 **Clickjacking** | Headers: `X-Frame-Options` & `frame-ancestors` | Medium | 5.4 | 💻 iframe snippet + cURL |
| 🔵 **Security Headers**| Missing `CSP`, `HSTS`, `X-Content-Type-Options` | Med / Low | 3.1-6.1 | 💻 cURL inspection command |
| 🔵 **Info Disclosure** | Headers: `Server`, `X-Powered-By` leaks | Low | 3.7 | 💻 Header fingerprint check |

---

### 6. 🔐 SSL/TLS Analysis (`phantom ssl`)

Comprehensive SSL/TLS security analysis.

```bash
# Analyze SSL configuration
phantom ssl --host example.com

# Custom port
phantom ssl --host example.com --port 8443
```

**Python API:**
```python
from phantom_recon import SSLAnalyzer

ssl = SSLAnalyzer(host="example.com", port=443)
info = ssl.analyze()

print(f"Issuer: {info['certificate']['issuer']}")
print(f"Valid until: {info['certificate']['not_after']}")
print(f"Protocol: {info['protocol']}")
print(f"Cipher: {info['cipher_suite']}")
print(f"Grade: {info['grade']}")
```

**Analysis Includes:**
- 📜 Certificate details (issuer, subject, SANs, validity)
- 🔒 Protocol version detection (SSLv3, TLS 1.0-1.3)
- 🔑 Cipher suite enumeration & strength analysis
- ⛓️ Certificate chain validation
- ⚠️ Expiry warnings
- 🔓 Self-signed detection
- 🛡️ HSTS check

---

### 7. 🔑 Brute Force (`phantom brute`)

Multi-protocol credential brute forcing.

```bash
# SSH brute force
phantom brute --target 192.168.1.1 --service ssh --userlist users.txt --passlist passwords.txt

# FTP with threading
phantom brute --target ftp.example.com --service ftp --userlist users.txt --passlist pass.txt --threads 10

# HTTP Basic Auth
phantom brute --target https://example.com/admin --service http --userlist users.txt --passlist pass.txt
```

**Python API:**
```python
from phantom_recon import BruteForcer

brute = BruteForcer(
    target="192.168.1.1",
    service="ssh",
    usernames=["admin", "root"],
    passwords=["password", "admin123"],
    threads=5
)
results = brute.run()

for cred in results["found"]:
    print(f"✅ {cred['username']}:{cred['password']}")
```

**Supported Protocols:**
- 🖥️ SSH (Paramiko)
- 📂 FTP
- 🌐 HTTP Basic Auth
- 📝 HTTP Form Auth

---

### 8. 🗺️ Network Mapping (`phantom network`)

Network discovery and mapping.

```bash
# Host discovery
phantom network --target 192.168.1.0/24 --discover

# Traceroute
phantom network --target 8.8.8.8 --traceroute
```

**Python API:**
```python
from phantom_recon import NetworkMapper

mapper = NetworkMapper(target="192.168.1.0/24")

# Discover live hosts
hosts = mapper.discover_hosts()
for host in hosts:
    print(f"{host['ip']} — {host['mac']} ({host['vendor']})")

# Traceroute
route = mapper.traceroute("8.8.8.8")
for hop in route:
    print(f"Hop {hop['ttl']}: {hop['ip']} ({hop['rtt']}ms)")
```

---

### 9. 📋 WHOIS Lookup (`phantom whois`)

Domain and IP registration information.

```bash
# Domain WHOIS
phantom whois --target example.com

# IP WHOIS
phantom whois --target 8.8.8.8
```

**Python API:**
```python
from phantom_recon import WhoisLookup

whois = WhoisLookup(target="example.com")
info = whois.lookup()

print(f"Registrar: {info['registrar']}")
print(f"Created: {info['creation_date']}")
print(f"Expires: {info['expiration_date']}")
print(f"Name Servers: {info['name_servers']}")
```

---

### 10. 📊 Report Generation (`phantom report`)

Generate professional reports from scan data.

```bash
# HTML report (recommended)
phantom report --input scan_results.json --format html --output report.html

# JSON structured report
phantom report --input scan_results.json --format json --output report.json

# Plain text
phantom report --input scan_results.json --format txt --output report.txt
```

**Python API:**
```python
from phantom_recon import ReportGenerator

report = ReportGenerator(scan_data=results)

# Generate HTML report
report.generate_html("report.html")

# Generate JSON report
report.generate_json("report.json")

# Generate text report
report.generate_text("report.txt")
```

---

### 🎯 Full Recon Pipeline (`phantom full`)

Run all modules in sequence for comprehensive reconnaissance.

```bash
# Complete recon pipeline
phantom full --target example.com --output full_report.html

# Full recon with verbose output
phantom full --target example.com --output report.html --verbose
```

This combines:
1. WHOIS Lookup → 2. DNS Enumeration → 3. Subdomain Discovery → 4. Port Scanning → 5. Web Recon → 6. SSL Analysis → 7. Header Analysis → 8. Vulnerability Scan → 9. Report Generation

---

## 🏗️ Project Structure

```
phantom-recon/
├── 📄 pyproject.toml          # Project configuration & dependencies
├── 📄 README.md               # This file
├── 📄 LICENSE                  # MIT License
├── 📄 CONTRIBUTING.md          # Contribution guidelines
├── 📄 SECURITY.md              # Security policy & responsible disclosure
├── 📄 .gitignore               # Git ignore rules
│
├── 🔥 phantom_recon/           # Main package
│   ├── __init__.py             # Package exports
│   ├── cli.py                  # CLI entry point (Click)
│   │
│   ├── 🧠 core/               # Core scanning modules
│   │   ├── __init__.py
│   │   ├── scanner.py          # Port scanner
│   │   ├── network.py          # Network mapper
│   │   ├── dns_enum.py         # DNS enumerator
│   │   ├── web_recon.py        # Web reconnaissance
│   │   ├── subdomain.py        # Subdomain finder
│   │   ├── vuln_scanner.py     # Vulnerability scanner
│   │   ├── brute.py            # Brute force module
│   │   ├── whois_lookup.py     # WHOIS lookup
│   │   ├── header_analyzer.py  # HTTP header analyzer
│   │   └── ssl_analyzer.py     # SSL/TLS analyzer
│   │
│   ├── 🛠️ utils/              # Utility modules
│   │   ├── __init__.py
│   │   ├── logger.py           # Rich logging & output
│   │   ├── validators.py       # Input validation
│   │   └── config.py           # Configuration management
│   │
│   └── 📊 reporting/          # Report generation
│       ├── __init__.py
│       ├── report_generator.py # Report engine
│       └── templates.py        # HTML report templates
│
├── 🧪 tests/                  # Test suite
│   ├── __init__.py
│   ├── test_scanner.py         # Port scanner tests
│   └── test_validators.py      # Validator tests
│
├── 📁 wordlists/              # Built-in wordlists
│   ├── subdomains.txt          # Common subdomains
│   ├── directories.txt         # Common web directories
│   └── credentials.txt         # Default credentials
│
└── 📁 reports/                 # Generated reports (gitignored)
```

---

## ⚙️ Configuration

### Config File (`phantom.yaml`)

```yaml
# Phantom Recon Configuration
general:
  timeout: 10
  threads: 50
  verbose: false
  output_format: html

scanner:
  default_ports: "1-1000"
  scan_type: connect
  service_detection: true

web_recon:
  user_agent: "Mozilla/5.0 (Phantom Recon/1.0)"
  follow_redirects: true
  max_depth: 3

brute_force:
  max_threads: 10
  delay: 0.5
  lockout_threshold: 5

reporting:
  format: html
  include_remediation: true
  severity_threshold: low
```

### Environment Variables

```bash
export PHANTOM_TIMEOUT=10
export PHANTOM_THREADS=50
export PHANTOM_OUTPUT_DIR=./reports
export PHANTOM_VERBOSE=true
export PHANTOM_USER_AGENT="Custom Agent"
```

---

## 🔧 Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/tahir/phantom-recon.git
cd phantom-recon

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate      # Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=phantom_recon --cov-report=html

# Run specific test file
pytest tests/test_scanner.py

# Run with verbose output
pytest -v
```

### Code Quality

```bash
# Format code
black phantom_recon/ tests/

# Lint
ruff check phantom_recon/ tests/

# Type checking
mypy phantom_recon/
```

---

## 📸 Screenshots

### CLI Banner
```
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗║
║   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║║
║   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║║
║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║║
║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║║
║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝║
║                                                                ║
║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗                 ║
║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║                 ║
║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                 ║
║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                 ║
║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║                 ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                 ║
║                                                                ║
║   🔥 Advanced Penetration Testing & Reconnaissance Toolkit     ║
║   📌 Version 1.0.0 | Author: Tahir | License: MIT             ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
```

---

## 🗺️ Roadmap

- [x] Core port scanning engine
- [x] Web reconnaissance module
- [x] DNS enumeration
- [x] Subdomain discovery
- [x] Vulnerability scanning
- [x] SSL/TLS analysis
- [x] Brute force module
- [x] Network mapping
- [x] WHOIS lookup
- [x] HTML/JSON/TXT report generation
- [ ] GUI web interface (Flask-based dashboard)
- [ ] API endpoint scanning (Swagger/OpenAPI)
- [ ] WAF detection & bypass techniques
- [ ] Wireless network scanning
- [ ] Social engineering toolkit
- [ ] Automated exploit suggestion
- [ ] Cloud infrastructure scanning (AWS/Azure/GCP)
- [ ] Docker container security scanning
- [ ] CI/CD pipeline integration
- [ ] Plugin system for custom modules

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a PR.

1. 🍴 Fork the repository
2. 🔧 Create a feature branch (`git checkout -b feature/amazing-feature`)
3. 💾 Commit changes (`git commit -m 'Add amazing feature'`)
4. 📤 Push to branch (`git push origin feature/amazing-feature`)
5. 📬 Open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Legal Disclaimer

**Phantom Recon** is designed for **legal and authorized** security testing purposes only. Usage of this toolkit for attacking targets without explicit mutual consent is **illegal**. The developers are not responsible for any misuse or damage caused by this tool.

**You are responsible for ensuring:**
- ✅ You have **written authorization** to test the target systems
- ✅ You comply with all **local, state, and federal laws**
- ✅ You follow **responsible disclosure** practices
- ✅ You use this tool in an **ethical manner**

---

## 🌟 Star History

If you find Phantom Recon useful, please consider giving it a ⭐ star on GitHub!

---

<p align="center">
  <strong>Built with ❤️ by <a href="https://github.com/Tahir-Omicron">Tahir</a></strong>
</p>

<p align="center">
  <sub>🔐 Hack Responsibly. Stay Ethical. 🔐</sub>
</p>
