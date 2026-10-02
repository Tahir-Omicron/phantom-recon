"""
Phantom Recon — Ultra-Modern Enterprise Security Dashboard (v1.2.0).

State-of-the-art dark glassmorphism cybersecurity report template featuring
real-time interactive search, severity filtering, SVG security health gauge,
exact location pills, 1-click PoC reproduction, and PDF print styling.
"""

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phantom Recon Security Audit — {{ data.get('target', 'Target') }}</title>
    <!-- Modern Typography -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #06080f;
            --bg-card: rgba(14, 19, 36, 0.75);
            --bg-card-hover: rgba(20, 27, 50, 0.85);
            --bg-inner: rgba(8, 12, 24, 0.6);
            --border: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(6, 182, 212, 0.5);
            
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
            --text-dim: #64748b;

            --neon-red: #ff3366;
            --neon-orange: #ff9100;
            --neon-yellow: #ffd600;
            --neon-green: #00e676;
            --neon-cyan: #00e5ff;
            --neon-blue: #2979ff;
            --neon-purple: #d500f9;

            --glow-cyan: 0 0 25px rgba(0, 229, 255, 0.35);
            --glow-red: 0 0 25px rgba(255, 51, 102, 0.35);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background-color: var(--bg-base);
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(0, 229, 255, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 85% 20%, rgba(255, 51, 102, 0.07) 0%, transparent 45%),
                radial-gradient(circle at 50% 80%, rgba(41, 121, 255, 0.06) 0%, transparent 50%);
            color: var(--text-main);
            font-family: 'Inter', -apple-system, sans-serif;
            line-height: 1.6;
            min-height: 100vh;
            overflow-x: hidden;
        }

        .container {
            max-width: 1360px;
            margin: 0 auto;
            padding: 40px 24px 80px;
        }

        /* Top Bar */
        .top-navbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 24px;
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 16px;
            margin-bottom: 36px;
        }

        .brand-logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.35em;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, var(--neon-cyan), var(--neon-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .top-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .btn-action {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border);
            color: var(--text-main);
            font-size: 0.85em;
            font-weight: 600;
            padding: 8px 16px;
            border-radius: 10px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.25s ease;
            text-decoration: none;
        }

        .btn-action:hover {
            background: rgba(255, 255, 255, 0.12);
            border-color: var(--neon-cyan);
            box-shadow: 0 0 15px rgba(0, 229, 255, 0.25);
            transform: translateY(-1px);
        }

        /* Hero Banner & Security Gauge */
        .hero-banner {
            display: grid;
            grid-template-columns: 1fr auto;
            align-items: center;
            gap: 32px;
            background: var(--bg-card);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 40px;
            margin-bottom: 36px;
            position: relative;
            overflow: hidden;
        }

        .hero-banner::after {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 3px;
            background: linear-gradient(90deg, var(--neon-red), var(--neon-orange), var(--neon-yellow), var(--neon-cyan));
        }

        .hero-info h1 {
            font-size: 2.6em;
            font-weight: 800;
            line-height: 1.15;
            margin-bottom: 12px;
            letter-spacing: -0.8px;
        }

        .hero-info .meta-desc {
            color: var(--text-sub);
            font-size: 1.05em;
            margin-bottom: 24px;
            max-width: 600px;
        }

        .target-chips {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
        }

        .chip {
            background: var(--bg-inner);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 6px 14px;
            font-size: 0.85em;
            color: var(--text-sub);
        }

        .chip strong {
            color: var(--text-main);
        }

        /* Circular Score Gauge */
        .gauge-wrapper {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-width: 170px;
        }

        .gauge-circle {
            position: relative;
            width: 130px;
            height: 130px;
        }

        .gauge-circle svg {
            width: 100%;
            height: 100%;
            transform: rotate(-90deg);
        }

        .gauge-bg {
            fill: none;
            stroke: rgba(255, 255, 255, 0.08);
            stroke-width: 10;
        }

        .gauge-fill {
            fill: none;
            stroke: var(--neon-cyan);
            stroke-width: 10;
            stroke-linecap: round;
            stroke-dasharray: 314;
            stroke-dashoffset: 60;
            transition: stroke-dashoffset 1s ease;
        }

        .gauge-value {
            position: absolute;
            inset: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-size: 1.8em;
            font-weight: 800;
            line-height: 1;
        }

        .gauge-label {
            font-size: 0.4em;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }

        /* Metric Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 36px;
        }

        .stat-card {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 24px;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
        }

        .stat-card:hover {
            border-color: var(--border-hover);
            transform: translateY(-3px);
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.4);
        }

        .stat-number {
            font-size: 2.5em;
            font-weight: 800;
            line-height: 1.1;
            margin-bottom: 6px;
        }

        .stat-title {
            color: var(--text-dim);
            font-size: 0.85em;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.6px;
        }

        /* Search & Filter Control Bar */
        .control-bar {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            margin-bottom: 28px;
            flex-wrap: wrap;
        }

        .search-box {
            position: relative;
            flex: 1;
            min-width: 260px;
        }

        .search-input {
            width: 100%;
            background: var(--bg-inner);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 12px 18px 12px 42px;
            color: var(--text-main);
            font-family: inherit;
            font-size: 0.9em;
            outline: none;
            transition: all 0.25s ease;
        }

        .search-input:focus {
            border-color: var(--neon-cyan);
            box-shadow: 0 0 15px rgba(0, 229, 255, 0.2);
        }

        .search-icon {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-dim);
            pointer-events: none;
        }

        .filter-tabs {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .filter-btn {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-sub);
            padding: 8px 16px;
            border-radius: 10px;
            font-size: 0.82em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .filter-btn:hover {
            color: var(--text-main);
            border-color: rgba(255, 255, 255, 0.25);
        }

        .filter-btn.active {
            background: var(--neon-cyan);
            border-color: var(--neon-cyan);
            color: #03131c;
            box-shadow: 0 0 15px rgba(0, 229, 255, 0.35);
        }

        /* Vulnerability Findings Section */
        .vuln-list {
            display: flex;
            flex-direction: column;
            gap: 20px;
            margin-bottom: 40px;
        }

        .vuln-card {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 26px;
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            position: relative;
            overflow: hidden;
        }

        .vuln-card:hover {
            border-color: rgba(255, 255, 255, 0.2);
            box-shadow: 0 14px 40px rgba(0, 0, 0, 0.45);
        }

        .vuln-card.critical { border-left: 5px solid var(--neon-red); }
        .vuln-card.high { border-left: 5px solid var(--neon-orange); }
        .vuln-card.medium { border-left: 5px solid var(--neon-yellow); }
        .vuln-card.low { border-left: 5px solid var(--neon-blue); }
        .vuln-card.info { border-left: 5px solid var(--text-dim); }

        .vuln-top {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 14px;
            flex-wrap: wrap;
        }

        .badge-group {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: 8px;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75em;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-critical { background: rgba(255, 51, 102, 0.15); color: #ff6b8b; border: 1px solid var(--neon-red); }
        .badge-high { background: rgba(255, 145, 0, 0.15); color: #ffb74d; border: 1px solid var(--neon-orange); }
        .badge-medium { background: rgba(255, 214, 0, 0.15); color: #fff59d; border: 1px solid var(--neon-yellow); }
        .badge-low { background: rgba(41, 121, 255, 0.15); color: #82b1ff; border: 1px solid var(--neon-blue); }
        .badge-info { background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid var(--text-dim); }
        .badge-verified { background: rgba(0, 230, 118, 0.15); color: #69f0ae; border: 1px solid var(--neon-green); }

        .vuln-title {
            font-size: 1.25em;
            font-weight: 700;
            color: var(--text-main);
        }

        /* Location Banner & Quick Actions */
        .location-strip {
            background: rgba(0, 229, 255, 0.06);
            border: 1px solid rgba(0, 229, 255, 0.2);
            border-radius: 12px;
            padding: 12px 18px;
            margin: 14px 0 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            flex-wrap: wrap;
        }

        .location-info {
            display: flex;
            align-items: center;
            gap: 10px;
            font-family: 'Fira Code', monospace;
            font-size: 0.88em;
            color: #38bdf8;
            word-break: break-all;
        }

        .quick-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .btn-jump {
            background: var(--neon-cyan);
            color: #021722;
            font-weight: 700;
            font-size: 0.82em;
            text-decoration: none;
            padding: 7px 16px;
            border-radius: 8px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s ease;
        }

        .btn-jump:hover {
            background: #38e1ff;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0, 229, 255, 0.45);
        }

        .btn-copy {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid var(--border);
            color: var(--text-main);
            font-size: 0.82em;
            font-weight: 600;
            padding: 7px 14px;
            border-radius: 8px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s ease;
        }

        .btn-copy:hover {
            background: rgba(255, 255, 255, 0.14);
            border-color: var(--text-sub);
            transform: translateY(-1px);
        }

        .vuln-desc {
            color: var(--text-sub);
            font-size: 0.95em;
            margin-bottom: 16px;
        }

        /* Technical Evidence Box */
        .evidence-panel {
            background: #04060c;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 14px 18px;
            margin: 14px 0;
            font-family: 'Fira Code', monospace;
            font-size: 0.82em;
            color: #e2e8f0;
            white-space: pre-wrap;
            word-break: break-word;
            position: relative;
        }

        .evidence-header {
            font-size: 0.72em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-dim);
            margin-bottom: 6px;
            font-weight: 700;
        }

        /* Mitigation Box */
        .mitigation-panel {
            background: rgba(0, 230, 118, 0.06);
            border-left: 4px solid var(--neon-green);
            padding: 12px 18px;
            border-radius: 0 10px 10px 0;
            font-size: 0.9em;
            color: #bbf7d0;
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }

        .mitigation-panel strong {
            color: #4ade80;
        }

        /* Tables for Ports & Subdomains */
        .content-card {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 28px;
            margin-bottom: 32px;
        }

        .content-title {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 1.35em;
            font-weight: 700;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 14px 18px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: rgba(255, 255, 255, 0.02);
            color: var(--neon-cyan);
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            font-weight: 700;
        }

        tr:hover td {
            background: rgba(0, 229, 255, 0.03);
        }

        /* Toast Feedback */
        .toast {
            position: fixed;
            bottom: 28px;
            right: 28px;
            background: var(--neon-green);
            color: #022013;
            font-weight: 700;
            padding: 14px 24px;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            pointer-events: none;
            z-index: 9999;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .toast.show {
            opacity: 1;
            transform: translateY(0);
        }

        /* Footer */
        .footer {
            text-align: center;
            padding-top: 48px;
            color: var(--text-dim);
            font-size: 0.88em;
            border-top: 1px solid var(--border);
        }

        /* Print Mode */
        @media print {
            body { background: white !important; color: black !important; }
            .top-navbar, .control-bar, .action-buttons, .toast { display: none !important; }
            .vuln-card, .stat-card, .hero-banner, .content-card {
                border: 1px solid #ccc !important;
                background: none !important;
                box-shadow: none !important;
                break-inside: avoid;
            }
            .location-strip { background: #f0f0f0 !important; color: black !important; }
            th { background: #eee !important; color: #333 !important; }
        }

        @media (max-width: 768px) {
            .hero-banner { grid-template-columns: 1fr; }
            .control-bar { flex-direction: column; }
            .search-box { width: 100%; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Top Navbar -->
        <nav class="top-navbar">
            <div class="brand-logo">
                <span>🔥</span> PHANTOM RECON
            </div>
            <div class="top-actions">
                <button class="btn-action" onclick="window.print()">
                    🖨️ Print / PDF
                </button>
                <button class="btn-action" onclick="downloadCSV()">
                    📊 Export CSV
                </button>
                <button class="btn-action" onclick="downloadJSON()">
                    📥 Export JSON
                </button>
            </div>
        </nav>

        <!-- Hero Banner with Security Score Gauge -->
        <header class="hero-banner">
            <div class="hero-info">
                <h1>Security Audit Report</h1>
                <p class="meta-desc">Comprehensive vulnerability intelligence and penetration testing report with verified proof-of-concept validation.</p>
                <div class="target-chips">
                    <span class="chip">🎯 Target: <strong>{{ data.get('target', 'N/A') }}</strong></span>
                    <span class="chip">⏱️ Audit Time: <strong>{{ generated_at }}</strong></span>
                    <span class="chip">⚡ Duration: <strong>{{ data.get('duration', 'N/A') }}s</strong></span>
                    <span class="chip">🛡️ Engine: <strong>Phantom Recon v1.6.0 (Zero False Positive)</strong></span>
                </div>
            </div>

            <!-- Health Gauge Ring -->
            <div class="gauge-wrapper">
                <div class="gauge-circle">
                    <svg viewBox="0 0 100 100">
                        <circle class="gauge-bg" cx="50" cy="50" r="42" />
                        <circle id="gaugeFill" class="gauge-fill" cx="50" cy="50" r="42" />
                    </svg>
                    <div class="gauge-value">
                        <span id="scoreText">--</span>
                        <span class="gauge-label">Score</span>
                    </div>
                </div>
            </div>
        </header>

        <!-- Metrics Overview -->
        <section class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" style="color: var(--neon-red);" id="countVulns">
                    {{ data.get('vulnerabilities', [])|length }}
                </div>
                <div class="stat-title">Confirmed Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: var(--neon-cyan);">
                    {{ data.get('ports', {})|length }}
                </div>
                <div class="stat-title">Open Port Services</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: var(--neon-orange);">
                    {{ data.get('subdomains', [])|length }}
                </div>
                <div class="stat-title">Discovered Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: var(--neon-green);">
                    {{ data.get('headers', {}).get('grade', 'A') }}
                </div>
                <div class="stat-title">Header Security Grade</div>
            </div>
        </section>

        <!-- Search & Filter Controls -->
        {% if data.get('vulnerabilities') %}
        <div class="control-bar">
            <div class="search-box">
                <span class="search-icon">🔍</span>
                <input type="text" id="searchInput" class="search-input" placeholder="Search by title, location, CVE, or parameter..." oninput="filterFindings()">
            </div>
            <div class="filter-tabs">
                <button class="filter-btn active" onclick="setSeverityFilter('all', this)">All ({{ data.get('vulnerabilities', [])|length }})</button>
                <button class="filter-btn" onclick="setSeverityFilter('critical', this)">Critical</button>
                <button class="filter-btn" onclick="setSeverityFilter('high', this)">High</button>
                <button class="filter-btn" onclick="setSeverityFilter('medium', this)">Medium</button>
                <button class="filter-btn" onclick="setSeverityFilter('low', this)">Low</button>
                <button class="filter-btn" onclick="setSeverityFilter('info', this)">Info</button>
            </div>
        </div>

        <!-- Vulnerability Findings List -->
        <section class="vuln-list" id="vulnList">
            {% for vuln in data.get('vulnerabilities', []) %}
            <article class="vuln-card {{ vuln.get('severity', 'info')|lower }}" data-severity="{{ vuln.get('severity', 'info')|lower }}">
                <div class="vuln-top">
                    <div>
                        <div class="badge-group">
                            <span class="badge badge-{{ vuln.get('severity', 'info')|lower }}">
                                {{ vuln.get('severity', 'info') }}
                            </span>
                            {% if vuln.get('cvss_score') %}
                            <span class="badge" style="background: rgba(255,255,255,0.06); color: var(--text-main); border: 1px solid var(--border);">
                                CVSS {{ vuln.get('cvss_score') }}
                            </span>
                            {% endif %}
                            <span class="badge badge-verified">
                                ✓ {{ vuln.get('confidence', 'CONFIRMED') }}
                            </span>
                            {% if vuln.get('cve') %}
                            <span class="badge" style="background: rgba(41, 121, 255, 0.15); color: #82b1ff; border: 1px solid var(--neon-blue);">
                                {{ vuln.get('cve') }}
                            </span>
                            {% endif %}
                        </div>
                        <h3 class="vuln-title">{{ vuln.get('title', 'Unknown Finding') }}</h3>
                    </div>
                </div>

                <!-- Location & Direct Link Bar -->
                <div class="location-strip">
                    <div class="location-info">
                        <span>📍 <strong>Location:</strong> {{ vuln.get('location', 'Global Target') }}</span>
                    </div>
                    <div class="quick-actions">
                        {% if vuln.get('poc_url') %}
                        <a href="{{ vuln.get('poc_url') }}" target="_blank" rel="noopener noreferrer" class="btn-jump">
                            🔗 Open in Browser
                        </a>
                        {% endif %}
                        {% if vuln.get('reproduce_curl') %}
                        <button class="btn-copy" onclick="copyText(`{{ vuln.get('reproduce_curl')|replace('`', '\\`') }}`)">
                            📋 Copy PoC cURL
                        </button>
                        {% endif %}
                    </div>
                </div>

                <p class="vuln-desc">{{ vuln.get('description', '') }}</p>

                {% if vuln.get('evidence') %}
                <div class="evidence-panel">
                    <div class="evidence-header">Verified Evidence & Proof-of-Concept:</div>
                    {{ vuln.get('evidence') }}
                </div>
                {% endif %}

                {% if vuln.get('remediation') %}
                <div class="mitigation-panel">
                    <div>
                        <strong>💡 Actionable Remediation:</strong> {{ vuln.get('remediation') }}
                    </div>
                </div>
                {% endif %}
            </article>
            {% endfor %}
        </section>
        {% endif %}

        <!-- WAF & Origin IP Exposure Section -->
        {% if data.get('waf') %}
        <section class="content-card">
            <div class="content-title">
                <span>🛡️ Web Application Firewall & Origin IP Analysis</span>
                {% if data.get('waf', {}).get('has_waf') %}
                <span class="badge badge-critical" style="background: rgba(255, 51, 102, 0.2); border: 1px solid var(--neon-red); color: var(--neon-red);">PROTECTED: {{ data.get('waf', {}).get('waf_name') }}</span>
                {% else %}
                <span class="badge badge-verified">DIRECT HOST / NO WAF</span>
                {% endif %}
            </div>
            
            <div style="margin-bottom: 1.2rem; line-height: 1.8;">
                <p><strong>Identified Provider:</strong> <span style="color: var(--neon-cyan); font-weight: 600;">{{ data.get('waf', {}).get('waf_name', 'None') }}</span></p>
                {% if data.get('waf', {}).get('resolved_ips') %}
                <p><strong>Resolved Edge IPs:</strong> <code>{{ data.get('waf', {}).get('resolved_ips')|join(', ') }}</code></p>
                {% endif %}
                {% if data.get('waf', {}).get('warning') %}
                <div class="evidence-panel" style="margin-top: 0.8rem; border-left: 4px solid var(--neon-orange); color: #ffb74d;">
                    {{ data.get('waf', {}).get('warning') }}
                </div>
                {% endif %}
            </div>

            {% if data.get('waf', {}).get('origin_leakage', {}).get('unprotected_origin_candidates') %}
            <h4 style="color: var(--neon-red); margin: 1.2rem 0 0.6rem 0;">🚨 Potential Unproxied Backend Origin IPs (WAF Bypass Risk)</h4>
            <table>
                <thead>
                    <tr>
                        <th>Candidate IP</th>
                        <th>Hostname</th>
                        <th>Discovery Source</th>
                        <th>Evidence / Note</th>
                    </tr>
                </thead>
                <tbody>
                    {% for cand in data.get('waf', {}).get('origin_leakage', {}).get('unprotected_origin_candidates') %}
                    <tr>
                        <td><code style="color: var(--neon-red); font-weight: 700;">{{ cand.get('ip') }}</code></td>
                        <td><strong>{{ cand.get('hostname') }}</strong></td>
                        <td><span class="badge" style="background: rgba(255, 145, 0, 0.15); color: #ffb74d; border: 1px solid var(--neon-orange);">{{ cand.get('source') }}</span></td>
                        <td><span style="color: var(--text-sub); font-size: 0.9em;">{{ cand.get('evidence') }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
        </section>
        {% endif %}

        <!-- API & Documentation Discovery Section -->
        {% if data.get('api_endpoints') %}
        <section class="content-card">
            <div class="content-title">
                <span>🔌 Discovered API Schemas & Documentation Portals</span>
                <span class="badge" style="background: rgba(0, 229, 255, 0.15); border: 1px solid var(--neon-cyan); color: var(--neon-cyan);">{{ data.get('api_endpoints', [])|length }} endpoints active</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>API Path</th>
                        <th>Architecture Type</th>
                        <th>Status</th>
                        <th>Evidence / Response Details</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ep in data.get('api_endpoints', []) %}
                    <tr>
                        <td><code style="color: var(--neon-cyan); font-weight: 700;">{{ ep.get('path') }}</code></td>
                        <td><span class="badge" style="background: rgba(213, 0, 249, 0.15); color: #ea80fc; border: 1px solid var(--neon-purple);">{{ ep.get('type') }}</span></td>
                        <td><span class="badge badge-verified">{{ ep.get('status_code', 200) }}</span></td>
                        <td><span style="color: var(--text-sub); font-size: 0.9em;">{{ ep.get('evidence') }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}

        <!-- Open Ports Section -->
        {% if data.get('ports') %}
        <section class="content-card">
            <div class="content-title">
                <span>🔍 Open Network Services & Banners</span>
                <span style="font-size: 0.75em; color: var(--text-dim);">{{ data.get('ports', {})|length }} active</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Port / Protocol</th>
                        <th>State</th>
                        <th>Service Detection</th>
                        <th>Banner / Version Info</th>
                    </tr>
                </thead>
                <tbody>
                    {% for port, info in data.get('ports', {}).items() %}
                    <tr>
                        <td><code style="color: var(--neon-cyan); font-weight: 600;">{{ port }}/tcp</code></td>
                        <td><span class="badge badge-verified">OPEN</span></td>
                        <td><strong>{{ info.get('service', 'unknown') }}</strong></td>
                        <td><code style="color: var(--text-sub);">{{ info.get('banner', '')[:100] or '-' }}</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}

        <!-- Discovered Subdomains -->
        {% if data.get('subdomains') %}
        <section class="content-card">
            <div class="content-title">
                <span>🔎 Discovered Subdomains & Live Endpoints</span>
                <span style="font-size: 0.75em; color: var(--text-dim);">{{ data.get('subdomains', [])|length }} resolved</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Resolved IP</th>
                        <th>HTTP Status</th>
                        <th>Direct Link</th>
                    </tr>
                </thead>
                <tbody>
                    {% for sub in data.get('subdomains', []) %}
                    <tr>
                        <td><strong>{{ sub.get('subdomain', '') }}</strong></td>
                        <td><code>{{ sub.get('ip', 'N/A') }}</code></td>
                        <td><span class="badge badge-info">{{ sub.get('status_code', 'N/A') }}</span></td>
                        <td><a href="http://{{ sub.get('subdomain', '') }}" target="_blank" rel="noopener noreferrer" style="color: var(--neon-cyan); text-decoration: none; font-weight: 600;">🔗 Open</a></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}

        <footer class="footer">
            <p>Generated by <strong>Phantom Recon Security Engine</strong>. Authorized testing results only.</p>
        </footer>
    </div>

    <!-- Toast Notification -->
    <div id="toast" class="toast">
        <span>✓</span> <span>PoC cURL command copied to clipboard!</span>
    </div>

    <script>
        // Copy text utility with toast animation
        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                const toast = document.getElementById('toast');
                toast.classList.add('show');
                setTimeout(() => {
                    toast.classList.remove('show');
                }, 2200);
            }).catch(err => {
                alert("Copy failed: " + err);
            });
        }

        // Live search and filtering
        let currentFilter = 'all';

        function setSeverityFilter(sev, btn) {
            currentFilter = sev;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterFindings();
        }

        function filterFindings() {
            const query = (document.getElementById('searchInput')?.value || '').toLowerCase();
            const cards = document.querySelectorAll('.vuln-card');

            cards.forEach(card => {
                const sev = card.getAttribute('data-severity');
                const text = card.innerText.toLowerCase();

                const matchesFilter = (currentFilter === 'all' || sev === currentFilter);
                const matchesSearch = query === '' || text.includes(query);

                if (matchesFilter && matchesSearch) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        // Calculate dynamic security health score
        function calculateSecurityScore() {
            const cards = document.querySelectorAll('.vuln-card');
            let deduction = 0;

            cards.forEach(card => {
                const sev = card.getAttribute('data-severity');
                if (sev === 'critical') deduction += 30;
                else if (sev === 'high') deduction += 15;
                else if (sev === 'medium') deduction += 7;
                else if (sev === 'low') deduction += 3;
            });

            let score = Math.max(0, 100 - deduction);
            const scoreEl = document.getElementById('scoreText');
            const gaugeFill = document.getElementById('gaugeFill');

            if (scoreEl) scoreEl.innerText = score;
            if (gaugeFill) {
                // Circumference = 2 * PI * 42 ≈ 264
                const circumference = 264;
                const offset = circumference - (circumference * (score / 100));
                gaugeFill.style.strokeDasharray = circumference;
                gaugeFill.style.strokeDashoffset = offset;

                if (score >= 80) {
                    gaugeFill.style.stroke = 'var(--neon-green)';
                } else if (score >= 50) {
                    gaugeFill.style.stroke = 'var(--neon-yellow)';
                } else {
                    gaugeFill.style.stroke = 'var(--neon-red)';
                }
            }
        }

        // Download CSV report utility
        function downloadCSV() {
            const rawData = {{ data|tojson }};
            const vulns = rawData.vulnerabilities || [];
            if (!vulns.length) {
                alert("No vulnerabilities recorded to export.");
                return;
            }
            const headers = ["ID", "Title", "Severity", "CVSS", "Location", "Direct URL", "PoC cURL", "Evidence", "Remediation"];
            const rows = vulns.map((v, i) => [
                i + 1,
                `"${(v.title || '').replace(/"/g, '""')}"`,
                `"${(v.severity || '').toUpperCase()}"`,
                v.cvss_score || 0.0,
                `"${(v.location || '').replace(/"/g, '""')}"`,
                `"${(v.poc_url || v.url || '').replace(/"/g, '""')}"`,
                `"${(v.reproduce_curl || '').replace(/"/g, '""')}"`,
                `"${(v.evidence || '').replace(/"/g, '""')}"`,
                `"${(v.remediation || '').replace(/"/g, '""')}"`
            ]);
            let csvContent = "\uFEFF" + headers.join(",") + "\n" + rows.map(r => r.join(",")).join("\n");
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = "phantom_recon_findings.csv";
            a.click();
            URL.revokeObjectURL(url);
        }

        // Download JSON report utility
        function downloadJSON() {
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({{ data|tojson }}, null, 2));
            const dlAnchor = document.createElement('a');
            dlAnchor.setAttribute("href", dataStr);
            dlAnchor.setAttribute("download", "phantom_recon_audit.json");
            dlAnchor.click();
        }

        window.addEventListener('DOMContentLoaded', calculateSecurityScore);
    </script>
</body>
</html>"""
