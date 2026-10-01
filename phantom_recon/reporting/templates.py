"""
Phantom Recon — HTML Report Templates (v1.1.0).

Professional interactive cybersecurity report template featuring exact vulnerability
locations, direct clickable jump links, 1-click cURL PoC copy buttons, and
modern glassmorphism styling.
"""

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phantom Recon Report — {{ data.get('target', 'Target') }}</title>
    <style>
        :root {
            --bg-primary: #0a0c14;
            --bg-secondary: #101424;
            --bg-card: rgba(22, 28, 48, 0.7);
            --bg-glass: rgba(255, 255, 255, 0.03);
            --text-primary: #f0f4f8;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-yellow: #eab308;
            --accent-green: #10b981;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --border: rgba(148, 163, 184, 0.15);
            --border-hover: rgba(6, 182, 212, 0.4);
            --glow-cyan: 0 0 20px rgba(6, 182, 212, 0.25);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: var(--bg-primary);
            background-image: radial-gradient(circle at 10% 20%, rgba(6, 182, 212, 0.05) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(239, 68, 68, 0.05) 0%, transparent 40%);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            min-height: 100vh;
        }

        .container {
            max-width: 1280px;
            margin: 0 auto;
            padding: 40px 24px;
        }

        /* Top Header */
        .report-header {
            text-align: center;
            padding: 48px 24px 32px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 36px;
            position: relative;
        }

        .report-header h1 {
            font-size: 2.8em;
            font-weight: 800;
            background: linear-gradient(135deg, #ff4d4d, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }

        .report-header .subtitle {
            color: var(--text-secondary);
            font-size: 1.15em;
            max-width: 650px;
            margin: 0 auto;
        }

        .meta-tags {
            display: flex;
            justify-content: center;
            gap: 16px;
            flex-wrap: wrap;
            margin-top: 24px;
        }

        .meta-pill {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 9999px;
            padding: 6px 16px;
            font-size: 0.85em;
            color: var(--text-secondary);
        }

        .meta-pill strong {
            color: var(--text-primary);
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 36px;
        }

        .stat-card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            text-align: center;
            transition: all 0.3s ease;
        }

        .stat-card:hover {
            border-color: var(--border-hover);
            transform: translateY(-2px);
            box-shadow: var(--glow-cyan);
        }

        .stat-value {
            font-size: 2.4em;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 8px;
        }

        .stat-label {
            color: var(--text-muted);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Sections */
        .section-card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            margin-bottom: 32px;
        }

        .section-title {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 1.4em;
            font-weight: 700;
            color: var(--text-primary);
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }

        /* Vulnerability Cards */
        .vuln-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 22px;
            margin-bottom: 20px;
            transition: all 0.25s ease;
            position: relative;
        }

        .vuln-item:hover {
            border-color: rgba(255, 255, 255, 0.2);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
        }

        .vuln-item.critical { border-left: 5px solid var(--accent-red); }
        .vuln-item.high { border-left: 5px solid var(--accent-orange); }
        .vuln-item.medium { border-left: 5px solid var(--accent-yellow); }
        .vuln-item.low { border-left: 5px solid var(--accent-blue); }
        .vuln-item.info { border-left: 5px solid var(--text-muted); }

        .vuln-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }

        .vuln-title {
            font-size: 1.2em;
            font-weight: 700;
            color: var(--text-primary);
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

        .badge-critical { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--accent-red); }
        .badge-high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid var(--accent-orange); }
        .badge-medium { background: rgba(234, 179, 8, 0.2); color: #fef08a; border: 1px solid var(--accent-yellow); }
        .badge-low { background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid var(--accent-blue); }
        .badge-info { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid var(--border); }

        /* Location Bar & Quick Jump */
        .location-banner {
            background: rgba(6, 182, 212, 0.08);
            border: 1px solid rgba(6, 182, 212, 0.25);
            border-radius: 8px;
            padding: 10px 14px;
            margin: 12px 0 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
        }

        .location-text {
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 0.88em;
            color: #67e8f9;
            display: flex;
            align-items: center;
            gap: 8px;
            word-break: break-all;
        }

        .action-buttons {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .btn-jump {
            background: var(--accent-cyan);
            color: #04141e;
            font-weight: 700;
            font-size: 0.82em;
            text-decoration: none;
            padding: 6px 14px;
            border-radius: 6px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s ease;
        }

        .btn-jump:hover {
            background: #22d3ee;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(6, 182, 212, 0.4);
        }

        .btn-copy {
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-primary);
            border: 1px solid var(--border);
            font-size: 0.82em;
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s ease;
        }

        .btn-copy:hover {
            background: rgba(255, 255, 255, 0.16);
            border-color: var(--text-secondary);
        }

        /* Description & Remediation */
        .vuln-desc {
            color: var(--text-secondary);
            font-size: 0.95em;
            margin-bottom: 14px;
        }

        .evidence-box {
            background: #080a12;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 12px 14px;
            margin: 12px 0;
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 0.83em;
            color: #e2e8f0;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .remedy-box {
            background: rgba(16, 185, 129, 0.08);
            border-left: 3px solid var(--accent-green);
            padding: 10px 14px;
            border-radius: 0 6px 6px 0;
            font-size: 0.9em;
            color: #a7f3d0;
        }

        .remedy-box strong {
            color: #34d399;
        }

        /* Tables for Port / Recon */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
        }

        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: rgba(255, 255, 255, 0.02);
            color: var(--accent-cyan);
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        tr:hover td {
            background: rgba(6, 182, 212, 0.03);
        }

        /* Toast notification */
        .toast {
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: #10b981;
            color: #032015;
            font-weight: 700;
            padding: 12px 20px;
            border-radius: 8px;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            pointer-events: none;
            z-index: 9999;
        }

        .toast.show {
            opacity: 1;
            transform: translateY(0);
        }

        .footer {
            text-align: center;
            padding: 40px 0;
            color: var(--text-muted);
            font-size: 0.85em;
            border-top: 1px solid var(--border);
            margin-top: 48px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="report-header">
            <h1>🔥 Phantom Recon Report</h1>
            <p class="subtitle">Comprehensive Security Assessment with Precise Vulnerability Tracking</p>
            <div class="meta-tags">
                <span class="meta-pill">Target: <strong>{{ data.get('target', 'N/A') }}</strong></span>
                <span class="meta-pill">Generated: <strong>{{ generated_at }}</strong></span>
                <span class="meta-pill">Duration: <strong>{{ data.get('duration', 'N/A') }}s</strong></span>
                <span class="meta-pill">Toolkit: <strong>Phantom Recon v1.1.0</strong></span>
            </div>
        </header>

        <!-- Stats Grid -->
        <section class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" style="color: var(--accent-cyan);">{{ data.get('ports', {})|length }}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--accent-red);">{{ data.get('vulnerabilities', [])|length }}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--accent-orange);">{{ data.get('subdomains', [])|length }}</div>
                <div class="stat-label">Discovered Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--accent-green);">{{ data.get('headers', {}).get('grade', 'N/A') }}</div>
                <div class="stat-label">Header Security Grade</div>
            </div>
        </section>

        <!-- Vulnerabilities Section -->
        {% if data.get('vulnerabilities') %}
        <section class="section-card">
            <div class="section-title">
                <span>🛡️ Identified Vulnerabilities & Direct Jump Links</span>
                <span style="font-size: 0.75em; color: var(--text-muted);">{{ data.get('vulnerabilities', [])|length }} findings</span>
            </div>

            {% for vuln in data.get('vulnerabilities', []) %}
            <article class="vuln-item {{ vuln.get('severity', 'info')|lower }}">
                <div class="vuln-header">
                    <div>
                        <span class="badge badge-{{ vuln.get('severity', 'info')|lower }}">
                            {{ vuln.get('severity', 'info') }}
                        </span>
                        {% if vuln.get('cvss_score') %}
                        <span class="badge" style="background: rgba(255,255,255,0.08); color: var(--text-primary); border: 1px solid var(--border);">
                            CVSS {{ vuln.get('cvss_score') }}
                        </span>
                        {% endif %}
                        <h3 class="vuln-title" style="margin-top: 8px;">{{ vuln.get('title', 'Unknown Vulnerability') }}</h3>
                    </div>
                </div>

                <!-- Location & Direct Link Bar -->
                <div class="location-banner">
                    <div class="location-text">
                        <span>📍 <strong>Location:</strong> {{ vuln.get('location', 'Global Application') }}</span>
                    </div>
                    <div class="action-buttons">
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
                <div style="margin-bottom: 8px;">
                    <span style="font-size: 0.8em; color: var(--text-muted); text-transform: uppercase;">Proof & Evidence:</span>
                    <div class="evidence-box">{{ vuln.get('evidence') }}</div>
                </div>
                {% endif %}

                {% if vuln.get('remediation') %}
                <div class="remedy-box">
                    <strong>💡 Remediation:</strong> {{ vuln.get('remediation') }}
                </div>
                {% endif %}
            </article>
            {% endfor %}
        </section>
        {% endif %}

        <!-- Port Scan Section -->
        {% if data.get('ports') %}
        <section class="section-card">
            <div class="section-title">
                <span>🔍 Open Port Scan Results</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Port / Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Banner / Version</th>
                    </tr>
                </thead>
                <tbody>
                    {% for port, info in data.get('ports', {}).items() %}
                    <tr>
                        <td><code>{{ port }}/tcp</code></td>
                        <td><span class="badge badge-low" style="background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border-color: var(--accent-green);">{{ info.get('state', 'open') }}</span></td>
                        <td><strong>{{ info.get('service', 'unknown') }}</strong></td>
                        <td><code style="color: var(--text-muted);">{{ info.get('banner', '')[:90] or '-' }}</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}

        <!-- Subdomain Section -->
        {% if data.get('subdomains') %}
        <section class="section-card">
            <div class="section-title">
                <span>🔎 Discovered Subdomains</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Address</th>
                        <th>Status Code</th>
                        <th>Direct Link</th>
                    </tr>
                </thead>
                <tbody>
                    {% for sub in data.get('subdomains', []) %}
                    <tr>
                        <td><strong>{{ sub.get('subdomain', '') }}</strong></td>
                        <td><code>{{ sub.get('ip', 'N/A') }}</code></td>
                        <td>{{ sub.get('status_code', '-') }}</td>
                        <td><a href="http://{{ sub.get('subdomain', '') }}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan); text-decoration: none;">🔗 Open</a></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}

        <!-- Footer -->
        <footer class="footer">
            <p>Generated automatically with <strong>Phantom Recon</strong> Penetration Testing Engine.</p>
            <p style="margin-top: 6px;">⚠️ Authorized security testing report. Confidentially handle findings.</p>
        </footer>
    </div>

    <!-- Toast Notification -->
    <div id="toast" class="toast">✓ PoC cURL copied to clipboard!</div>

    <script>
        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                const toast = document.getElementById('toast');
                toast.classList.add('show');
                setTimeout(() => {
                    toast.classList.remove('show');
                }, 2500);
            }).catch(err => {
                alert("Failed to copy command: " + err);
            });
        }
    </script>
</body>
</html>"""
