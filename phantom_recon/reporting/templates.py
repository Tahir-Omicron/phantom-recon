"""
Phantom Recon — HTML Report Templates.

Professional dark-themed HTML templates for report generation
with responsive design, severity badges, and collapsible sections.
"""

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phantom Recon Report — {{ data.get('target', 'Unknown') }}</title>
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a2e;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --accent-red: #ff4444;
            --accent-cyan: #00bcd4;
            --accent-green: #4caf50;
            --accent-yellow: #ffca28;
            --accent-orange: #ff9800;
            --accent-blue: #2196f3;
            --border: #2a2a3e;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Segoe UI', 'Inter', -apple-system, sans-serif;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }

        /* Header */
        .report-header {
            text-align: center;
            padding: 60px 0 40px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 40px;
        }

        .report-header h1 {
            font-size: 2.5em;
            color: var(--accent-red);
            margin-bottom: 10px;
        }

        .report-header .subtitle {
            color: var(--text-secondary);
            font-size: 1.1em;
        }

        .report-header .meta {
            margin-top: 20px;
            color: var(--text-secondary);
            font-size: 0.9em;
        }

        /* Cards */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }

        .card h2 {
            color: var(--accent-cyan);
            font-size: 1.4em;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-box {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }

        .stat-box .value {
            font-size: 2em;
            font-weight: bold;
            color: var(--accent-cyan);
        }

        .stat-box .label {
            color: var(--text-secondary);
            font-size: 0.85em;
            margin-top: 4px;
        }

        /* Tables */
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
            background: var(--bg-secondary);
            color: var(--accent-cyan);
            font-weight: 600;
        }

        tr:hover td {
            background: rgba(0, 188, 212, 0.05);
        }

        /* Severity Badges */
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-critical { background: #d32f2f; color: white; }
        .badge-high { background: #f44336; color: white; }
        .badge-medium { background: var(--accent-orange); color: #000; }
        .badge-low { background: var(--accent-blue); color: white; }
        .badge-info { background: #546e7a; color: white; }
        .badge-open { background: var(--accent-green); color: white; }
        .badge-closed { background: #f44336; color: white; }
        .badge-filtered { background: var(--accent-yellow); color: #000; }

        .badge-grade {
            font-size: 1.5em;
            padding: 8px 20px;
        }

        .grade-a { background: var(--accent-green); color: white; }
        .grade-b { background: #8bc34a; color: #000; }
        .grade-c { background: var(--accent-yellow); color: #000; }
        .grade-d { background: var(--accent-orange); color: #000; }
        .grade-f { background: #d32f2f; color: white; }

        /* Collapsible */
        .collapsible {
            cursor: pointer;
            user-select: none;
        }

        .collapsible::after {
            content: ' ▼';
            font-size: 0.7em;
        }

        .collapsible.collapsed::after {
            content: ' ▶';
        }

        .collapsible-content {
            overflow: hidden;
            transition: max-height 0.3s ease;
        }

        .collapsible-content.collapsed {
            max-height: 0 !important;
            padding: 0;
        }

        /* Code blocks */
        code, pre {
            background: var(--bg-secondary);
            border-radius: 4px;
            font-family: 'Fira Code', 'Consolas', monospace;
        }

        code { padding: 2px 6px; font-size: 0.9em; }
        pre { padding: 16px; overflow-x: auto; margin: 8px 0; }

        /* Footer */
        .report-footer {
            text-align: center;
            padding: 40px 0;
            border-top: 1px solid var(--border);
            margin-top: 40px;
            color: var(--text-secondary);
            font-size: 0.85em;
        }

        /* Print */
        @media print {
            body { background: white; color: black; }
            .card { border: 1px solid #ddd; }
            th { background: #f5f5f5; color: #333; }
        }

        /* Responsive */
        @media (max-width: 768px) {
            .container { padding: 20px 10px; }
            .report-header h1 { font-size: 1.8em; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="report-header">
            <h1>🔥 Phantom Recon Report</h1>
            <p class="subtitle">Advanced Penetration Testing & Reconnaissance</p>
            <p class="meta">
                Target: <strong>{{ data.get('target', 'N/A') }}</strong> |
                Generated: {{ generated_at }} |
                Duration: {{ data.get('duration', 'N/A') }}s
            </p>
        </div>

        <!-- Executive Summary -->
        <div class="card">
            <h2 class="collapsible" onclick="toggleSection(this)">📋 Executive Summary</h2>
            <div class="collapsible-content">
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="value">{{ data.get('ports', {})|length }}</div>
                        <div class="label">Open Ports</div>
                    </div>
                    <div class="stat-box">
                        <div class="value">{{ data.get('vulnerabilities', [])|length }}</div>
                        <div class="label">Vulnerabilities</div>
                    </div>
                    <div class="stat-box">
                        <div class="value">{{ data.get('subdomains', [])|length }}</div>
                        <div class="label">Subdomains</div>
                    </div>
                    <div class="stat-box">
                        <div class="value">{{ data.get('headers', {}).get('grade', 'N/A') }}</div>
                        <div class="label">Header Grade</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Port Scan -->
        {% if data.get('ports') %}
        <div class="card">
            <h2 class="collapsible" onclick="toggleSection(this)">🔍 Port Scan Results</h2>
            <div class="collapsible-content">
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Banner</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for port, info in data.get('ports', {}).items() %}
                        <tr>
                            <td><code>{{ port }}/tcp</code></td>
                            <td><span class="badge badge-{{ info.get('state', 'unknown') }}">{{ info.get('state', '') }}</span></td>
                            <td>{{ info.get('service', '') }}</td>
                            <td><code>{{ info.get('banner', '')[:80] }}</code></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <!-- Vulnerabilities -->
        {% if data.get('vulnerabilities') %}
        <div class="card">
            <h2 class="collapsible" onclick="toggleSection(this)">🛡️ Vulnerabilities</h2>
            <div class="collapsible-content">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>Description</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for vuln in data.get('vulnerabilities', []) %}
                        <tr>
                            <td><span class="badge badge-{{ vuln.get('severity', 'info') }}">{{ vuln.get('severity', '') }}</span></td>
                            <td><strong>{{ vuln.get('title', '') }}</strong></td>
                            <td>{{ vuln.get('description', '') }}</td>
                            <td>{{ vuln.get('remediation', '') }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <!-- SSL Analysis -->
        {% if data.get('ssl') %}
        <div class="card">
            <h2 class="collapsible" onclick="toggleSection(this)">🔐 SSL/TLS Analysis</h2>
            <div class="collapsible-content">
                {% set ssl = data.get('ssl', {}) %}
                <p>Grade: <span class="badge badge-grade grade-{{ ssl.get('grade', 'f')|lower }}">{{ ssl.get('grade', 'N/A') }}</span></p>
                <table>
                    <tr><th>Protocol</th><td>{{ ssl.get('protocol', 'N/A') }}</td></tr>
                    <tr><th>Cipher Suite</th><td>{{ ssl.get('cipher_suite', 'N/A') }}</td></tr>
                    <tr><th>Issuer</th><td>{{ ssl.get('certificate', {}).get('issuer', {}).get('common_name', 'N/A') }}</td></tr>
                    <tr><th>Valid Until</th><td>{{ ssl.get('certificate', {}).get('not_after', 'N/A') }}</td></tr>
                </table>
            </div>
        </div>
        {% endif %}

        <!-- Footer -->
        <div class="report-footer">
            <p>Generated by <strong>Phantom Recon v1.0.0</strong></p>
            <p>⚠️ This report contains sensitive security information. Handle accordingly.</p>
        </div>
    </div>

    <script>
        function toggleSection(el) {
            const content = el.nextElementSibling;
            el.classList.toggle('collapsed');
            content.classList.toggle('collapsed');
        }
    </script>
</body>
</html>"""
