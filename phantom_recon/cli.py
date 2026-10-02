"""
Phantom Recon — CLI Entry Point.

Provides the main command-line interface using Click, with commands
for all scanning modules and report generation.

⚠️ DISCLAIMER: For authorized security testing only.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
import urllib3

# Suppress unverified HTTPS request warnings for clean CLI output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from phantom_recon.utils.logger import (
    print_banner,
    print_command_palette,
    console,
    section_header,
    success,
    error,
    info,
    warning,
    print_results_table,
    print_vulnerabilities_matrix,
    print_scan_summary,
    severity_badge,
)
from phantom_recon import __version__
from phantom_recon.utils.config import load_or_create_config


class PhantomGroup(click.Group):
    """Custom Click Group with stylized Rich Command Palette."""
    def get_help(self, ctx):
        print_banner()
        print_command_palette()
        return ""


# ─── Main CLI Group ─────────────────────────────────────────────
@click.group(cls=PhantomGroup, invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.option("--no-color", is_flag=True, help="Disable colored output.")
@click.option("--config", "-c", type=str, default=None, help="Path to config file.")
@click.option("--output", "-o", type=str, default=None, help="Output file path.")
@click.option("--format", "-f", "output_format", type=click.Choice(["html", "json", "txt", "csv", "md"]), default="json", help="Output format.")
@click.version_option(version=__version__, prog_name="Phantom Recon")
@click.pass_context
def main(ctx, verbose, no_color, config, output, output_format):
    """🔥 Phantom Recon — Advanced Penetration Testing & Reconnaissance Toolkit"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["config"] = load_or_create_config(config)
    ctx.obj["output"] = output
    ctx.obj["format"] = output_format

    if ctx.invoked_subcommand is None:
        print_banner()
        print_command_palette()


# ─── Interactive Command Palette ────────────────────────────────
@main.command(name="help")
def help_cmd():
    """📖 Display the interactive command palette & quick syntax cheat sheet."""
    print_banner()
    print_command_palette()


# ─── Port Scan ──────────────────────────────────────────────────
@main.command()
@click.option("--target", "-t", required=True, help="Target IP or hostname.")
@click.option("--ports", "-p", default="1-1000", help="Ports to scan (e.g., '80', '1-1000', '22,80,443').")
@click.option("--type", "scan_type", type=click.Choice(["connect", "udp"]), default="connect", help="Scan type.")
@click.option("--threads", default=50, help="Number of threads.")
@click.option("--timeout", default=2.0, help="Timeout per port (seconds).")
@click.pass_context
def scan(ctx, target, ports, scan_type, threads, timeout):
    """🔍 Port scanning with service detection."""
    print_banner()
    section_header("Port Scanner")

    from phantom_recon.core.scanner import PortScanner

    scanner = PortScanner(
        target=target, ports=ports, threads=threads,
        timeout=timeout, scan_type=scan_type,
    )
    results = scanner.scan()

    # Display results
    if results.get("ports"):
        rows = []
        for port, port_info in results["ports"].items():
            rows.append([
                f"{port}/tcp",
                f"[green]{port_info['state']}[/green]",
                port_info.get("service", ""),
                port_info.get("banner", "")[:60],
            ])

        print_results_table(
            f"Scan Results — {target}",
            [("Port", "bold"), ("State", ""), ("Service", "cyan"), ("Banner", "dim")],
            rows,
        )

    if results.get("is_waf_proxy"):
        warning(
            f"Target IP ({results['ip']}) belongs to {results.get('waf_provider', 'Cloud')} WAF/CDN proxy network.\n"
            f"Port scan results reflect {results.get('waf_provider')} Anycast edge infrastructure, not the origin server.\n"
            f"Run 'phantom waf -t {target}' to audit for unproxied backend origin IP addresses."
        )

    print_scan_summary(target, datetime.fromisoformat(results["start_time"]),
                       datetime.fromisoformat(results["end_time"]), results["open_ports_count"])

    _save_output(ctx, results)


# ─── WAF & Origin IP Audit ──────────────────────────────────────
@main.command()
@click.option("--target", "-t", required=True, help="Target domain, IP, or URL.")
@click.option("--timeout", default=6.0, help="Request timeout (seconds).")
@click.pass_context
def waf(ctx, target, timeout):
    """🛡️ WAF & CDN detector with unproxied origin IP leakage audit."""
    print_banner()
    section_header("WAF / CDN & Origin IP Exposure Audit")

    from phantom_recon.core.waf_detector import WAFDetector

    detector = WAFDetector(target=target, timeout=timeout)
    results = detector.run_full_waf_analysis()

    # Display WAF Status Table
    has_waf = results.get("has_waf", False)
    waf_name = results.get("waf_name", "None")
    resolved_ips = results.get("resolved_ips", [])

    status_color = "red" if has_waf else "green"
    waf_status_str = f"[{status_color}]{'PROTECTED' if has_waf else 'DIRECT / NO WAF'}[/{status_color}]"

    rows = [
        ["Target", target],
        ["WAF / CDN Status", waf_status_str],
        ["Identified Provider", f"[bold cyan]{waf_name}[/bold cyan]"],
        ["Resolved Edge IPs", ", ".join(resolved_ips) if resolved_ips else "None"],
    ]

    print_results_table(
        f"WAF Detection Overview — {target}",
        [("Attribute", "bold"), ("Value", "")],
        rows,
    )

    if results.get("warning"):
        warning(results["warning"])

    if results.get("indicators"):
        console.print("\n[bold]Fingerprint Evidence:[/bold]")
        for ind in results["indicators"]:
            console.print(f"  [cyan]•[/cyan] {ind}")

    origin_info = results.get("origin_leakage", {})
    unprotected = origin_info.get("unprotected_origin_candidates", [])

    if unprotected:
        console.print("\n[bold red]🚨 POTENTIAL UNPROXIED ORIGIN IP LEAKAGE (WAF BYPASS RISK):[/bold red]")
        candidate_rows = []
        for c in unprotected:
            candidate_rows.append([
                c["ip"],
                c["hostname"],
                c["source"],
                c["evidence"],
            ])
        print_results_table(
            "Unproxied Origin Candidates",
            [("IP Address", "bold red"), ("Hostname", "cyan"), ("Leak Source", "yellow"), ("Details", "dim")],
            candidate_rows,
        )
    elif has_waf:
        success("No direct backend origin IP leaks detected in common DNS/subdomain records.")

    _save_output(ctx, results)


# ─── API & Documentation Discovery ─────────────────────────────
@main.command()
@click.option("--url", "-u", required=True, help="Target application URL.")
@click.option("--timeout", default=6.0, help="Request timeout (seconds).")
@click.pass_context
def api(ctx, url, timeout):
    """🔍 API endpoint discovery (Swagger/OpenAPI, GraphQL & Spring Actuators)."""
    print_banner()
    section_header("API & Architecture Discovery")

    from phantom_recon.core.api_scanner import APIScanner

    scanner = APIScanner(url=url, timeout=timeout)
    endpoints = scanner.scan_endpoints()

    if endpoints:
        rows = []
        for ep in endpoints:
            rows.append([
                ep.get("path", ""),
                ep.get("type", ""),
                str(ep.get("status_code", 200)),
                ep.get("evidence", "")[:60],
            ])

        print_results_table(
            f"API Endpoints Discovered — {url}",
            [("Path", "bold cyan"), ("Architecture Type", "yellow"), ("Status", "green"), ("Details / Evidence", "dim")],
            rows,
        )
        success(f"Discovered [bold]{len(endpoints)}[/bold] exposed API schemas / documentation interfaces.")
    else:
        info("No standard public API documentation or Swagger schemas discovered.")

    _save_output(ctx, {"target": url, "api_endpoints": endpoints})


# ─── Cloud Storage & Bucket Audit ──────────────────────────────
@main.command()
@click.option("--target", "-t", required=True, help="Target domain, URL, or organization keyword.")
@click.option("--threads", default=20, help="Concurrency thread pool count.")
@click.option("--timeout", default=3.5, help="Network timeout per bucket probe (seconds).")
@click.pass_context
def cloud(ctx, target, threads, timeout):
    """☁️ Multi-Cloud storage auditor: AWS S3, Google Cloud, Azure Blob bucket leaks."""
    print_banner()
    section_header("Cloud Storage & Bucket Leakage Auditor")

    from phantom_recon.core.cloud_auditor import CloudAuditor

    info(f"Auditing cloud storage bucket exposure for: [bold cyan]{target}[/bold cyan]")
    auditor = CloudAuditor(target=target, threads=threads, timeout=timeout)
    results = auditor.run_cloud_audit()

    findings = results.get("findings", [])
    open_buckets = results.get("open_buckets", [])
    protected_buckets = results.get("protected_buckets", [])

    if findings:
        rows = []
        for f in findings:
            status_text = "[bold red]OPEN (LISTABLE)[/bold red]" if f.get("is_open") else "[dim green]PROTECTED[/dim green]"
            rows.append([
                f.get("provider", ""),
                f.get("bucket_name", ""),
                status_text,
                f.get("severity", "").upper(),
                str(f.get("object_count", 0)) if f.get("is_open") else "N/A",
                f.get("url", ""),
            ])

        print_results_table(
            f"Cloud Storage Findings — {target}",
            [
                ("Provider", "bold cyan"),
                ("Bucket / Account", "white"),
                ("Access Status", "yellow"),
                ("Severity", "magenta"),
                ("Objects", "green"),
                ("URL", "blue"),
            ],
            rows,
        )

        if open_buckets:
            error(f"🚨 CRITICAL ALERT: Found {len(open_buckets)} PUBLICLY LISTABLE cloud bucket(s)!")
            for ob in open_buckets:
                console.print(f"   [bold red]•[/bold red] {ob.get('provider')}: [underline]{ob.get('url')}[/underline] ({ob.get('object_count')} files exposed)")
        else:
            success(f"No publicly listable cloud buckets found ({len(protected_buckets)} protected buckets exist).")
    else:
        info("No cloud storage buckets or Azure containers discovered for this target.")

    _save_output(ctx, results)


# ─── Web Recon ──────────────────────────────────────────────────
@main.command()
@click.option("--url", "-u", required=True, help="Target URL.")
@click.option("--full", is_flag=True, help="Run full reconnaissance.")
@click.option("--tech", is_flag=True, help="Technology detection only.")
@click.option("--dirs", is_flag=True, help="Directory enumeration only.")
@click.pass_context
def recon(ctx, url, full, tech, dirs):
    """🌐 Web application reconnaissance."""
    print_banner()
    section_header("Web Reconnaissance")

    from phantom_recon.core.web_recon import WebRecon

    web = WebRecon(url=url)

    if full or (not tech and not dirs):
        results = web.run_full_recon()
    else:
        results = {}
        if tech:
            results["technologies"] = web.fingerprint_technologies()
        if dirs:
            results["directories"] = web.enumerate_directories()

    # Display results
    if "technologies" in results and results["technologies"]:
        info(f"Technologies detected: {', '.join(results['technologies'])}")

    if "directories" in results and results["directories"]:
        for d in results["directories"]:
            success(f"[{d['status_code']}] {d['path']}")

    if "js_analysis" in results:
        endpoints = results["js_analysis"].get("endpoints", [])
        secrets = results["js_analysis"].get("secrets", [])
        if endpoints:
            info(f"Discovered JS API Endpoints ({len(endpoints)}): {', '.join(endpoints[:5])}" + ("..." if len(endpoints) > 5 else ""))
        if secrets:
            console.print("\n[bold red]🚨 EXPOSED CLIENT-SIDE JAVASCRIPT SECRETS FOUND:[/bold red]")
            for s in secrets:
                console.print(f"  • [yellow]{s.get('type')}[/yellow] in [cyan]{s.get('file')}[/cyan] (Token: {s.get('preview')})")

    if "security_txt" in results and results["security_txt"].get("exists"):
        sec = results["security_txt"]
        success(f"RFC 9116 security.txt discovered at {sec.get('url')} (Contacts: {', '.join(sec.get('contact', []))})")

    _save_output(ctx, results)


# ─── DNS Enumeration ────────────────────────────────────────────
@main.command()
@click.option("--domain", "-d", required=True, help="Target domain.")
@click.option("--type", "record_type", default="all", help="Record types (all, a, mx, ns, txt, etc.).")
@click.option("--zone-transfer", is_flag=True, help="Attempt zone transfer.")
@click.option("--email", "email_audit", is_flag=True, help="Include SPF/DMARC email security audit.")
@click.pass_context
def dns(ctx, domain, record_type, zone_transfer, email_audit):
    """📡 DNS record enumeration and anti-spoofing defense audit."""
    print_banner()
    section_header("DNS Enumeration")

    from phantom_recon.core.dns_enum import DNSEnumerator

    enumerator = DNSEnumerator(domain=domain)

    if record_type.lower() == "all":
        results = enumerator.enumerate_all()
        results["email_security"] = enumerator.audit_email_security()
    else:
        types = [t.strip().upper() for t in record_type.split(",")]
        results = {"domain": domain, "records": {}}
        for t in types:
            records = enumerator.enumerate_type(t)
            if records:
                results["records"][t] = records
        if email_audit:
            results["email_security"] = enumerator.audit_email_security()

    if zone_transfer:
        zt_results = enumerator.check_zone_transfer()
        results["zone_transfer"] = zt_results

    # Display
    for rtype, records in results.get("records", {}).items():
        for r in records:
            info(f"{rtype}: {r.get('value', '')}")

    if "email_security" in results:
        email_sec = results["email_security"]
        spf = email_sec.get("spf", {})
        dmarc = email_sec.get("dmarc", {})
        console.print("\n[bold cyan]📧 Email Anti-Spoofing & Domain Protection:[/bold cyan]")
        spf_status = "[bold green]✓ Configured[/bold green]" if spf.get("present") else "[bold red]✗ Missing[/bold red]"
        console.print(f"  • SPF Record:    {spf_status} ({spf.get('policy', 'None')})")
        if dmarc.get("present"):
            d_pol = dmarc.get("policy", "none")
            d_color = "bold green" if d_pol in ("reject", "quarantine") else "bold yellow"
            console.print(f"  • DMARC Policy:  [{d_color}]✓ {d_pol.upper()}[/{d_color}] ({dmarc.get('raw', '')[:60]})")
        else:
            console.print("  • DMARC Policy:  [bold red]✗ Missing (High Spoofing Risk)[/bold red]")

    _save_output(ctx, results)


# ─── Subdomain Discovery ────────────────────────────────────────
@main.command()
@click.option("--domain", "-d", required=True, help="Target domain.")
@click.option("--wordlist", "-w", default=None, help="Custom wordlist file.")
@click.option("--threads", default=30, help="Number of threads.")
@click.option("--ct-logs", is_flag=True, help="Search Certificate Transparency logs.")
@click.pass_context
def subdomain(ctx, domain, wordlist, threads, ct_logs):
    """🔎 Subdomain discovery."""
    print_banner()
    section_header("Subdomain Discovery")

    from phantom_recon.core.subdomain import SubdomainFinder

    word_list = None
    if wordlist:
        with open(wordlist, "r") as f:
            word_list = [line.strip() for line in f if line.strip()]

    finder = SubdomainFinder(domain=domain, wordlist=word_list, threads=threads)

    if ct_logs:
        results = finder.ct_search()
    else:
        results = finder.find_all()

    # Display
    if results:
        rows = []
        for sub in results:
            rows.append([
                sub["subdomain"],
                sub.get("ip", "N/A"),
                str(sub.get("status_code", "N/A")),
                sub.get("source", ""),
            ])
        print_results_table(
            f"Subdomains — {domain}",
            [("Subdomain", "bold"), ("IP", "cyan"), ("Status", ""), ("Source", "dim")],
            rows,
        )

        takeovers = [s for s in results if s.get("takeover_risk")]
        if takeovers:
            console.print("\n[bold red]🚨 POTENTIAL SUBDOMAIN TAKEOVER VULNERABILITIES DETECTED:[/bold red]")
            for t in takeovers:
                console.print(f"  [bold red]• {t['subdomain']}[/bold red] → Dangling service: [yellow]{t.get('takeover_service', 'Unknown')}[/yellow] (Evidence: {t.get('takeover_evidence', '')})")

    _save_output(ctx, {"domain": domain, "subdomains": results})


@main.command()
@click.option("--url", "-u", required=True, help="Target URL.")
@click.option("--checks", default="all", help="Checks to run (all, headers, cors, redirect, sensitive).")
@click.option("--deep", is_flag=True, help="Deep scan mode.")
@click.option("--output", "-o", default=None, help="Output file path (e.g. report.html or scan.json).")
@click.pass_context
def vuln(ctx, url, checks, deep, output):
    """🛡️ Vulnerability scanning with exact location tracing and direct jump links."""
    print_banner()
    section_header("Vulnerability Scanner")

    if output:
        ctx.obj["output"] = output

    from phantom_recon.core.vuln_scanner import VulnerabilityScanner

    scanner = VulnerabilityScanner(url=url)
    results = scanner.scan_all()

    # Display
    if results:
        print_vulnerabilities_matrix(
            results,
            f"Vulnerability Assessment & Explanations Matrix — {url}",
        )

        # Print detailed breakdown for direct access & verification
        console.print("[bold yellow]📍 DETAILED VULNERABILITY LOCATIONS & REPRODUCTION LINKS:[/bold yellow]\n")
        for idx, v in enumerate(results, 1):
            poc_link = v.get("poc_url") or url
            curl_cmd = v.get("reproduce_curl") or f"curl -i -k '{poc_link}'"
            console.print(f"  [bold white]#{idx} {v['title']}[/bold white] ({severity_badge(v['severity'])})")
            console.print(f"     [bold cyan]📍 Location:[/bold cyan]    {v.get('location', 'Global Application')}")
            console.print(f"     [bold green]🔗 Direct Link:[/bold green]  [link={poc_link}][bold underline cyan]{poc_link}[/bold underline cyan][/link]")
            console.print(f"     [bold magenta]💻 PoC cURL:[/bold magenta]    [dim]{curl_cmd}[/dim]")
            if v.get("evidence"):
                console.print(f"     [dim]📋 Evidence:    {v.get('evidence')[:120]}...[/dim]")
            console.print(f"     [bold green]💡 Fix:[/bold green]         {v.get('remediation', 'N/A')}\n")

    summary = scanner.get_summary()
    info(f"Summary: {summary}")

    _save_output(ctx, {"url": url, "vulnerabilities": results, "summary": summary})


# ─── Brute Force ─────────────────────────────────────────────────
@main.command()
@click.option("--target", "-t", required=True, help="Target host.")
@click.option("--service", "-s", type=click.Choice(["ssh", "ftp", "http"]), default="ssh", help="Service.")
@click.option("--userlist", default=None, help="Username wordlist file.")
@click.option("--passlist", default=None, help="Password wordlist file.")
@click.option("--threads", default=5, help="Number of threads.")
@click.pass_context
def brute(ctx, target, service, userlist, passlist, threads):
    """🔑 Credential brute forcing."""
    print_banner()
    section_header("Brute Force")

    from phantom_recon.core.brute import BruteForcer

    usernames = None
    passwords = None

    if userlist:
        usernames = BruteForcer.load_wordlist(userlist)
    if passlist:
        passwords = BruteForcer.load_wordlist(passlist)

    bruter = BruteForcer(
        target=target, service=service,
        usernames=usernames, passwords=passwords, threads=threads,
    )
    results = bruter.run()

    if results["found"]:
        for cred in results["found"]:
            success(f"{cred['username']}:{cred['password']}")
    else:
        warning("No valid credentials found.")

    _save_output(ctx, results)


# ─── WHOIS ──────────────────────────────────────────────────────
@main.command()
@click.option("--target", "-t", required=True, help="Domain or IP address.")
@click.pass_context
def whois(ctx, target):
    """📋 WHOIS lookup."""
    print_banner()
    section_header("WHOIS Lookup")

    from phantom_recon.core.whois_lookup import WhoisLookup

    lookup = WhoisLookup(target=target)
    results = lookup.lookup()

    # Display key fields
    for key in ["domain_name", "registrar", "creation_date", "expiration_date",
                "name_servers", "org", "country"]:
        if key in results:
            info(f"{key}: {results[key]}")

    _save_output(ctx, results)


# ─── Headers ────────────────────────────────────────────────────
@main.command()
@click.option("--url", "-u", required=True, help="Target URL.")
@click.pass_context
def headers(ctx, url):
    """📊 HTTP security header analysis."""
    print_banner()
    section_header("Header Analysis")

    from phantom_recon.core.header_analyzer import HeaderAnalyzer

    analyzer = HeaderAnalyzer(url=url)
    results = analyzer.analyze()

    if "grade" in results:
        info(f"Grade: {results['grade']}")

    if "checks" in results:
        rows = []
        for check in results["checks"]:
            status = "[green]✓[/green]" if check["secure"] else "[red]✗[/red]"
            rows.append([
                status,
                check["header"],
                check["value"] or "[dim]missing[/dim]",
                check.get("recommendation", "")[:50],
            ])
        print_results_table(
            f"Security Headers — {url}",
            [("", ""), ("Header", "bold"), ("Value", ""), ("Recommendation", "dim")],
            rows,
        )

    _save_output(ctx, results)


# ─── SSL/TLS ────────────────────────────────────────────────────
@main.command("ssl")
@click.option("--host", "-h", "hostname", required=True, help="Target hostname.")
@click.option("--port", "-p", default=443, help="Target port.")
@click.pass_context
def ssl_cmd(ctx, hostname, port):
    """🔐 SSL/TLS security analysis."""
    print_banner()
    section_header("SSL/TLS Analysis")

    from phantom_recon.core.ssl_analyzer import SSLAnalyzer

    analyzer = SSLAnalyzer(host=hostname, port=port)
    results = analyzer.analyze()

    if "grade" in results:
        info(f"Grade: {results['grade']}")
    if "protocol" in results:
        info(f"Protocol: {results['protocol']}")
    if "cipher_suite" in results:
        info(f"Cipher: {results['cipher_suite']}")

    cert = results.get("certificate", {})
    if cert:
        info(f"Subject: {cert.get('subject', {}).get('common_name', 'N/A')}")
        info(f"Issuer: {cert.get('issuer', {}).get('common_name', 'N/A')}")
        info(f"Valid Until: {cert.get('not_after', 'N/A')}")
        info(f"Self-Signed: {cert.get('self_signed', 'N/A')}")

    if results.get("issues"):
        warning(f"{len(results['issues'])} issue(s) found:")
        for issue in results["issues"]:
            error(f"  [{issue['severity']}] {issue['title']}")

    _save_output(ctx, results)


# ─── Network Mapping ────────────────────────────────────────────
@main.command()
@click.option("--target", "-t", required=True, help="Target IP or CIDR range.")
@click.option("--discover", is_flag=True, help="Discover live hosts.")
@click.option("--traceroute", "do_traceroute", is_flag=True, help="Run traceroute.")
@click.pass_context
def network(ctx, target, discover, do_traceroute):
    """🗺️ Network mapping and discovery."""
    print_banner()
    section_header("Network Mapper")

    from phantom_recon.core.network import NetworkMapper

    mapper = NetworkMapper(target=target)
    results = {"target": target}

    if discover:
        hosts = mapper.discover_hosts()
        results["hosts"] = hosts
        if hosts:
            rows = [[h["ip"], h.get("hostname", ""), f"{h.get('response_time', 0)}ms"]
                     for h in hosts]
            print_results_table(
                f"Live Hosts — {target}",
                [("IP", "bold"), ("Hostname", ""), ("RTT", "cyan")],
                rows,
            )

    if do_traceroute:
        hops = mapper.traceroute()
        results["traceroute"] = hops
        if hops:
            rows = [[str(h["ttl"]), h["ip"], h.get("hostname", ""), f"{h.get('rtt', 0)}ms"]
                     for h in hops]
            print_results_table(
                f"Traceroute — {target}",
                [("Hop", ""), ("IP", "bold"), ("Hostname", ""), ("RTT", "cyan")],
                rows,
            )

    if not discover and not do_traceroute:
        warning("Specify --discover or --traceroute")

    _save_output(ctx, results)


# ─── Report Generation ──────────────────────────────────────────
@main.command()
@click.option("--input", "-i", "input_file", required=True, help="Input JSON scan data file.")
@click.option("--format", "-f", "report_format", type=click.Choice(["html", "json", "txt", "csv", "md"]), default="html")
@click.option("--output", "-o", required=True, help="Output report file path.")
@click.pass_context
def report(ctx, input_file, report_format, output):
    """📊 Generate reports from scan data in HTML, JSON, TXT, CSV, or Markdown."""
    print_banner()
    section_header("Report Generator")

    from phantom_recon.reporting.report_generator import ReportGenerator

    with open(input_file, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    generator = ReportGenerator(scan_data=scan_data)

    if report_format == "html":
        generator.generate_html(output)
    elif report_format == "csv":
        generator.generate_csv(output)
    elif report_format in ("md", "markdown"):
        generator.generate_markdown(output)
    elif report_format == "json":
        generator.generate_json(output)
    elif report_format == "txt":
        generator.generate_text(output)

    success(f"Report generated: {output}")


# ─── Full Recon Pipeline ────────────────────────────────────────
@main.command()
@click.option("--target", "-t", required=True, help="Target domain or IP.")
@click.option("--output", "-o", default="phantom_report.html", help="Output report file.")
@click.pass_context
def full(ctx, target, output):
    """🎯 Full reconnaissance pipeline with web fingerprinting and zero-false-positive audit."""
    print_banner()
    section_header("Full Recon Pipeline")
    info(f"Target: {target}")

    all_results: dict = {"target": target, "timestamp": datetime.now().isoformat()}

    # 1. WHOIS
    try:
        section_header("Step 1/11: WHOIS Lookup")
        from phantom_recon.core.whois_lookup import WhoisLookup
        whois_data = WhoisLookup(target=target).lookup()
        all_results["whois"] = whois_data
        success("WHOIS complete")
    except Exception as e:
        warning(f"WHOIS failed: {e}")

    # 2. DNS
    try:
        section_header("Step 2/11: DNS Enumeration")
        from phantom_recon.core.dns_enum import DNSEnumerator
        dns_data = DNSEnumerator(domain=target).enumerate_all()
        all_results["dns"] = dns_data
        success("DNS enumeration complete")
    except Exception as e:
        warning(f"DNS failed: {e}")

    # 3. Subdomain Discovery
    try:
        section_header("Step 3/11: Subdomain Discovery")
        from phantom_recon.core.subdomain import SubdomainFinder
        subs = SubdomainFinder(domain=target, threads=20).find_all()
        all_results["subdomains"] = subs
        success(f"Found {len(subs)} subdomains")
    except Exception as e:
        warning(f"Subdomain discovery failed: {e}")

    # 4. WAF & Origin IP Audit
    try:
        section_header("Step 4/11: WAF & Origin IP Leakage Audit")
        from phantom_recon.core.waf_detector import WAFDetector
        waf_data = WAFDetector(target=target).run_full_waf_analysis()
        all_results["waf"] = waf_data
        if waf_data.get("has_waf"):
            warning(f"Target is fronted by {waf_data.get('waf_name')} CDN/WAF!")
            if waf_data.get("origin_leakage", {}).get("leakage_detected"):
                error(f"🚨 Potential unproxied origin server IP leakage detected!")
        else:
            success("No cloud WAF edge proxy detected (direct host)")
    except Exception as e:
        warning(f"WAF audit failed: {e}")

    # 5. Cloud Storage Audit
    try:
        section_header("Step 5/11: Cloud Storage & Bucket Leakage Audit")
        from phantom_recon.core.cloud_auditor import CloudAuditor
        cloud_results = CloudAuditor(target=target, threads=20).run_cloud_audit()
        all_results["cloud_storage"] = cloud_results
        open_b = cloud_results.get("open_buckets_count", 0)
        prot_b = cloud_results.get("protected_buckets_count", 0)
        if open_b > 0:
            error(f"🚨 Found {open_b} PUBLICLY LISTABLE cloud storage buckets!")
        else:
            success(f"Cloud audit complete: 0 open buckets ({prot_b} protected)")
    except Exception as e:
        warning(f"Cloud storage audit failed: {e}")

    # 6. Port Scan
    try:
        section_header("Step 6/11: Port Scanning")
        from phantom_recon.core.scanner import PortScanner
        scan_results = PortScanner(target=target, ports="1-1000", threads=50).scan()
        all_results["ports"] = scan_results.get("ports", {})
        success(f"Found {scan_results.get('open_ports_count', 0)} open ports")
    except Exception as e:
        warning(f"Port scan failed: {e}")

    # 7. Web Reconnaissance
    try:
        section_header("Step 7/11: Web Application Reconnaissance")
        from phantom_recon.core.web_recon import WebRecon
        url = f"https://{target}" if not target.startswith("http") else target
        web_results = WebRecon(url=url).run_full_recon()
        all_results["technologies"] = web_results.get("technologies", [])
        all_results["directories"] = web_results.get("directories", [])
        all_results["forms"] = web_results.get("forms", [])
        success(f"Detected {len(all_results['technologies'])} technologies and {len(all_results['directories'])} directories")
    except Exception as e:
        warning(f"Web reconnaissance failed: {e}")

    # 8. API Discovery
    try:
        section_header("Step 8/11: API & Architecture Discovery")
        from phantom_recon.core.api_scanner import APIScanner
        url = f"https://{target}" if not target.startswith("http") else target
        api_results = APIScanner(url=url).scan_endpoints()
        all_results["api_endpoints"] = api_results
        success(f"Discovered {len(api_results)} API endpoints / schemas")
    except Exception as e:
        warning(f"API discovery failed: {e}")

    # 9. Header Analysis
    try:
        section_header("Step 9/11: Header Analysis")
        from phantom_recon.core.header_analyzer import HeaderAnalyzer
        url = f"https://{target}" if not target.startswith("http") else target
        header_data = HeaderAnalyzer(url=url).analyze()
        all_results["headers"] = header_data
        success(f"Header grade: {header_data.get('grade', 'N/A')}")
    except Exception as e:
        warning(f"Header analysis failed: {e}")

    # 10. SSL Analysis
    try:
        section_header("Step 10/11: SSL/TLS Analysis")
        from phantom_recon.core.ssl_analyzer import SSLAnalyzer
        ssl_data = SSLAnalyzer(host=target).analyze()
        all_results["ssl"] = ssl_data
        success(f"SSL grade: {ssl_data.get('grade', 'N/A')}")
    except Exception as e:
        warning(f"SSL analysis failed: {e}")

    # 11. Vulnerability Scan
    try:
        section_header("Step 11/11: Vulnerability Scan")
        from phantom_recon.core.vuln_scanner import VulnerabilityScanner
        url = f"https://{target}" if not target.startswith("http") else target
        vuln_data = VulnerabilityScanner(url=url).scan_all()
        all_results["vulnerabilities"] = vuln_data
        success(f"Found {len(vuln_data)} vulnerabilities")
        if vuln_data:
            print_vulnerabilities_matrix(vuln_data, f"Vulnerability Assessment & Explanations Matrix — {target}")
            console.print("[bold yellow]📍 DETAILED REPRODUCTION PROOF-OF-CONCEPT & DIRECT ACCESS:[/bold yellow]\n")
            for idx, v in enumerate(vuln_data, 1):
                poc_link = v.get("poc_url") or url
                curl_cmd = v.get("reproduce_curl") or f"curl -i -k '{poc_link}'"
                console.print(f"  [bold white]#{idx} {v['title']}[/bold white] ({severity_badge(v['severity'])})")
                console.print(f"     [bold cyan]📍 Location:[/bold cyan]    {v.get('location', 'Global Application')}")
                console.print(f"     [bold green]🔗 Direct Link:[/bold green]  [link={poc_link}][bold underline cyan]{poc_link}[/bold underline cyan][/link]")
                console.print(f"     [bold magenta]💻 PoC cURL:[/bold magenta]    [dim]{curl_cmd}[/dim]")
                if v.get("evidence"):
                    console.print(f"     [dim]📋 Evidence:    {v.get('evidence')[:120]}...[/dim]")
                console.print(f"     [bold green]💡 Fix:[/bold green]         {v.get('remediation', 'N/A')}\n")
    except Exception as e:
        warning(f"Vulnerability scan failed: {e}")

    # Generate report
    section_header("Generating Report")
    from phantom_recon.reporting.report_generator import ReportGenerator
    generator = ReportGenerator(scan_data=all_results)

    if output.endswith(".csv"):
        generator.generate_csv(output)
    elif output.endswith(".md") or output.endswith(".markdown"):
        generator.generate_markdown(output)
    elif output.endswith(".json"):
        generator.generate_json(output)
    elif output.endswith(".txt"):
        generator.generate_text(output)
    else:
        generator.generate_html(output)

    success(f"Full report saved: {output}")

    # Also save JSON
    json_output = output.rsplit(".", 1)[0] + ".json"
    generator.generate_json(json_output)
    info(f"JSON data saved: {json_output}")


def _save_output(ctx: click.Context, data: dict) -> None:
    """Save output to file if --output specified with automatic HTML/JSON/TXT/CSV/MD formatting."""
    output = ctx.obj.get("output") or ctx.params.get("output")
    if output:
        output_format = ctx.obj.get("format", "json")
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)

        scan_dict = dict(data)
        if "target" not in scan_dict and "url" in scan_dict:
            scan_dict["target"] = scan_dict["url"]

        from phantom_recon.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(scan_data=scan_dict)

        if output.endswith(".html") or output_format == "html":
            gen.generate_html(str(path))
            success(f"Interactive HTML Report generated: [bold underline cyan]{path}[/bold underline cyan]")
        elif output.endswith(".csv") or output_format == "csv":
            gen.generate_csv(str(path))
            success(f"CSV Report generated: [bold]{path}[/bold]")
        elif output.endswith(".md") or output_format in ("md", "markdown"):
            gen.generate_markdown(str(path))
            success(f"Markdown Report generated: [bold]{path}[/bold]")
        elif output.endswith(".txt") or output_format == "txt":
            gen.generate_text(str(path))
            success(f"Plain Text Report generated: [bold]{path}[/bold]")
        else:
            path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            info(f"JSON Data output saved to {output}")


if __name__ == "__main__":
    main()
