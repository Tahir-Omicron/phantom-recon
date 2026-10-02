"""
╔══════════════════════════════════════════════════════════════╗
║  🔥 Phantom Recon — Advanced Penetration Testing Toolkit    ║
║  Ethical hacking & reconnaissance framework for security    ║
║  professionals and red team operators.                      ║
╚══════════════════════════════════════════════════════════════╝
"""

__version__ = "2.0.0"
__author__ = "Tahir"
__license__ = "MIT"

from phantom_recon.core.scanner import PortScanner
from phantom_recon.core.network import NetworkMapper
from phantom_recon.core.dns_enum import DNSEnumerator
from phantom_recon.core.web_recon import WebRecon
from phantom_recon.core.subdomain import SubdomainFinder
from phantom_recon.core.vuln_scanner import VulnerabilityScanner
from phantom_recon.core.brute import BruteForcer
from phantom_recon.core.whois_lookup import WhoisLookup
from phantom_recon.core.header_analyzer import HeaderAnalyzer
from phantom_recon.core.ssl_analyzer import SSLAnalyzer
from phantom_recon.core.waf_detector import WAFDetector
from phantom_recon.core.api_scanner import APIScanner
from phantom_recon.core.cloud_auditor import CloudAuditor
from phantom_recon.core.http_methods import HTTPMethodsAuditor
from phantom_recon.core.cms_auditor import CMSAuditor
from phantom_recon.core.autonomous_auditor import AutonomousAuditor
from phantom_recon.reporting.report_generator import ReportGenerator
from phantom_recon.reporting.security_score import calculate_security_score

__all__ = [
    "PortScanner",
    "NetworkMapper",
    "DNSEnumerator",
    "WebRecon",
    "SubdomainFinder",
    "VulnerabilityScanner",
    "BruteForcer",
    "WhoisLookup",
    "HeaderAnalyzer",
    "SSLAnalyzer",
    "WAFDetector",
    "APIScanner",
    "CloudAuditor",
    "HTTPMethodsAuditor",
    "CMSAuditor",
    "AutonomousAuditor",
    "ReportGenerator",
    "calculate_security_score",
]
