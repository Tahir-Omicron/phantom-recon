"""Core modules for Phantom Recon penetration testing toolkit."""

from phantom_recon.core.http_methods import HTTPMethodsAuditor
from phantom_recon.core.cms_auditor import CMSAuditor
from phantom_recon.core.autonomous_auditor import AutonomousAuditor, AuditFinding
from phantom_recon.core.favicon_analyzer import FaviconAnalyzer, calculate_shodan_favicon_hash
from phantom_recon.core.takeover import SubdomainTakeoverAuditor
from phantom_recon.core.policy_auditor import PolicyAuditor

__all__ = [
    "HTTPMethodsAuditor",
    "CMSAuditor",
    "AutonomousAuditor",
    "AuditFinding",
    "FaviconAnalyzer",
    "calculate_shodan_favicon_hash",
    "SubdomainTakeoverAuditor",
    "PolicyAuditor",
]

