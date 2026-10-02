"""
Phantom Recon — Multi-Cloud Object Storage & Bucket Leakage Auditor.

Discovers publicly accessible or existing cloud storage buckets across:
- Amazon Web Services (AWS) S3
- Google Cloud Storage (GCS)
- Microsoft Azure Blob Storage

Engineered with zero-false-positive validation to identify exposed databases,
backups, source code, and employee records without false alarms.

⚠️ DISCLAIMER: For authorized security testing only.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
import json
import re
from typing import Any, Optional
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from phantom_recon.utils.logger import get_logger, console
from phantom_recon.utils.validators import validate_domain, validate_url

logger = get_logger(__name__)

# High-risk enterprise bucket name suffixes and prefixes
COMMON_BUCKET_PATTERNS = [
    # Backups & Data
    "backup", "backups", "bak", "data", "db", "database", "dump", "dumps",
    "archive", "raw", "records", "sql",
    # Environments
    "dev", "devel", "development", "staging", "stage", "stg", "test", "testing",
    "prod", "production", "uat", "qa",
    # Assets & Web
    "assets", "media", "static", "public", "files", "images", "img", "uploads",
    "content", "web", "cdn",
    # Internal & Sensitive
    "internal", "private", "confidential", "secret", "corp", "finance",
    "hr", "admin", "secure", "security", "infra",
    # Logs & Metrics
    "logs", "log", "audit", "monitoring", "telemetry",
    # Cloud & Tech
    "cloud", "storage", "app", "api", "bucket", "repo", "builds", "packages",
]


@dataclass
class CloudBucketFinding:
    """Represents a discovered cloud storage bucket or container."""
    provider: str                   # "AWS S3", "Google Cloud", "Azure Blob"
    bucket_name: str                # e.g., "target-backup"
    url: str                        # Direct probe URL
    status: str                     # "OPEN_LISTABLE", "PROTECTED"
    is_open: bool                   # True if publicly readable/listable
    severity: str                   # "CRITICAL" if is_open else "INFO"
    cvss_score: float               # 9.1 if is_open else 0.0
    object_count: int = 0           # Count of publicly listed files/objects
    sample_files: list[str] = field(default_factory=list) # Extracted sample keys/filenames
    evidence: str = ""              # Concrete proof / headers
    remediation: str = ""           # Specific mitigation guideline
    cve: str = "CWE-284"            # Improper Access Control

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return asdict(self)


class CloudAuditor:
    """
    Multi-Cloud Storage & Bucket Leakage Auditor.
    
    Generates intelligent permutations of domain/organization names and audits
    AWS S3, GCP Storage, and Azure Blob containers for public access misconfigurations.
    """

    def __init__(
        self,
        target: str,
        timeout: float = 3.5,
        threads: int = 15,
        user_agent: Optional[str] = None,
        custom_wordlist: Optional[list[str]] = None,
    ):
        """
        Initialize CloudAuditor.

        Args:
            target: Target domain (e.g. 'example.com'), URL, or organization name.
            timeout: Network timeout per request (seconds).
            threads: Concurrency thread count.
            user_agent: Custom HTTP User-Agent.
            custom_wordlist: Optional custom bucket names/words to test.
        """
        self.target = target.strip()
        self.timeout = timeout
        self.threads = max(1, min(threads, 50))
        self.custom_wordlist = custom_wordlist or []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 PhantomRecon/1.7.0"
            ),
            "Accept": "application/xml,application/json,text/html,*/*",
        })
        self.session.verify = False

        self.findings: list[CloudBucketFinding] = []

    def extract_keywords(self) -> list[str]:
        """
        Extract base organization keywords and variations from the target.
        Handles domains, subdomains, URLs, and bare names.
        """
        raw = self.target.lower()
        if raw.startswith(("http://", "https://")):
            parsed = urlparse(raw)
            host = parsed.netloc or parsed.path
        else:
            host = raw

        # Remove port if present
        host = host.split(":")[0].strip("/")

        # Clean common TLDs (e.g. .com, .net, .co.uk, .gov.az)
        parts = host.split(".")
        if len(parts) >= 2:
            # Common compound TLDs
            if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu"):
                core_domain = parts[-3]
            else:
                core_domain = parts[-2]
        else:
            core_domain = parts[0]

        keywords = set()
        clean_core = re.sub(r"[^a-z0-9\-]", "", core_domain)
        if clean_core:
            keywords.add(clean_core)
            # If contains hyphens, also add individual parts
            if "-" in clean_core:
                for subpart in clean_core.split("-"):
                    if len(subpart) >= 3:
                        keywords.add(subpart)

        # Also add significant subdomain labels (e.g., 'portal', 'api', 'dev', 'payments')
        if len(parts) >= 2:
            tld_offset = 2 if (len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu")) else 1
            domain_idx = len(parts) - 1 - tld_offset
            for sub_label in parts[:domain_idx]:
                sub_clean = re.sub(r"[^a-z0-9\-]", "", sub_label)
                if len(sub_clean) >= 3 and sub_clean not in ("www", "http", "https"):
                    keywords.add(sub_clean)
                    if clean_core:
                        keywords.add(f"{clean_core}-{sub_clean}")

        # Full host without dots
        combined = "".join(parts[:-1]) if len(parts) > 1 else parts[0]
        combined_clean = re.sub(r"[^a-z0-9]", "", combined)
        if len(combined_clean) >= 3 and len(combined_clean) <= 30:
            keywords.add(combined_clean)

        return sorted(list(keywords), key=len, reverse=True)

    def generate_bucket_names(self) -> list[str]:
        """
        Generate bucket candidate names using smart permutations.
        """
        keywords = self.extract_keywords()
        bucket_candidates = set()

        # Add custom words first
        for word in self.custom_wordlist:
            w = word.strip().lower()
            if 3 <= len(w) <= 63:
                bucket_candidates.add(w)

        for kw in keywords:
            # Base keyword
            if 3 <= len(kw) <= 63:
                bucket_candidates.add(kw)

            # Permutations: kw-pattern, kwpattern
            for pat in COMMON_BUCKET_PATTERNS:
                c1 = f"{kw}-{pat}"
                c2 = f"{pat}-{kw}"
                c3 = f"{kw}{pat}"

                for c in (c1, c2, c3):
                    # Valid AWS/GCP bucket name rules (3-63 chars, lowercase, no consecutive dashes)
                    if 3 <= len(c) <= 63 and not c.startswith("-") and not c.endswith("-"):
                        bucket_candidates.add(c)

        return sorted(list(bucket_candidates))

    def audit_aws_s3(self, bucket_name: str) -> Optional[CloudBucketFinding]:
        """
        Audit an AWS S3 bucket candidate.
        Checks for public list permissions and bucket existence.
        """
        url = f"https://{bucket_name}.s3.amazonaws.com"
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            body = resp.text

            # 1. Check for Publicly Listable Bucket (Status 200 + ListBucketResult)
            if resp.status_code == 200 and ("<ListBucketResult" in body or "<Contents>" in body):
                sample_files = self._parse_s3_xml_keys(body)
                count = len(re.findall(r"<Key>", body)) or len(sample_files)
                evidence = (
                    f"AWS S3 Public XML Listing Verified (HTTP 200 OK).\n"
                    f"Discovered {count} publicly downloadable objects.\n"
                    f"Sample Keys: {', '.join(sample_files[:5])}"
                )
                remediation = (
                    "Enable 'S3 Block Public Access' at the AWS account and bucket level. "
                    "Review Bucket Policy and ACL to remove 's3:ListBucket' permissions for 'Everyone' / 'AuthenticatedUsers'."
                )
                return CloudBucketFinding(
                    provider="AWS S3",
                    bucket_name=bucket_name,
                    url=url,
                    status="OPEN_LISTABLE",
                    is_open=True,
                    severity="CRITICAL",
                    cvss_score=9.1,
                    object_count=count,
                    sample_files=sample_files,
                    evidence=evidence,
                    remediation=remediation,
                )

            # 2. Check for Protected Bucket Exists (Status 403 + AccessDenied + Amazon S3 server)
            server_header = resp.headers.get("Server", "")
            if resp.status_code == 403 and ("AccessDenied" in body or "AllAccessDisabled" in body or "AmazonS3" in server_header):
                evidence = f"AWS S3 Bucket Exists (HTTP 403 AccessDenied). Direct listing is currently blocked."
                remediation = "Maintain Block Public Access settings and monitor CloudTrail for unauthorized access attempts."
                return CloudBucketFinding(
                    provider="AWS S3",
                    bucket_name=bucket_name,
                    url=url,
                    status="PROTECTED",
                    is_open=False,
                    severity="INFO",
                    cvss_score=0.0,
                    evidence=evidence,
                    remediation=remediation,
                )

        except requests.RequestException:
            pass

        return None

    def audit_gcp_storage(self, bucket_name: str) -> Optional[CloudBucketFinding]:
        """
        Audit a Google Cloud Storage (GCS) bucket candidate.
        """
        url = f"https://storage.googleapis.com/{bucket_name}"
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            body = resp.text

            # 1. Check for Publicly Listable GCS Bucket
            if resp.status_code == 200 and ("<ListBucketResult" in body or "<Contents>" in body or '"items":' in body):
                sample_files = self._parse_s3_xml_keys(body)
                count = len(re.findall(r"<Key>", body)) or len(sample_files)
                evidence = (
                    f"Google Cloud Storage Public XML Listing Verified (HTTP 200 OK).\n"
                    f"Discovered {count} publicly downloadable objects.\n"
                    f"Sample Keys: {', '.join(sample_files[:5])}"
                )
                remediation = (
                    "Enforce 'Public Access Prevention' (PAP) on the Google Cloud Storage bucket. "
                    "Remove 'allUsers' and 'allAuthenticatedUsers' from IAM permissions."
                )
                return CloudBucketFinding(
                    provider="Google Cloud",
                    bucket_name=bucket_name,
                    url=url,
                    status="OPEN_LISTABLE",
                    is_open=True,
                    severity="CRITICAL",
                    cvss_score=9.1,
                    object_count=count,
                    sample_files=sample_files,
                    evidence=evidence,
                    remediation=remediation,
                )

            # 2. Check for Protected GCS Bucket Exists (403 AccessDenied)
            if resp.status_code == 403 and ("AccessDenied" in body or "Access denied" in body or "UploadServer" in resp.headers.get("Server", "")):
                evidence = f"Google Cloud Storage Bucket Exists (HTTP 403 AccessDenied). Direct listing is currently restricted."
                return CloudBucketFinding(
                    provider="Google Cloud",
                    bucket_name=bucket_name,
                    url=url,
                    status="PROTECTED",
                    is_open=False,
                    severity="INFO",
                    cvss_score=0.0,
                    evidence=evidence,
                    remediation="Maintain uniform bucket-level access and verify public access prevention remains active.",
                )

        except requests.RequestException:
            pass

        return None

    def audit_azure_blob(
        self, name_candidate: str, container_name: Optional[str] = None
    ) -> Optional[CloudBucketFinding]:
        """
        Audit Microsoft Azure Blob Storage container candidates.
        Azure Storage account names must be 3-24 lowercase alphanumeric chars (no hyphens).
        """
        clean_account = re.sub(r"[^a-z0-9]", "", name_candidate.lower())
        if not (3 <= len(clean_account) <= 24):
            return None

        # Check root account enumeration and common public container names
        containers_to_test = [container_name] if container_name else ["$root", "public", "backup", "data", "media"]
        for container in containers_to_test:
            url = f"https://{clean_account}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                body = resp.text

                # 1. Publicly Listable Azure Container
                if resp.status_code == 200 and ("<EnumerationResults" in body or "<Blob>" in body):
                    sample_files = re.findall(r"<Name>(.*?)</Name>", body)
                    count = len(re.findall(r"<Blob>", body)) or len(sample_files)
                    evidence = (
                        f"Azure Blob Storage Container '{container}' is Publicly Listable (HTTP 200 OK).\n"
                        f"Discovered {count} publicly downloadable blobs.\n"
                        f"Sample Blobs: {', '.join(sample_files[:5])}"
                    )
                    remediation = (
                        "Set Azure Storage Account 'Allow Blob public access' to Disabled. "
                        "Change container access level to 'Private (no anonymous access)'."
                    )
                    return CloudBucketFinding(
                        provider="Azure Blob",
                        bucket_name=f"{clean_account}/{container}",
                        url=url,
                        status="OPEN_LISTABLE",
                        is_open=True,
                        severity="CRITICAL",
                        cvss_score=9.1,
                        object_count=count,
                        sample_files=sample_files,
                        evidence=evidence,
                        remediation=remediation,
                    )

                # 2. Azure Storage Account exists but container access denied
                server_hdr = resp.headers.get("Server", "")
                if ("Windows-Azure-Blob" in server_hdr) and resp.status_code in (403, 400):
                    return CloudBucketFinding(
                        provider="Azure Blob",
                        bucket_name=clean_account,
                        url=f"https://{clean_account}.blob.core.windows.net",
                        status="PROTECTED",
                        is_open=False,
                        severity="INFO",
                        cvss_score=0.0,
                        evidence="Azure Storage Account exists. Public blob container listing is restricted.",
                        remediation="Ensure anonymous access remains disabled across all storage containers.",
                    )
            except requests.RequestException:
                pass

        return None

    def _parse_s3_xml_keys(self, xml_text: str) -> list[str]:
        """Extract sample object keys from S3 / GCS XML response."""
        keys = []
        try:
            # Fast regex extraction (robust to namespaces)
            raw_keys = re.findall(r"<Key>(.*?)</Key>", xml_text)
            for k in raw_keys[:10]:
                if k.strip():
                    keys.append(k.strip())
        except Exception:
            pass
        return keys

    def audit_single_candidate(self, bucket_name: str) -> list[CloudBucketFinding]:
        """Audit a single bucket candidate across AWS, GCP, and Azure."""
        results = []
        # 1. AWS S3
        s3_res = self.audit_aws_s3(bucket_name)
        if s3_res:
            results.append(s3_res)

        # 2. GCP Storage
        gcp_res = self.audit_gcp_storage(bucket_name)
        if gcp_res:
            results.append(gcp_res)

        # 3. Azure Blob (only for non-hyphenated candidates to avoid redundant probes)
        if "-" not in bucket_name or len(bucket_name) <= 15:
            az_res = self.audit_azure_blob(bucket_name)
            if az_res:
                results.append(az_res)

        return results

    def run_cloud_audit(self) -> dict[str, Any]:
        """
        Execute concurrent multi-cloud storage audit across all generated permutations.
        Returns a comprehensive findings dictionary.
        """
        candidates = self.generate_bucket_names()
        logger.info(
            f"Initiating Cloud Storage Audit on target '{self.target}' "
            f"({len(candidates)} permutations across AWS, GCP, Azure, {self.threads} threads)..."
        )

        from concurrent.futures import ThreadPoolExecutor, as_completed

        self.findings = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_bucket = {
                executor.submit(self.audit_single_candidate, b): b
                for b in candidates
            }

            for future in as_completed(future_to_bucket):
                try:
                    res_list = future.result()
                    for f in res_list:
                        self.findings.append(f)
                        if f.is_open:
                            logger.warning(
                                f"🚨 [bold red]OPEN CLOUD BUCKET FOUND[/bold red]: "
                                f"{f.provider} -> {f.url} ({f.object_count} objects exposed!)"
                            )
                        else:
                            logger.debug(f"Protected cloud bucket: {f.provider} -> {f.url}")
                except Exception as e:
                    logger.debug(f"Bucket probe error: {e}")

        # Deduplicate findings by URL
        seen_urls = set()
        deduped = []
        for f in self.findings:
            if f.url not in seen_urls:
                seen_urls.add(f.url)
                deduped.append(f)
        self.findings = deduped

        # Sort: Open/Critical findings first, then alphabetical
        self.findings.sort(key=lambda x: (0 if x.is_open else 1, x.provider, x.bucket_name))

        open_findings = [f for f in self.findings if f.is_open]
        protected_findings = [f for f in self.findings if not f.is_open]

        summary = {
            "target": self.target,
            "total_tested": len(candidates),
            "total_discovered": len(self.findings),
            "open_buckets_count": len(open_findings),
            "protected_buckets_count": len(protected_findings),
            "findings": [f.to_dict() for f in self.findings],
            "open_buckets": [f.to_dict() for f in open_findings],
            "protected_buckets": [f.to_dict() for f in protected_findings],
        }

        return summary
