"""
Tests for Phantom Recon v1.7.0 Features.

Covers:
- Multi-Cloud Storage & Bucket Leakage Auditor (AWS S3, GCP, Azure Blob)
- Zero false-positive XML/JSON bucket response parsing
- Vulnerability Assessment & Explanations Matrix reporting
- HTML, Markdown, and Text report finding explanation columns
- CLI cloud command and vulnerability matrix rendering
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from click.testing import CliRunner

from phantom_recon.core.cloud_auditor import CloudAuditor, CloudBucketFinding
from phantom_recon.core.vuln_scanner import VulnerabilityScanner
from phantom_recon.reporting.report_generator import ReportGenerator
from phantom_recon.utils.logger import print_vulnerabilities_matrix
from phantom_recon.cli import main


class TestCloudAuditorKeywords:
    """Test keyword extraction and permutation generation for cloud buckets."""

    def test_extract_keywords_from_domain(self):
        auditor = CloudAuditor(target="portal.dev.megacorp.com")
        keywords = auditor.extract_keywords()
        assert "megacorp" in keywords
        assert "portal" in keywords
        assert "dev" in keywords
        assert "com" not in keywords

    def test_extract_keywords_from_url(self):
        auditor = CloudAuditor(target="https://secure.payments.fintech.io/api")
        keywords = auditor.extract_keywords()
        assert "fintech" in keywords
        assert "payments" in keywords
        assert "secure" in keywords

    def test_generate_bucket_names(self):
        auditor = CloudAuditor(target="mycompany.com")
        names = auditor.generate_bucket_names()
        assert len(names) > 0
        assert "mycompany" in names
        assert "mycompany-backup" in names or "mycompany-data" in names
        # Check all names conform to lowercase cloud bucket naming conventions
        for name in names:
            assert name == name.lower()
            assert 3 <= len(name) <= 63


class TestCloudAuditorProviders:
    """Test provider-specific bucket discovery and access level auditing."""

    @patch("requests.Session.get")
    def test_audit_aws_s3_open_listable(self, mock_get):
        xml_response = """<?xml version="1.0" encoding="UTF-8"?>
        <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <Name>megacorp-backup</Name>
            <Prefix></Prefix>
            <Contents>
                <Key>database_backup_2026.sql</Key>
                <Size>10485760</Size>
            </Contents>
            <Contents>
                <Key>credentials.env</Key>
                <Size>2048</Size>
            </Contents>
        </ListBucketResult>"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = xml_response
        mock_resp.headers = {"Content-Type": "application/xml"}
        mock_get.return_value = mock_resp

        auditor = CloudAuditor(target="megacorp.com")
        finding = auditor.audit_aws_s3("megacorp-backup")

        assert finding is not None
        assert finding.provider == "AWS S3"
        assert finding.bucket_name == "megacorp-backup"
        assert finding.is_open is True
        assert finding.status == "OPEN_LISTABLE"
        assert finding.severity == "CRITICAL"
        assert finding.cvss_score == 9.1
        assert finding.object_count == 2
        assert "database_backup_2026.sql" in finding.sample_files
        assert "credentials.env" in finding.sample_files

    @patch("requests.Session.get")
    def test_audit_aws_s3_protected(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
        mock_resp.headers = {"Server": "AmazonS3"}
        mock_get.return_value = mock_resp

        auditor = CloudAuditor(target="megacorp.com")
        finding = auditor.audit_aws_s3("megacorp-prod")

        assert finding is not None
        assert finding.provider == "AWS S3"
        assert finding.is_open is False
        assert finding.status == "PROTECTED"
        assert finding.severity == "INFO"
        assert finding.cvss_score == 0.0

    @patch("requests.Session.get")
    def test_audit_gcp_storage_open_listable(self, mock_get):
        xml_response = """<?xml version="1.0" encoding="UTF-8"?>
        <ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
            <Name>megacorp-assets</Name>
            <Contents>
                <Key>app-bundle.zip</Key>
                <Size>4096</Size>
            </Contents>
        </ListBucketResult>"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = xml_response
        mock_resp.headers = {"Content-Type": "application/xml", "Server": "UploadServer"}
        mock_get.return_value = mock_resp

        auditor = CloudAuditor(target="megacorp.com")
        finding = auditor.audit_gcp_storage("megacorp-assets")

        assert finding is not None
        assert finding.provider == "Google Cloud"
        assert finding.is_open is True
        assert finding.status == "OPEN_LISTABLE"
        assert finding.severity == "CRITICAL"
        assert "app-bundle.zip" in finding.sample_files

    @patch("requests.Session.get")
    def test_audit_azure_blob_open_listable(self, mock_get):
        xml_response = """<?xml version="1.0" encoding="utf-8"?>
        <EnumerationResults ServiceEndpoint="https://megacorp.blob.core.windows.net/">
            <Blobs>
                <Blob>
                    <Name>customer_dump.xlsx</Name>
                </Blob>
            </Blobs>
        </EnumerationResults>"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = xml_response
        mock_resp.headers = {"Server": "Windows-Azure-Blob/1.0"}
        mock_get.return_value = mock_resp

        auditor = CloudAuditor(target="megacorp.com")
        finding = auditor.audit_azure_blob("megacorp", "public")

        assert finding is not None
        assert finding.provider == "Azure Blob"
        assert finding.is_open is True
        assert finding.status == "OPEN_LISTABLE"
        assert finding.severity == "CRITICAL"
        assert "customer_dump.xlsx" in finding.sample_files

    @patch("requests.Session.get")
    def test_non_existent_bucket_returns_none(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "<Error><Code>NoSuchBucket</Code></Error>"
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        auditor = CloudAuditor(target="megacorp.com")
        finding = auditor.audit_aws_s3("non-existent-random-xyz-1234567")
        assert finding is None


class TestVulnScannerCloudIntegration:
    """Test integration of CloudAuditor inside VulnerabilityScanner."""

    @patch.object(CloudAuditor, "run_cloud_audit")
    def test_scanner_maps_open_bucket_to_critical_vulnerability(self, mock_audit):
        mock_audit.return_value = {
            "target": "example.com",
            "open_buckets_count": 1,
            "protected_buckets_count": 0,
            "findings": [
                {
                    "provider": "AWS S3",
                    "bucket_name": "example-backup",
                    "url": "https://example-backup.s3.amazonaws.com",
                    "status": "OPEN_LISTABLE",
                    "is_open": True,
                    "severity": "CRITICAL",
                    "cvss_score": 9.1,
                    "object_count": 5,
                    "sample_files": ["db.sql", "config.json"],
                    "evidence": "Publicly listable S3 bucket XML (5 objects found)",
                    "remediation": "Disable Public Access Block on AWS S3.",
                    "cve": "CWE-284",
                }
            ],
        }

        scanner = VulnerabilityScanner(url="https://example.com")
        cloud_vulns = scanner.check_cloud_storage()

        assert len(cloud_vulns) == 1
        vuln = cloud_vulns[0]
        assert vuln.severity == "critical"
        assert "AWS S3" in vuln.title
        assert "example-backup" in vuln.title
        assert vuln.cvss_score == 9.1
        assert "s3.amazonaws.com" in vuln.poc_url


class TestReportMatrixExplanations:
    """Verify that reports generate detailed table matrices with explanations and remediation."""

    @pytest.fixture
    def sample_scan_data(self):
        return {
            "target": "https://app.vulncorp.com",
            "url": "https://app.vulncorp.com",
            "vulnerabilities": [
                {
                    "title": "Cross-Origin Resource Sharing (CORS) Misconfiguration",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "confidence": "CONFIRMED",
                    "category": "cors",
                    "location": "GET /api/user/profile",
                    "url": "https://app.vulncorp.com",
                    "poc_url": "https://app.vulncorp.com/api/user/profile",
                    "reproduce_curl": "curl -i -H 'Origin: https://evil.com' 'https://app.vulncorp.com/api/user/profile'",
                    "evidence": "Access-Control-Allow-Origin: https://evil.com reflected with credentials",
                    "description": "Arbitrary cross-origin sites can read authenticated user profile responses.",
                    "remediation": "Restrict Access-Control-Allow-Origin to trusted origins and omit wildcard reflection.",
                },
                {
                    "title": "Missing HTTP Strict Transport Security (HSTS)",
                    "severity": "medium",
                    "cvss_score": 5.3,
                    "confidence": "CONFIRMED",
                    "category": "headers",
                    "location": "Header: Strict-Transport-Security",
                    "url": "https://app.vulncorp.com",
                    "poc_url": "https://app.vulncorp.com",
                    "reproduce_curl": "curl -I 'https://app.vulncorp.com'",
                    "evidence": "Strict-Transport-Security header was not returned in HTTP response",
                    "description": "Lack of HSTS exposes clients to SSL stripping and downgrade attacks.",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                },
            ],
            "cloud_storage": {
                "open_buckets_count": 0,
                "findings": [],
            },
        }

    def test_markdown_report_contains_matrix_columns(self, tmp_path, sample_scan_data):
        out_file = tmp_path / "report.md"
        generator = ReportGenerator(scan_data=sample_scan_data)
        generator.generate_markdown(str(out_file))

        content = out_file.read_text(encoding="utf-8")
        # Check matrix header columns
        assert "Vulnerability Findings Overview & Technical Matrix" in content
        assert "What It Is (Description & Impact)" in content
        assert "Remediation Guidance" in content
        assert "Arbitrary cross-origin sites can read authenticated user profile responses" in content
        assert "Restrict Access-Control-Allow-Origin" in content

    def test_text_report_contains_matrix_and_dossiers(self, tmp_path, sample_scan_data):
        out_file = tmp_path / "report.txt"
        generator = ReportGenerator(scan_data=sample_scan_data)
        generator.generate_text(str(out_file))

        content = out_file.read_text(encoding="utf-8")
        assert "VULNERABILITY FINDINGS MATRIX" in content
        assert "DETAILED VULNERABILITY DOSSIERS & REMEDIATION" in content
        assert "What It Is & Risk:" in content
        assert "Arbitrary cross-origin sites" in content

    def test_html_report_contains_matrix_table(self, tmp_path, sample_scan_data):
        out_file = tmp_path / "report.html"
        generator = ReportGenerator(scan_data=sample_scan_data)
        generator.generate_html(str(out_file))

        content = out_file.read_text(encoding="utf-8")
        assert "matrixTable" in content
        assert "matrix-row" in content
        assert "Vulnerability Findings & Explanations Matrix" in content
        assert "What It Is &amp; Real-World Impact" in content or "What It Is & Real-World Impact" in content
        assert "Arbitrary cross-origin sites" in content


class TestCLIFeatures:
    """Test CLI commands and visual matrix components."""

    def test_print_vulnerabilities_matrix_runs_cleanly(self):
        findings = [
            {
                "title": "Exposed .env Configuration File",
                "severity": "critical",
                "cvss_score": 9.8,
                "location": "https://example.com/.env",
                "description": "Environment variable file exposes DB passwords and API tokens.",
                "remediation": "Block dotfile access in web server configuration.",
                "cve": "CWE-200",
            }
        ]
        # Calling print_vulnerabilities_matrix should execute without error
        print_vulnerabilities_matrix(findings, "Test Matrix")

    @patch.object(CloudAuditor, "run_cloud_audit")
    def test_cli_cloud_command(self, mock_audit):
        mock_audit.return_value = {
            "target": "example.com",
            "total_tested": 10,
            "total_discovered": 1,
            "open_buckets_count": 1,
            "protected_buckets_count": 0,
            "findings": [
                {
                    "provider": "AWS S3",
                    "bucket_name": "example-backup",
                    "url": "https://example-backup.s3.amazonaws.com",
                    "status": "OPEN_LISTABLE",
                    "is_open": True,
                    "severity": "CRITICAL",
                    "cvss_score": 9.1,
                    "object_count": 3,
                    "sample_files": ["backup.sql"],
                    "evidence": "Publicly readable XML",
                    "remediation": "Block Public Access",
                }
            ],
        }

        runner = CliRunner()
        result = runner.invoke(main, ["cloud", "-t", "example.com"])
        assert result.exit_code == 0
        assert "Cloud Storage & Bucket Leakage Auditor" in result.output
        assert "AWS S3" in result.output
