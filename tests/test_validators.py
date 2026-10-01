"""
Tests for Phantom Recon — Validators module.
"""

import pytest

from phantom_recon.utils.validators import (
    validate_ip,
    validate_ipv4,
    validate_ipv6,
    validate_cidr,
    validate_domain,
    validate_url,
    validate_email,
    validate_port,
    parse_ports,
    validate_target,
    validate_file_path,
)


class TestIPValidation:
    """Tests for IP address validation."""

    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True
        assert validate_ip("0.0.0.0") is True
        assert validate_ip("255.255.255.255") is True

    def test_valid_ipv6(self):
        assert validate_ip("::1") is True
        assert validate_ip("fe80::1") is True
        assert validate_ip("2001:db8::1") is True

    def test_invalid_ip(self):
        assert validate_ip("256.1.1.1") is False
        assert validate_ip("abc") is False
        assert validate_ip("") is False
        assert validate_ip("192.168.1") is False
        assert validate_ip("192.168.1.1.1") is False

    def test_ipv4_specific(self):
        assert validate_ipv4("192.168.1.1") is True
        assert validate_ipv4("::1") is False

    def test_ipv6_specific(self):
        assert validate_ipv6("::1") is True
        assert validate_ipv6("192.168.1.1") is False


class TestCIDRValidation:
    """Tests for CIDR notation validation."""

    def test_valid_cidr(self):
        assert validate_cidr("192.168.1.0/24") is True
        assert validate_cidr("10.0.0.0/8") is True
        assert validate_cidr("172.16.0.0/12") is True

    def test_invalid_cidr(self):
        assert validate_cidr("192.168.1.0/33") is False
        assert validate_cidr("abc/24") is False
        assert validate_cidr("") is False


class TestDomainValidation:
    """Tests for domain name validation."""

    def test_valid_domains(self):
        assert validate_domain("example.com") is True
        assert validate_domain("sub.example.com") is True
        assert validate_domain("my-site.co.uk") is True
        assert validate_domain("test123.org") is True

    def test_invalid_domains(self):
        assert validate_domain("") is False
        assert validate_domain("-example.com") is False
        assert validate_domain("example") is False
        assert validate_domain(".com") is False
        assert validate_domain("exam ple.com") is False


class TestURLValidation:
    """Tests for URL validation."""

    def test_valid_urls(self):
        assert validate_url("https://example.com") is True
        assert validate_url("http://192.168.1.1") is True
        assert validate_url("https://example.com/path?q=1") is True
        assert validate_url("http://sub.example.com:8080") is True

    def test_invalid_urls(self):
        assert validate_url("") is False
        assert validate_url("ftp://example.com") is False
        assert validate_url("example.com") is False
        assert validate_url("not-a-url") is False


class TestEmailValidation:
    """Tests for email validation."""

    def test_valid_emails(self):
        assert validate_email("user@example.com") is True
        assert validate_email("test.user@domain.co.uk") is True
        assert validate_email("admin+tag@example.org") is True

    def test_invalid_emails(self):
        assert validate_email("") is False
        assert validate_email("@example.com") is False
        assert validate_email("user@") is False
        assert validate_email("user@.com") is False


class TestPortValidation:
    """Tests for port number validation."""

    def test_valid_ports(self):
        assert validate_port(0) is True
        assert validate_port(80) is True
        assert validate_port(443) is True
        assert validate_port(65535) is True

    def test_invalid_ports(self):
        assert validate_port(-1) is False
        assert validate_port(65536) is False
        assert validate_port(100000) is False


class TestPortParsing:
    """Tests for port specification parsing."""

    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_comma_separated(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_port_range(self):
        result = parse_ports("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_mixed_format(self):
        result = parse_ports("22,80,8000-8002")
        assert result == [22, 80, 8000, 8001, 8002]

    def test_deduplication(self):
        result = parse_ports("80,80,80")
        assert result == [80]

    def test_spaces_in_ports(self):
        result = parse_ports("22, 80, 443")
        assert result == [22, 80, 443]

    def test_invalid_port_string(self):
        with pytest.raises(ValueError):
            parse_ports("abc")

    def test_port_out_of_range(self):
        with pytest.raises(ValueError):
            parse_ports("99999")

    def test_invalid_range(self):
        with pytest.raises(ValueError):
            parse_ports("1000-500")


class TestTargetValidation:
    """Tests for target type detection."""

    def test_detect_ipv4(self):
        assert validate_target("192.168.1.1") == "ipv4"

    def test_detect_ipv6(self):
        assert validate_target("::1") == "ipv6"

    def test_detect_cidr(self):
        assert validate_target("192.168.1.0/24") == "cidr"

    def test_detect_domain(self):
        assert validate_target("example.com") == "domain"

    def test_detect_url(self):
        assert validate_target("https://example.com") == "url"

    def test_detect_unknown(self):
        assert validate_target("not valid at all!!!") == "unknown"
