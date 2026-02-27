"""Tests for backend.validators — input sanitization and target validation."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from backend.validators import (
    sanitize_target,
    validate_target,
    validate_port,
    validate_cidr,
    require_valid_target,
)


# ═══════════════════════════════════════════════════════════════════
# sanitize_target
# ═══════════════════════════════════════════════════════════════════


class TestSanitize:
    def test_strips_whitespace(self):
        assert sanitize_target("  192.168.1.1  ") == "192.168.1.1"

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="empty"):
            sanitize_target("")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            sanitize_target("a" * 300)

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_target("192.168.1.1; rm -rf /")

    def test_rejects_ampersand(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_target("example.com && cat /etc/passwd")

    def test_rejects_pipe(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_target("example.com | whoami")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_target("`id`")

    def test_rejects_dollar_sign(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_target("$(whoami)")

    def test_rejects_newline(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_target("example.com\ncat /etc/passwd")

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_target("../../../etc/passwd")

    def test_accepts_valid_ip(self):
        assert sanitize_target("192.168.1.1") == "192.168.1.1"

    def test_accepts_valid_domain(self):
        assert sanitize_target("example.com") == "example.com"


# ═══════════════════════════════════════════════════════════════════
# validate_target
# ═══════════════════════════════════════════════════════════════════


class TestValidateTarget:
    def test_ipv4(self):
        valid, ttype, reason = validate_target("192.168.1.1")
        assert valid is True
        assert ttype == "ipv4"

    def test_ipv4_cidr(self):
        valid, ttype, reason = validate_target("10.0.0.0/24")
        assert valid is True
        assert ttype == "ipv4_cidr"

    def test_ipv6(self):
        valid, ttype, reason = validate_target("2001:db8::1")
        assert valid is True
        assert ttype == "ipv6"

    def test_domain(self):
        valid, ttype, reason = validate_target("example.com")
        assert valid is True
        assert ttype == "domain"

    def test_subdomain(self):
        valid, ttype, reason = validate_target("sub.example.com")
        assert valid is True
        assert ttype == "domain"

    def test_url_http(self):
        valid, ttype, reason = validate_target("http://192.168.1.1")
        assert valid is True
        assert ttype == "url"

    def test_url_https(self):
        valid, ttype, reason = validate_target("https://example.com/path")
        assert valid is True
        assert ttype == "url"

    def test_hostname_local(self):
        valid, ttype, reason = validate_target("target-host.local")
        assert valid is True
        assert ttype in ("domain", "hostname")

    def test_invalid_ipv4(self):
        valid, ttype, reason = validate_target("999.999.999.999")
        assert valid is False

    def test_command_injection_semicolon(self):
        valid, ttype, reason = validate_target("192.168.1.1; rm -rf /")
        assert valid is False
        assert "dangerous" in reason

    def test_command_injection_ampersand(self):
        valid, ttype, reason = validate_target("example.com && cat /etc/passwd")
        assert valid is False

    def test_command_substitution(self):
        valid, ttype, reason = validate_target("$(whoami)")
        assert valid is False

    def test_backtick_injection(self):
        valid, ttype, reason = validate_target("`id`")
        assert valid is False

    def test_empty_string(self):
        valid, ttype, reason = validate_target("")
        assert valid is False

    def test_too_long(self):
        valid, ttype, reason = validate_target("a" * 300)
        assert valid is False

    def test_path_traversal(self):
        valid, ttype, reason = validate_target("../../../etc/passwd")
        assert valid is False

    def test_newline_injection(self):
        valid, ttype, reason = validate_target("example.com\ncat /etc/passwd")
        assert valid is False

    def test_pipe_injection(self):
        valid, ttype, reason = validate_target("10.0.0.1 | cat /etc/shadow")
        assert valid is False


# ═══════════════════════════════════════════════════════════════════
# validate_port
# ═══════════════════════════════════════════════════════════════════


class TestValidatePort:
    def test_valid_port(self):
        valid, reason = validate_port(443)
        assert valid is True

    def test_port_min(self):
        valid, _ = validate_port(1)
        assert valid is True

    def test_port_max(self):
        valid, _ = validate_port(65535)
        assert valid is True

    def test_port_zero(self):
        valid, _ = validate_port(0)
        assert valid is False

    def test_port_too_high(self):
        valid, _ = validate_port(70000)
        assert valid is False


# ═══════════════════════════════════════════════════════════════════
# validate_cidr
# ═══════════════════════════════════════════════════════════════════


class TestValidateCidr:
    def test_valid_cidr(self):
        valid, _ = validate_cidr("10.0.0.0/8")
        assert valid is True

    def test_host_cidr(self):
        valid, _ = validate_cidr("192.168.1.1/32")
        assert valid is True

    def test_invalid_cidr(self):
        valid, _ = validate_cidr("999.0.0.0/8")
        assert valid is False


# ═══════════════════════════════════════════════════════════════════
# require_valid_target (HTTPException)
# ═══════════════════════════════════════════════════════════════════


class TestRequireValidTarget:
    def test_returns_sanitized(self):
        result = require_valid_target("  10.0.0.1  ")
        assert result == "10.0.0.1"

    def test_raises_on_injection(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            require_valid_target("10.0.0.1; cat /etc/passwd")
        assert exc_info.value.status_code == 400

    def test_raises_on_empty(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            require_valid_target("")
        assert exc_info.value.status_code == 400
