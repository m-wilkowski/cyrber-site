"""Tests for modules/certipy_scan.py — AD CS enumeration (all mocked, no real AD)."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from modules.certipy_scan import (
    _detect_esc_vulns,
    _esc_remediation,
    _is_low_priv,
    _make_finding,
    _parse_certipy_output,
    run_certipy,
)


# ═══════════════════════════════════════════════════════════════
#  _is_low_priv
# ═══════════════════════════════════════════════════════════════


class TestIsLowPriv:

    def test_authenticated_users(self):
        assert _is_low_priv("Authenticated Users") is True

    def test_domain_users(self):
        assert _is_low_priv("Domain Users") is True

    def test_domain_admins_not_low(self):
        assert _is_low_priv("Domain Admins") is False

    def test_builtin_users(self):
        assert _is_low_priv("BUILTIN\\Users") is True

    def test_enterprise_admins_not_low(self):
        assert _is_low_priv("Enterprise Admins") is False

    def test_everyone(self):
        assert _is_low_priv("Everyone") is True

    def test_domain_computers(self):
        assert _is_low_priv("Domain Computers") is True


# ═══════════════════════════════════════════════════════════════
#  _esc_remediation
# ═══════════════════════════════════════════════════════════════


class TestEscRemediation:

    def test_esc1(self):
        r = _esc_remediation("ESC1")
        assert "Supply in the request" in r

    def test_esc6(self):
        r = _esc_remediation("ESC6")
        assert "certutil" in r

    def test_unknown_esc(self):
        r = _esc_remediation("ESC99")
        assert r == "Review and restrict AD CS configuration."


# ═══════════════════════════════════════════════════════════════
#  _make_finding
# ═══════════════════════════════════════════════════════════════


class TestMakeFinding:

    def test_structure(self):
        f = _make_finding("ESC1", "TestTemplate", "desc", "critical")
        assert f["esc"] == "ESC1"
        assert f["name"] == "ESC1: TestTemplate"
        assert f["title"] == "AD CS ESC1 — TestTemplate"
        assert f["severity"] == "critical"
        assert f["description"] == "desc"
        assert f["mitre"] == "T1649"
        assert f["source"] == "certipy"
        assert "Supply in the request" in f["remediation"]

    def test_detail_from_descriptions(self):
        f = _make_finding("ESC8", "CA1", "web enrollment", "high")
        assert "NTLM relay" in f["detail"]

    def test_unknown_esc_empty_detail(self):
        f = _make_finding("ESC99", "X", "d", "low")
        assert f["detail"] == ""


# ═══════════════════════════════════════════════════════════════
#  _detect_esc_vulns
# ═══════════════════════════════════════════════════════════════


class TestDetectEscVulns:

    def test_esc1(self):
        tpl = {
            "Enrollee Supplies Subject": True,
            "Client Authentication": True,
            "Enrollment Rights": ["Domain Users"],
            "Requires Manager Approval": False,
        }
        vulns = _detect_esc_vulns("VulnTpl", tpl)
        escs = [v["esc"] for v in vulns]
        assert "ESC1" in escs

    def test_esc2(self):
        tpl = {
            "Any Purpose": True,
            "Enrollment Rights": ["Authenticated Users"],
        }
        vulns = _detect_esc_vulns("AnyPurposeTpl", tpl)
        escs = [v["esc"] for v in vulns]
        assert "ESC2" in escs

    def test_esc3(self):
        tpl = {
            "Certificate Request Agent": True,
            "Enrollment Rights": ["Domain Users"],
        }
        vulns = _detect_esc_vulns("AgentTpl", tpl)
        escs = [v["esc"] for v in vulns]
        assert "ESC3" in escs

    def test_esc4_write_dacl(self):
        tpl = {
            "Write Dacl": ["Domain Users"],
        }
        vulns = _detect_esc_vulns("AclTpl", tpl)
        escs = [v["esc"] for v in vulns]
        assert "ESC4" in escs

    def test_clean_template_admin_only(self):
        """Template with admin-only enrollment → no vulns."""
        tpl = {
            "Enrollee Supplies Subject": True,
            "Client Authentication": True,
            "Enrollment Rights": ["Domain Admins"],
            "Requires Manager Approval": False,
        }
        vulns = _detect_esc_vulns("SafeTpl", tpl)
        assert vulns == []

    def test_esc1_blocked_by_approval(self):
        """ESC1 conditions met but requires approval → no ESC1."""
        tpl = {
            "Enrollee Supplies Subject": True,
            "Client Authentication": True,
            "Enrollment Rights": ["Domain Users"],
            "Requires Manager Approval": True,
        }
        vulns = _detect_esc_vulns("ApprovalTpl", tpl)
        escs = [v["esc"] for v in vulns]
        assert "ESC1" not in escs

    def test_esc9(self):
        tpl = {
            "No Security Extension": True,
            "Enrollment Rights": ["Domain Users"],
        }
        vulns = _detect_esc_vulns("NoSecExtTpl", tpl)
        escs = [v["esc"] for v in vulns]
        assert "ESC9" in escs

    def test_esc13(self):
        tpl = {
            "Issuance Policies": ["SomePolicy"],
            "Enrollment Rights": ["Authenticated Users"],
        }
        vulns = _detect_esc_vulns("PolicyTpl", tpl)
        escs = [v["esc"] for v in vulns]
        assert "ESC13" in escs


# ═══════════════════════════════════════════════════════════════
#  _parse_certipy_output
# ═══════════════════════════════════════════════════════════════


class TestParseCertipyOutput:

    def test_full_parse(self):
        """CA with Web Enrollment + User SAN + vulnerable template → findings."""
        raw = {
            "Certificate Authorities": {
                "CORP-CA": {
                    "DNS Name": "dc01.corp.local",
                    "Certificate Subject": "CN=CORP-CA",
                    "Web Enrollment": "Enabled",
                    "User Specified SAN": "Enabled",
                }
            },
            "Certificate Templates": {
                "VulnTemplate": {
                    "Enabled": True,
                    "Enrollee Supplies Subject": True,
                    "Client Authentication": True,
                    "Enrollment Rights": ["Domain Users"],
                    "Requires Manager Approval": False,
                }
            },
        }
        result = _parse_certipy_output(raw, "10.0.0.1")

        assert result["findings_count"] > 0
        assert result["risk_level"] == "critical"
        assert len(result["vulnerable_templates"]) > 0
        escs = [f["esc"] for f in result["findings"]]
        assert "ESC6" in escs  # User Specified SAN
        assert "ESC8" in escs  # Web Enrollment
        assert "ESC1" in escs  # template vuln

    def test_clean_output(self):
        """No vulnerabilities → risk_level low, empty findings."""
        raw = {
            "Certificate Authorities": {
                "SAFE-CA": {
                    "DNS Name": "dc01.safe.local",
                    "Web Enrollment": "Disabled",
                    "User Specified SAN": "Disabled",
                }
            },
            "Certificate Templates": {
                "SafeTemplate": {
                    "Enabled": True,
                    "Enrollment Rights": ["Domain Admins"],
                }
            },
        }
        result = _parse_certipy_output(raw, "10.0.0.1")

        assert result["findings_count"] == 0
        assert result["risk_level"] == "low"
        assert result["vulnerable_templates"] == []

    def test_esc7_manage_ca(self):
        """CA grants ManageCA to Domain Users → ESC7."""
        raw = {
            "Certificate Authorities": {
                "WEAK-CA": {
                    "DNS Name": "dc.corp.local",
                    "Web Enrollment": "Disabled",
                    "User Specified SAN": "Disabled",
                    "ManageCA": ["Domain Users"],
                }
            },
            "Certificate Templates": {},
        }
        result = _parse_certipy_output(raw, "10.0.0.1")
        escs = [f["esc"] for f in result["findings"]]
        assert "ESC7" in escs

    def test_empty_input(self):
        """Empty JSON → no crash, low risk."""
        result = _parse_certipy_output({}, "10.0.0.1")
        assert result["findings_count"] == 0
        assert result["risk_level"] == "low"


# ═══════════════════════════════════════════════════════════════
#  run_certipy — integration (mocked subprocess)
# ═══════════════════════════════════════════════════════════════


class TestRunCertipy:

    @patch("modules.certipy_scan.shutil.which", return_value="/usr/bin/certipy")
    def test_no_credentials(self, mock_which):
        """No AD credentials → skipped."""
        result = run_certipy("192.168.1.1")
        assert result["skipped"] is True
        assert "requires AD credentials" in result["reason"]

    @patch("modules.certipy_scan.shutil.which", return_value=None)
    def test_certipy_not_installed(self, mock_which):
        """certipy not in PATH → skipped."""
        result = run_certipy("192.168.1.1")
        assert result["skipped"] is True
        assert result["reason"] == "certipy not installed"

    @patch("modules.certipy_scan.shutil.which", return_value="/usr/bin/certipy")
    @patch("modules.certipy_scan.subprocess.run")
    def test_timeout(self, mock_run, mock_which):
        """subprocess.run raises TimeoutExpired → error with 'timed out'."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="certipy", timeout=120)

        result = run_certipy("192.168.1.1", username="u", password="p",
                             domain="corp.local", dc_ip="10.0.0.1")

        assert "timed out" in result["error"]
        assert result["findings"] == []
