"""Tests for modules/verify.py — CyrberVerify fraud detection."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from modules.verify import (
    CyrberVerify,
    calculate_risk,
    detect_query_type,
    _extract_red_flags,
    _whois_lookup,
    _wayback_first,
    _check_mx,
    _load_disposable_domains,
)


# ═══════════════════════════════════════════════════════════════
#  detect_query_type
# ═══════════════════════════════════════════════════════════════


class TestDetectQueryType:

    def test_url_with_scheme(self):
        assert detect_query_type("https://example.com") == "url"
        assert detect_query_type("http://evil.site/phish") == "url"

    def test_url_with_dot(self):
        assert detect_query_type("example.com") == "url"
        assert detect_query_type("ageotrans.eu") == "url"

    def test_email(self):
        assert detect_query_type("user@example.com") == "email"
        assert detect_query_type("test@domain.pl") == "email"

    def test_company(self):
        assert detect_query_type("AGE OTRANS sp z o o") == "company"
        assert detect_query_type("Firma Handlowa") == "company"


# ═══════════════════════════════════════════════════════════════
#  calculate_risk
# ═══════════════════════════════════════════════════════════════


class TestCalculateRisk:

    def test_clean_signals(self):
        signals = {
            "whois": {"age_days": 3650, "available": False},
            "google_safe_browsing": {"flagged": False},
            "virustotal": {"positives": 0, "total": 70},
            "urlhaus": {"blacklisted": False, "urls_count": 0},
        }
        score = calculate_risk(signals)
        assert score == 0

    def test_new_domain_high_risk(self):
        signals = {
            "whois": {"age_days": 30, "available": False},
            "google_safe_browsing": {"flagged": True},
            "virustotal": {"positives": 5, "total": 70},
        }
        score = calculate_risk(signals)
        # 40 (age<90) + 70 (gsb) + 60 (vt>=3) = 170 → capped 100
        assert score == 100

    def test_moderate_risk(self):
        signals = {
            "whois": {"age_days": 200, "available": False},
            "urlhaus": {"blacklisted": False, "urls_count": 3},
        }
        score = calculate_risk(signals)
        # 20 (age<365) + 25 (urlhaus urls>0) = 45
        assert score == 45

    def test_company_not_found(self):
        signals = {"company": {"found": False}}
        score = calculate_risk(signals)
        assert score == 60

    def test_disposable_email(self):
        signals = {
            "disposable_email": True,
            "mx": {"has_mx": False},
        }
        score = calculate_risk(signals)
        # 50 (disposable) + 30 (no mx) = 80
        assert score == 80

    def test_wayback_new_site(self):
        signals = {"wayback": {"archive_age_days": 30}}
        score = calculate_risk(signals)
        assert score == 25

    def test_empty_signals(self):
        assert calculate_risk({}) == 0

    def test_cap_at_100(self):
        signals = {
            "whois": {"age_days": 10, "available": True},
            "google_safe_browsing": {"flagged": True},
            "virustotal": {"positives": 10, "total": 70},
            "urlhaus": {"blacklisted": True},
            "disposable_email": True,
            "mx": {"has_mx": False},
        }
        score = calculate_risk(signals)
        assert score == 100


# ═══════════════════════════════════════════════════════════════
#  extract_red_flags
# ═══════════════════════════════════════════════════════════════


class TestExtractRedFlags:

    def test_new_domain(self):
        flags = _extract_red_flags({"whois": {"age_days": 30}})
        assert any("30 dni" in f for f in flags)

    def test_no_flags_clean(self):
        flags = _extract_red_flags({
            "whois": {"age_days": 3650, "available": False},
            "google_safe_browsing": {"flagged": False},
        })
        assert len(flags) == 0

    def test_multiple_flags(self):
        flags = _extract_red_flags({
            "google_safe_browsing": {"flagged": True, "threats": ["MALWARE"]},
            "urlhaus": {"blacklisted": True},
            "disposable_email": True,
        })
        assert len(flags) == 3


# ═══════════════════════════════════════════════════════════════
#  verify methods (mocked)
# ═══════════════════════════════════════════════════════════════


class TestVerifyUrl:

    @patch("modules.verify._whois_lookup")
    @patch("modules.verify._google_safe_browsing")
    @patch("modules.verify._virustotal_url")
    @patch("modules.verify._wayback_first")
    @patch("modules.verify._resolve_domain_ip")
    def test_verify_url_clean(self, mock_ip, mock_wb, mock_vt, mock_gsb, mock_whois):
        mock_whois.return_value = {"age_days": 3650, "domain": "example.com", "available": False}
        mock_gsb.return_value = {"available": True, "flagged": False}
        mock_vt.return_value = {"available": True, "positives": 0, "total": 70}
        mock_wb.return_value = {"available": True, "first_archive": "2015-01-01", "archive_age_days": 4000}
        mock_ip.return_value = None

        with patch("modules.verify._urlhaus_lookup", return_value={"urls_count": 0, "blacklisted": False}):
            v = CyrberVerify()
            result = v.verify_url("https://example.com")

        assert result["type"] == "url"
        assert result["risk_score"] == 0
        assert result["verdict"] == "BEZPIECZNE"
        assert "signals" in result
        assert "timestamp" in result

    @patch("modules.verify._whois_lookup")
    @patch("modules.verify._google_safe_browsing")
    @patch("modules.verify._virustotal_url")
    @patch("modules.verify._wayback_first")
    @patch("modules.verify._resolve_domain_ip")
    def test_verify_url_suspicious(self, mock_ip, mock_wb, mock_vt, mock_gsb, mock_whois):
        mock_whois.return_value = {"age_days": 200, "domain": "shady.com", "available": False}
        mock_gsb.return_value = {"available": True, "flagged": False}
        mock_vt.return_value = {"available": True, "positives": 2, "total": 70}
        mock_wb.return_value = {"available": True, "archive_age_days": 100, "first_archive": "2025-10-01"}
        mock_ip.return_value = None

        with patch("modules.verify._urlhaus_lookup", return_value={"urls_count": 0, "blacklisted": False}):
            v = CyrberVerify()
            result = v.verify_url("https://shady.com")

        # 20 (age<365) + 30 (vt 1-2) + 25 (wb<180) = 75
        assert result["risk_score"] == 75
        assert result["verdict"] == "OSZUSTWO"


class TestVerifyEmail:

    @patch("modules.verify._whois_lookup")
    @patch("modules.verify._check_mx")
    @patch("modules.verify._load_disposable_domains")
    def test_verify_email_clean(self, mock_disp, mock_mx, mock_whois):
        mock_disp.return_value = set()
        mock_mx.return_value = {"has_mx": True, "records": [{"host": "mx.example.com", "priority": 10}]}
        mock_whois.return_value = {"age_days": 5000, "domain": "example.com", "available": False}

        with patch("modules.verify._urlhaus_lookup", return_value={"urls_count": 0, "blacklisted": False}):
            v = CyrberVerify()
            result = v.verify_email("user@example.com")

        assert result["type"] == "email"
        assert result["risk_score"] == 0
        assert result["verdict"] == "BEZPIECZNE"

    @patch("modules.verify._whois_lookup")
    @patch("modules.verify._check_mx")
    @patch("modules.verify._load_disposable_domains")
    def test_verify_email_disposable(self, mock_disp, mock_mx, mock_whois):
        mock_disp.return_value = {"tempmail.com", "guerrillamail.com"}
        mock_mx.return_value = {"has_mx": True, "records": []}
        mock_whois.return_value = {"age_days": 100, "domain": "tempmail.com", "available": False}

        with patch("modules.verify._urlhaus_lookup", return_value={"urls_count": 0, "blacklisted": False}):
            v = CyrberVerify()
            result = v.verify_email("scammer@tempmail.com")

        assert result["signals"]["disposable_email"] is True
        assert result["risk_score"] >= 50

    def test_verify_email_invalid_format(self):
        v = CyrberVerify()
        result = v.verify_email("notanemail")
        assert result["risk_score"] == 80
        assert result["verdict"] == "OSZUSTWO"


class TestVerifyCompany:

    @patch("modules.verify._krs_lookup")
    @patch("modules.verify._ceidg_lookup")
    def test_company_found_krs(self, mock_ceidg, mock_krs):
        mock_krs.return_value = {
            "found": True, "registry": "KRS",
            "name": "Test Sp. z o.o.", "status": "active",
        }
        mock_ceidg.return_value = {"found": False, "registry": "CEIDG"}

        v = CyrberVerify()
        result = v.verify_company("Test Sp. z o.o.", country="PL")

        assert result["type"] == "company"
        assert result["risk_score"] == 0
        assert result["verdict"] == "BEZPIECZNE"

    @patch("modules.verify._krs_lookup")
    @patch("modules.verify._ceidg_lookup")
    def test_company_not_found(self, mock_ceidg, mock_krs):
        mock_krs.return_value = {"found": False, "registry": "KRS"}
        mock_ceidg.return_value = {"found": False, "registry": "CEIDG"}

        v = CyrberVerify()
        result = v.verify_company("Fake Company", country="PL")

        assert result["risk_score"] == 60
        assert result["verdict"] == "PODEJRZANE"


# ═══════════════════════════════════════════════════════════════
#  generate_verdict
# ═══════════════════════════════════════════════════════════════


class TestGenerateVerdict:

    def test_verdict_safe_fallback(self):
        from modules.verify import generate_verdict
        # When AI is unavailable, it should still return a valid verdict
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(10, {}, "test.com")
        assert result["verdict"] == "BEZPIECZNE"
        assert "summary" in result

    def test_verdict_fraud_fallback(self):
        from modules.verify import generate_verdict
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(80, {"urlhaus": {"blacklisted": True}}, "evil.com")
        assert result["verdict"] == "OSZUSTWO"
        assert len(result["red_flags"]) > 0
