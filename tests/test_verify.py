"""Tests for modules/verify.py — CyrberVerify fraud detection."""

import json
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from modules.verify import (
    CyrberVerify,
    SAFE_EMAIL_DOMAINS,
    KNOWN_COMPANIES,
    _COMPANY_KEYWORDS_PL,
    _COMPANY_KEYWORDS_UK,
    _COMPANY_KEYWORDS_DE,
    calculate_risk,
    detect_query_type,
    generate_verdict,
    _extract_red_flags,
    _extract_trust_factors,
    _extract_signal_explanations,
    _extract_problems,
    _extract_positives,
    _generate_action,
    _generate_narrative,
    _generate_educational_tips,
    _generate_immediate_actions,
    _generate_if_paid_already,
    _generate_report_to,
    _krs_lookup,
    _ceidg_lookup,
    _biala_lista_lookup,
    _companies_house_lookup,
    _opencorporates_lookup,
    _urlhaus_lookup,
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

    def test_nip_as_company(self):
        """NIP (10 digits) should be detected as company."""
        assert detect_query_type("5272720862") == "company"
        assert detect_query_type("527-272-08-62") == "company"
        assert detect_query_type("527 272 08 62") == "company"

    def test_company_keywords_pl(self):
        """Polish company keywords → company."""
        assert detect_query_type("Firma sp z o o") == "company"
        assert detect_query_type("Test gmbh") == "company"
        assert detect_query_type("Acme Ltd") == "company"


# ═══════════════════════════════════════════════════════════════
#  calculate_risk — bidirectional scoring
#  Thresholds: <20 BEZPIECZNE, 20-50 PODEJRZANE, >50 OSZUSTWO
# ═══════════════════════════════════════════════════════════════


class TestCalculateRisk:

    def test_clean_signals(self):
        """Clean signals with old domain should score 0 (negative factors floor to 0)."""
        signals = {
            "whois": {"age_days": 3650, "available": False},
            "google_safe_browsing": {"flagged": False},
            "virustotal": {"positives": 0, "total": 70},
            "urlhaus": {"blacklisted": False, "urls_count": 0},
        }
        score = calculate_risk(signals)
        # age 3650 = exactly 10 years → -30, floor to 0
        assert score == 0

    def test_new_domain_high_risk(self):
        signals = {
            "whois": {"age_days": 30, "available": False},
            "google_safe_browsing": {"flagged": True},
            "virustotal": {"positives": 5, "total": 70},
        }
        score = calculate_risk(signals)
        # 40 (age<90) + 70 (gsb) + 60 (vt>=5) = 170 → capped 100
        assert score == 100

    def test_moderate_risk(self):
        signals = {
            "whois": {"age_days": 200, "available": False},
            "urlhaus": {"blacklisted": False, "urls_count": 3},
        }
        score = calculate_risk(signals)
        # 20 (age<365) = 20 (urlhaus urls_count no longer scores without blacklisted)
        assert score == 20

    def test_company_not_found_no_registries(self):
        """Company not found, no registries searched → +5."""
        signals = {"company": {"found": False}}
        score = calculate_risk(signals)
        assert score == 5

    def test_company_not_found_nip_two_registries(self):
        """NIP not found in PL (KRS+CEIDG+BL) → +30."""
        signals = {"company": {"found": False, "registries_searched": ["KRS", "CEIDG", "Biała Lista VAT"], "query_type": "nip"}}
        score = calculate_risk(signals)
        assert score == 30

    def test_company_not_found_one_registry(self):
        """NIP not found in one registry → +20."""
        signals = {"company": {"found": False, "registries_searched": ["KRS"]}}
        score = calculate_risk(signals)
        assert score == 20

    def test_company_name_search_limited(self):
        """Name search limited → only +5 (not penalized heavily)."""
        signals = {"company": {"found": False, "name_search_limited": True, "registries_searched": ["Biała Lista VAT", "Companies House"]}}
        score = calculate_risk(signals)
        assert score == 5

    def test_company_name_search_limited_with_candidates(self):
        """Name search limited + candidates → +5-5=0."""
        signals = {"company": {"found": False, "name_search_limited": True, "registries_searched": ["Biała Lista VAT"], "candidates": [{"name": "X"}]}}
        score = calculate_risk(signals)
        assert score == 0

    def test_company_found_reduces(self):
        """Company confirmed in registry reduces score."""
        signals = {
            "whois": {"age_days": 200, "available": False},
            "company": {"found": True, "registry": "KRS"},
        }
        score = calculate_risk(signals)
        # 20 (age<365) - 40 (company found) = -20 → floor 0
        assert score == 0

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

    def test_floor_at_zero(self):
        """Trust signals should not produce negative scores."""
        signals = {
            "whois": {"age_days": 5000, "available": False},
            "tranco": {"available": True, "rank": 500},
            "spf_dmarc": {"has_spf": True, "has_dmarc": True},
            "company": {"found": True, "registry": "KRS"},
            "crtsh": {"cert_age_days": 1000},
        }
        score = calculate_risk(signals)
        assert score == 0

    # ── NEW bidirectional tests ──

    def test_tranco_top_10k_reduces_risk(self):
        """Tranco rank 5000 → -50."""
        signals = {
            "whois": {"age_days": 200, "available": False},
            "tranco": {"available": True, "rank": 5000},
            "urlhaus": {"blacklisted": True},  # +50
        }
        score = calculate_risk(signals)
        # 20 (age<365) + 50 (urlhaus) - 50 (tranco top10K) = 20
        assert score == 20

    def test_old_domain_reduces_risk(self):
        """Domain age >10 years → -30."""
        signals = {
            "whois": {"age_days": 4000, "available": False},
            "urlhaus": {"blacklisted": True},  # +50
        }
        score = calculate_risk(signals)
        # 50 (urlhaus) - 30 (age>3650) = 20
        assert score == 20

    def test_abuseipdb_high_score(self):
        """AbuseIPDB score 80 → +40."""
        signals = {
            "abuseipdb": {"available": True, "abuseConfidenceScore": 80, "totalReports": 15, "isWhitelisted": False},
        }
        score = calculate_risk(signals)
        assert score == 40

    def test_abuseipdb_whitelisted_reduces(self):
        """AbuseIPDB whitelisted → -30."""
        signals = {
            "whois": {"age_days": 200, "available": False},
            "abuseipdb": {"available": True, "abuseConfidenceScore": 0, "isWhitelisted": True},
            "urlhaus": {"blacklisted": True},  # +50
        }
        score = calculate_risk(signals)
        # 20 (age<365) + 50 (urlhaus) - 30 (whitelisted) = 40
        assert score == 40

    def test_spf_dmarc_bonus(self):
        """Both SPF + DMARC present → -10."""
        signals = {
            "whois": {"age_days": 200, "available": False},
            "spf_dmarc": {"has_spf": True, "has_dmarc": True},
        }
        score = calculate_risk(signals)
        # 20 (age<365) - 10 (spf+dmarc) = 10
        assert score == 10

    def test_known_safe_domain_pattern(self):
        """Tranco 5K + age 4000 + SPF+DMARC → score ≤ 0 (floored)."""
        signals = {
            "whois": {"age_days": 4000, "available": False},
            "tranco": {"available": True, "rank": 5000},
            "spf_dmarc": {"has_spf": True, "has_dmarc": True},
            "google_safe_browsing": {"flagged": False},
            "virustotal": {"positives": 0, "total": 70},
        }
        score = calculate_risk(signals)
        # -30 (age>3650) - 50 (tranco top10K) - 10 (spf+dmarc) = -90 → floor 0
        assert score == 0

    def test_new_thresholds(self):
        """Verify new threshold boundaries: <20 BEZPIECZNE, 25 PODEJRZANE, 55 OSZUSTWO."""
        from modules.verify import generate_verdict
        with patch("modules.verify.generate_verdict", wraps=generate_verdict):
            # Score 15 → BEZPIECZNE
            r1 = generate_verdict(15, {}, "test")
            assert r1["verdict"] == "BEZPIECZNE"
            # Score 25 → PODEJRZANE
            r2 = generate_verdict(25, {}, "test")
            assert r2["verdict"] == "PODEJRZANE"
            # Score 55 → OSZUSTWO
            r3 = generate_verdict(55, {}, "test")
            assert r3["verdict"] == "OSZUSTWO"

    def test_crtsh_old_cert_reduces(self):
        """cert_age_days 1000 → -20."""
        signals = {
            "whois": {"age_days": 200, "available": False},
            "crtsh": {"cert_age_days": 1000},
            "urlhaus": {"blacklisted": True},  # +50
        }
        score = calculate_risk(signals)
        # 20 (age<365) + 50 (urlhaus) - 20 (cert>730) = 50
        assert score == 50


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

    def test_new_sources_flags(self):
        """Red flags include AbuseIPDB, OTX, IPinfo, SPF/DMARC, crt.sh."""
        flags = _extract_red_flags({
            "abuseipdb": {"abuseConfidenceScore": 80, "totalReports": 10},
            "otx": {"pulse_count": 3},
            "ipinfo": {"country": "RU"},
            "spf_dmarc": {"has_spf": False, "has_dmarc": False},
            "crtsh": {"cert_age_days": 5},
        })
        assert any("AbuseIPDB" in f for f in flags)
        assert any("OTX" in f for f in flags)
        assert any("IPinfo" in f or "hosting" in f for f in flags)
        assert any("SPF" in f for f in flags)
        assert any("crt.sh" in f or "certyfikat" in f for f in flags)


# ═══════════════════════════════════════════════════════════════
#  extract_trust_factors
# ═══════════════════════════════════════════════════════════════


class TestExtractTrustFactors:

    def test_tranco_trust(self):
        factors = _extract_trust_factors({"tranco": {"available": True, "rank": 500}})
        assert any("Tranco" in f for f in factors)
        assert any("top 10K" in f for f in factors)

    def test_old_domain_trust(self):
        factors = _extract_trust_factors({"whois": {"age_days": 5000}})
        assert any("lat" in f for f in factors)

    def test_spf_dmarc_trust(self):
        factors = _extract_trust_factors({"spf_dmarc": {"has_spf": True, "has_dmarc": True}})
        assert any("SPF" in f and "DMARC" in f for f in factors)

    def test_company_confirmed_trust(self):
        factors = _extract_trust_factors({"company": {"found": True, "registry": "KRS"}})
        assert any("potwierdzona" in f for f in factors)


# ═══════════════════════════════════════════════════════════════
#  extract_signal_explanations
# ═══════════════════════════════════════════════════════════════


class TestExtractSignalExplanations:

    def test_returns_list_of_dicts(self):
        expls = _extract_signal_explanations({
            "whois": {"age_days": 50},
            "google_safe_browsing": {"available": True, "flagged": False},
        })
        assert isinstance(expls, list)
        assert len(expls) >= 2
        for e in expls:
            assert "signal" in e
            assert "risk" in e
            assert e["risk"] in ("green", "gray", "amber", "red")

    def test_new_domain_red(self):
        expls = _extract_signal_explanations({"whois": {"age_days": 10}})
        whois_expl = [e for e in expls if "WHOIS" in e["signal"]]
        assert whois_expl[0]["risk"] == "red"


# ═══════════════════════════════════════════════════════════════
#  verify methods (mocked)
# ═══════════════════════════════════════════════════════════════


class TestVerifyUrl:

    @patch("modules.verify._otx_lookup")
    @patch("modules.verify._tranco_lookup")
    @patch("modules.verify._check_spf_dmarc")
    @patch("modules.verify._crtsh_lookup")
    @patch("modules.verify._rdap_lookup")
    @patch("modules.verify._whois_lookup")
    @patch("modules.verify._google_safe_browsing")
    @patch("modules.verify._virustotal_url")
    @patch("modules.verify._wayback_first")
    @patch("modules.verify._resolve_domain_ip")
    def test_verify_url_clean(self, mock_ip, mock_wb, mock_vt, mock_gsb, mock_whois,
                               mock_rdap, mock_crtsh, mock_spf, mock_tranco, mock_otx):
        mock_whois.return_value = {"age_days": 3650, "domain": "example.com", "available": False}
        mock_gsb.return_value = {"available": True, "flagged": False}
        mock_vt.return_value = {"available": True, "positives": 0, "total": 70}
        mock_wb.return_value = {"available": True, "first_archive": "2015-01-01", "archive_age_days": 4000}
        mock_ip.return_value = None
        mock_rdap.return_value = {"available": True, "registration": "2015-01-01"}
        mock_crtsh.return_value = {"available": True, "cert_age_days": 2000}
        mock_spf.return_value = {"has_spf": True, "has_dmarc": True}
        mock_tranco.return_value = {"available": True, "rank": 5000}
        mock_otx.return_value = {"available": True, "pulse_count": 0, "validation": []}

        with patch("modules.verify._urlhaus_lookup", return_value={"urls_count": 0, "blacklisted": False}):
            v = CyrberVerify()
            result = v.verify_url("https://example.com")

        assert result["type"] == "url"
        assert result["risk_score"] == 0
        assert result["verdict"] == "BEZPIECZNE"
        assert "signals" in result
        assert "timestamp" in result
        assert "trust_factors" in result
        assert "signal_explanations" in result

    @patch("modules.verify._otx_lookup")
    @patch("modules.verify._tranco_lookup")
    @patch("modules.verify._check_spf_dmarc")
    @patch("modules.verify._crtsh_lookup")
    @patch("modules.verify._rdap_lookup")
    @patch("modules.verify._whois_lookup")
    @patch("modules.verify._google_safe_browsing")
    @patch("modules.verify._virustotal_url")
    @patch("modules.verify._wayback_first")
    @patch("modules.verify._resolve_domain_ip")
    def test_verify_url_suspicious(self, mock_ip, mock_wb, mock_vt, mock_gsb, mock_whois,
                                    mock_rdap, mock_crtsh, mock_spf, mock_tranco, mock_otx):
        mock_whois.return_value = {"age_days": 200, "domain": "shady.com", "available": False}
        mock_gsb.return_value = {"available": True, "flagged": False}
        mock_vt.return_value = {"available": True, "positives": 2, "total": 70}
        mock_wb.return_value = {"available": True, "archive_age_days": 100, "first_archive": "2025-10-01"}
        mock_ip.return_value = None
        mock_rdap.return_value = {"available": False}
        mock_crtsh.return_value = {"available": True, "cert_age_days": None}
        mock_spf.return_value = {"has_spf": False, "has_dmarc": False}
        mock_tranco.return_value = {"available": True, "rank": None}
        mock_otx.return_value = {"available": True, "pulse_count": 0, "validation": []}

        with patch("modules.verify._urlhaus_lookup", return_value={"urls_count": 0, "blacklisted": False}):
            v = CyrberVerify()
            result = v.verify_url("https://shady.com")

        # 20 (age<365) + 30 (vt>=2) + 25 (wb<180) + 15 (no spf+dmarc) + 10 (no tranco) = 100
        assert result["risk_score"] == 100
        assert result["verdict"] == "OSZUSTWO"


class TestVerifyEmail:

    @patch("modules.verify._check_spf_dmarc")
    @patch("modules.verify._whois_lookup")
    @patch("modules.verify._check_mx")
    @patch("modules.verify._load_disposable_domains")
    def test_verify_email_clean(self, mock_disp, mock_mx, mock_whois, mock_spf):
        mock_disp.return_value = set()
        mock_mx.return_value = {"has_mx": True, "records": [{"host": "mx.example.com", "priority": 10}]}
        mock_whois.return_value = {"age_days": 5000, "domain": "example.com", "available": False}
        mock_spf.return_value = {"has_spf": True, "has_dmarc": True}

        with patch("modules.verify._urlhaus_lookup", return_value={"urls_count": 0, "blacklisted": False}):
            v = CyrberVerify()
            result = v.verify_email("user@example.com")

        assert result["type"] == "email"
        assert result["risk_score"] == 0
        assert result["verdict"] == "BEZPIECZNE"

    @patch("modules.verify._check_spf_dmarc")
    @patch("modules.verify._whois_lookup")
    @patch("modules.verify._check_mx")
    @patch("modules.verify._load_disposable_domains")
    def test_verify_email_disposable(self, mock_disp, mock_mx, mock_whois, mock_spf):
        mock_disp.return_value = {"tempmail.com", "guerrillamail.com"}
        mock_mx.return_value = {"has_mx": True, "records": []}
        mock_whois.return_value = {"age_days": 100, "domain": "tempmail.com", "available": False}
        mock_spf.return_value = {"has_spf": False, "has_dmarc": False}

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
        assert "trust_factors" in result
        assert "signal_explanations" in result


class TestVerifyCompany:

    @patch("modules.verify._biala_lista_lookup")
    @patch("modules.verify._krs_lookup")
    @patch("modules.verify._ceidg_lookup")
    def test_nip_found_biala_lista(self, mock_ceidg, mock_krs, mock_bl):
        """NIP → Biała Lista found first → BEZPIECZNE."""
        mock_bl.return_value = {
            "found": True, "registry": "Biała Lista VAT",
            "name": "FIRMA TESTOWA", "nip": "5272720862", "status_vat": "Czynny", "krs": "",
        }
        mock_krs.return_value = {"found": False, "registry": "KRS"}
        mock_ceidg.return_value = {"found": False, "registry": "CEIDG"}

        v = CyrberVerify()
        result = v.verify_company("5272720862", country="PL")

        assert result["type"] == "company"
        assert result["risk_score"] == 0
        assert result["signals"]["company"]["registry"] == "Biała Lista VAT"

    @patch("modules.verify._biala_lista_lookup")
    @patch("modules.verify._krs_lookup")
    @patch("modules.verify._ceidg_lookup")
    def test_nip_bl_miss_krs_found(self, mock_ceidg, mock_krs, mock_bl):
        """NIP → BL miss → KRS fallback found → BEZPIECZNE."""
        mock_bl.return_value = {"found": False, "registry": "Biała Lista VAT"}
        mock_krs.return_value = {
            "found": True, "registry": "KRS",
            "name": "Test Sp. z o.o.", "nip": "5272720862", "status": "active",
        }
        mock_ceidg.return_value = {"found": False, "registry": "CEIDG"}

        v = CyrberVerify()
        result = v.verify_company("5272720862", country="PL")

        assert result["risk_score"] == 0
        assert result["signals"]["company"]["registry"] == "KRS"

    @patch("modules.verify._biala_lista_lookup")
    @patch("modules.verify._krs_lookup")
    @patch("modules.verify._ceidg_lookup")
    def test_nip_not_found(self, mock_ceidg, mock_krs, mock_bl):
        """NIP not found in all 3 PL registries → +30, PODEJRZANE."""
        mock_bl.return_value = {"found": False, "registry": "Biała Lista VAT"}
        mock_krs.return_value = {"found": False, "registry": "KRS"}
        mock_ceidg.return_value = {"found": False, "registry": "CEIDG"}

        v = CyrberVerify()
        result = v.verify_company("9999999999", country="PL")

        assert result["risk_score"] == 30
        assert result["verdict"] == "PODEJRZANE"
        assert "Biała Lista VAT" in result["signals"]["company"]["registries_searched"]
        assert "KRS" in result["signals"]["company"]["registries_searched"]

    @patch("modules.verify._biala_lista_lookup")
    @patch("modules.verify._krs_lookup")
    def test_krs_number_found(self, mock_krs, mock_bl):
        """KRS number (0000XXXXXX) → KRS found, enriched with BL status_vat."""
        mock_krs.return_value = {
            "found": True, "registry": "KRS",
            "name": "FIRMA SP. Z O.O.", "krs": "0000537910", "nip": "6770065406", "status": "active",
        }
        mock_bl.return_value = {
            "found": True, "registry": "Biała Lista VAT",
            "status_vat": "Czynny", "account_numbers": ["PL111"],
        }

        v = CyrberVerify()
        result = v.verify_company("0000537910", country="PL")

        assert result["risk_score"] == 0
        assert result["signals"]["company"]["registry"] == "KRS"
        assert result["signals"]["company"]["status_vat"] == "Czynny"

    @patch("modules.verify._krs_lookup")
    def test_krs_number_not_found(self, mock_krs):
        """KRS number not found → PODEJRZANE."""
        mock_krs.return_value = {"found": False, "registry": "KRS"}

        v = CyrberVerify()
        result = v.verify_company("0000000001", country="PL")

        assert result["signals"]["company"]["query_type"] == "krs"
        assert result["risk_score"] == 20  # 1 registry

    @patch("modules.verify.COMPANIES_HOUSE_KEY", "test-key")
    @patch("modules.verify._companies_house_lookup")
    def test_name_search_not_found_limited(self, mock_ch):
        """Name search not found → name_search_limited, manual_check_urls."""
        mock_ch.return_value = {"found": False, "registry": "Companies House"}

        v = CyrberVerify()
        result = v.verify_company("Jakas Firma", country="AUTO")

        company = result["signals"]["company"]
        assert company["name_search_limited"] is True
        assert company["manual_check_urls"]
        assert any(u["name"] == "KRS" for u in company["manual_check_urls"])
        assert result["risk_score"] == 5
        assert result["verdict"] == "BEZPIECZNE"

    @patch("modules.verify.COMPANIES_HOUSE_KEY", "test-key")
    @patch("modules.verify._companies_house_lookup")
    def test_name_search_found_companies_house(self, mock_ch):
        """Name search → CH found → BEZPIECZNE."""
        mock_ch.return_value = {
            "found": True, "registry": "Companies House",
            "name": "ACME LTD", "company_number": "12345", "status": "active",
        }

        v = CyrberVerify()
        result = v.verify_company("ACME", country="AUTO")

        assert result["risk_score"] == 0
        assert result["signals"]["company"]["registry"] == "Companies House"

    @patch("modules.verify.COMPANIES_HOUSE_KEY", "test-key")
    @patch("modules.verify._companies_house_lookup")
    def test_name_search_ch_candidates(self, mock_ch):
        """Name search → CH candidates → name_search_limited + candidates propagated."""
        mock_ch.return_value = {
            "found": False, "registry": "Companies House",
            "candidates": [{"name": "SIMILAR LTD", "company_number": "99"}],
        }

        v = CyrberVerify()
        result = v.verify_company("Something", country="AUTO")

        company = result["signals"]["company"]
        assert company["name_search_limited"] is True
        assert company["candidates"]
        assert company["candidates"][0]["source"] == "Companies House"
        assert result["risk_score"] == 0  # 5 - 5

    def test_known_company_google(self):
        """Known company (Google) → BEZPIECZNE, score 0."""
        v = CyrberVerify()
        result = v.verify_company("Google", country="AUTO")

        assert result["risk_score"] == 0
        assert result["verdict"] == "BEZPIECZNE"
        assert result["signals"]["company"]["registry"] == "known_company"

    def test_known_company_emca(self):
        """Known company (EMCA Software) → BEZPIECZNE, score 0."""
        v = CyrberVerify()
        result = v.verify_company("EMCA Software", country="AUTO")

        assert result["risk_score"] == 0
        assert result["verdict"] == "BEZPIECZNE"


# ═══════════════════════════════════════════════════════════════
#  Registry lookup unit tests
# ═══════════════════════════════════════════════════════════════


class TestKrsLookup:

    @patch("modules.verify.requests.get")
    def test_krs_nip_lookup(self, mock_get):
        """NIP (10 digits) → OdpisAktualny endpoint."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "odpis": {"dane": {
                "nazwa": "EMCA SOFTWARE SP. Z O.O.",
                "numerKRS": "0000123456",
                "nip": "5272720862",
                "regon": "123456789",
                "adres": "Warszawa",
                "dataRejestracjiWKRS": "2010-01-15",
            }}
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = _krs_lookup("5272720862")

        assert result["found"] is True
        assert result["registry"] == "KRS"
        assert result["nip"] == "5272720862"
        assert "OdpisAktualny" in mock_get.call_args[0][0]

    def test_krs_name_returns_not_a_number(self):
        """Name string → not_a_number, no HTTP call."""
        result = _krs_lookup("EMCA Software")
        assert result["found"] is False
        assert result.get("reason") == "not_a_number"

    @patch("modules.verify.requests.get")
    def test_krs_404(self, mock_get):
        """NIP not in KRS → found=False."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = _krs_lookup("9999999999")
        assert result["found"] is False


class TestCeidgLookup:

    @patch("modules.verify.requests.get")
    def test_ceidg_nip_lookup(self, mock_get):
        """NIP → firmy?nip= endpoint."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "firmy": [
                {"nazwa": "JAN KOWALSKI USŁUGI IT", "wlasciciel": {"nip": "1234567890"}, "status": "AKTYWNY", "dataRozpoczeciaDzialalnosci": "2015-03-01"},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = _ceidg_lookup("1234567890")

        assert result["found"] is True
        assert result["registry"] == "CEIDG"
        call_url = mock_get.call_args[0][0]
        assert "/firmy?" in call_url
        assert "nip=1234567890" in call_url

    def test_ceidg_name_returns_not_a_number(self):
        """Name string → not_a_number, no HTTP call."""
        result = _ceidg_lookup("EMCA Software")
        assert result["found"] is False
        assert result.get("reason") == "not_a_number"

    @patch("modules.verify.CEIDG_AUTH_KEY", "test-key-123")
    @patch("modules.verify.requests.get")
    def test_ceidg_auth_header(self, mock_get):
        """CEIDG_AUTH_KEY is sent as Bearer token."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"firmy": []}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        _ceidg_lookup("1234567890")

        headers = mock_get.call_args[1].get("headers", {})
        assert headers.get("Authorization") == "Bearer test-key-123"


class TestCompaniesHouseLookup:

    @patch("modules.verify.COMPANIES_HOUSE_KEY", "test-key")
    @patch("modules.verify.requests.get")
    def test_ch_candidates(self, mock_get):
        """CH returns results but no exact match → candidates."""
        from modules.verify import _companies_house_lookup
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "items": [
                {"title": "ACME CORP LTD", "company_number": "12345678", "company_status": "active"},
                {"title": "ACME TRADING LTD", "company_number": "87654321", "company_status": "active"},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = _companies_house_lookup("EMCA Software")

        assert result["found"] is False
        assert len(result["candidates"]) == 2
        assert result["candidates"][0]["name"] == "ACME CORP LTD"

    @patch("modules.verify.COMPANIES_HOUSE_KEY", "test-key")
    @patch("modules.verify.requests.get")
    def test_ch_exact_match(self, mock_get):
        """CH returns exact match → found=True."""
        from modules.verify import _companies_house_lookup
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "items": [
                {"title": "EMCA SOFTWARE LTD", "company_number": "99999", "company_status": "active", "address_snippet": "London"},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = _companies_house_lookup("EMCA Software")

        assert result["found"] is True
        assert result["name"] == "EMCA SOFTWARE LTD"


class TestBialaListaLookup:

    @patch("modules.verify.requests.get")
    def test_bl_nip_found(self, mock_get):
        """NIP → Biała Lista found."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "result": {
                "subject": {
                    "name": "EMCA SOFTWARE SP. Z O.O.",
                    "nip": "5272907526",
                    "regon": "123456789",
                    "statusVat": "Czynny",
                    "krs": "0000654321",
                    "residenceAddress": "ul. Testowa 1, 00-001 Warszawa",
                    "accountNumbers": ["PL12345678901234567890123456"],
                }
            }
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = _biala_lista_lookup("5272907526")

        assert result["found"] is True
        assert result["registry"] == "Biała Lista VAT"
        assert result["nip"] == "5272907526"
        assert result["status_vat"] == "Czynny"

    def test_bl_name_not_supported(self):
        """Name search → not supported, returns immediately without HTTP call."""
        result = _biala_lista_lookup("EMCA Software")

        assert result["found"] is False
        assert result["registry"] == "Biała Lista VAT"
        assert result["reason"] == "name_search_not_supported"

    @patch("modules.verify.requests.get")
    def test_bl_regon_found(self, mock_get):
        """REGON (9 digits) → found."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "result": {
                "subject": {
                    "name": "FIRMA REGON SP. Z O.O.",
                    "nip": "1234567890",
                    "regon": "123456789",
                    "statusVat": "Czynny",
                    "krs": "",
                    "residenceAddress": "ul. Testowa 5, 00-002 Kraków",
                    "accountNumbers": [],
                }
            }
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = _biala_lista_lookup("123456789")

        assert result["found"] is True
        assert result["registry"] == "Biała Lista VAT"
        assert result["regon"] == "123456789"
        call_url = mock_get.call_args[0][0]
        assert "/regon/" in call_url

    @patch("modules.verify.requests.get")
    def test_bl_not_found(self, mock_get):
        """404 → not found."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = _biala_lista_lookup("9999999999")

        assert result["found"] is False

    @patch("modules.verify.requests.get")
    def test_bl_error_graceful(self, mock_get):
        """Network error → graceful failure."""
        mock_get.side_effect = Exception("timeout")
        result = _biala_lista_lookup("1234567890")  # NIP to reach HTTP call
        assert result["found"] is False
        assert "error" in result


class TestOpenCorporatesLookup:

    @patch("modules.verify.OPENCORPORATES_KEY", "test-key")
    @patch("modules.verify.requests.get")
    def test_oc_found(self, mock_get):
        """Exact match → found=True."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": {"companies": [
                {"company": {"name": "EMCA SOFTWARE SP. Z O.O.", "company_number": "KRS001", "jurisdiction_code": "pl", "current_status": "Active"}},
            ]}
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = _opencorporates_lookup("EMCA Software")
        assert result["found"] is True
        assert result["jurisdiction"] == "pl"

    def test_oc_no_key(self):
        """No API key → skip."""
        result = _opencorporates_lookup("test")
        assert result["found"] is False
        assert result.get("reason") == "no_api_key"


class TestCalculateRiskCandidates:

    def test_nip_candidates_reduce_penalty(self):
        """NIP search: candidates reduce penalty by 5."""
        signals = {
            "company": {
                "found": False,
                "registries_searched": ["KRS", "CEIDG", "Biała Lista VAT"],
                "candidates": [{"name": "Similar Corp"}],
            }
        }
        score = calculate_risk(signals)
        # 30 (3 registries) - 5 (candidates) = 25
        assert score == 25

    def test_nip_no_candidates_full_penalty(self):
        """NIP search: no candidates → full penalty."""
        signals = {
            "company": {
                "found": False,
                "registries_searched": ["KRS", "CEIDG", "Biała Lista VAT"],
            }
        }
        score = calculate_risk(signals)
        assert score == 30

    def test_name_search_limited_low_penalty(self):
        """Name search limited → +5 only."""
        signals = {
            "company": {
                "found": False,
                "name_search_limited": True,
                "registries_searched": ["Companies House"],
            }
        }
        score = calculate_risk(signals)
        assert score == 5

    def test_name_search_limited_candidates_zero(self):
        """Name search limited + candidates → 5-5=0."""
        signals = {
            "company": {
                "found": False,
                "name_search_limited": True,
                "registries_searched": ["Companies House"],
                "candidates": [{"name": "X"}],
            }
        }
        score = calculate_risk(signals)
        assert score == 0


class TestExtractProblemsCandidates:

    def test_problems_nip_with_candidates(self):
        """NIP search: candidates → 'podobne wyniki' message."""
        signals = {
            "company": {
                "found": False,
                "registries_searched": ["KRS", "CEIDG"],
                "candidates": [{"name": "EMCA SP. Z O.O."}],
            }
        }
        problems = _extract_problems(signals)
        company_problems = [p for p in problems if "Firma" in p["title"] or "podobne" in p["title"]]
        assert len(company_problems) == 1
        assert "podobne" in company_problems[0]["title"]

    def test_problems_nip_without_candidates(self):
        """NIP search: no candidates → standard not-found."""
        signals = {
            "company": {
                "found": False,
                "registries_searched": ["KRS"],
            }
        }
        problems = _extract_problems(signals)
        company_problems = [p for p in problems if "Firma" in p["title"] or "nie znalezion" in p.get("title", "").lower()]
        assert len(company_problems) == 1
        assert "nie znaleziona" in company_problems[0]["title"].lower()

    def test_problems_name_search_limited(self):
        """Name search limited → mentions NIP hint and manual check links."""
        signals = {
            "company": {
                "found": False,
                "name_search_limited": True,
                "registries_searched": [],
                "manual_check_urls": [
                    {"name": "KRS", "url": "https://wyszukiwarka-krs.ms.gov.pl/"},
                    {"name": "CEIDG", "url": "https://www.biznes.gov.pl/pl/wyszukiwarka-ceidg"},
                ],
            }
        }
        problems = _extract_problems(signals)
        company_problems = [p for p in problems if "zweryfikować" in p.get("title", "").lower() or "nazwie" in p.get("title", "").lower()]
        assert len(company_problems) == 1
        assert "NIP" in company_problems[0]["what_means"]
        assert "KRS" in company_problems[0]["real_risk"]

    def test_problems_name_search_limited_with_candidates(self):
        """Name search limited + candidates → mentions candidates and manual links."""
        signals = {
            "company": {
                "found": False,
                "name_search_limited": True,
                "registries_searched": ["Companies House"],
                "candidates": [{"name": "SIMILAR FIRMA"}],
                "manual_check_urls": [
                    {"name": "KRS", "url": "https://wyszukiwarka-krs.ms.gov.pl/"},
                ],
            }
        }
        problems = _extract_problems(signals)
        company_problems = [p for p in problems if "zweryfikować" in p.get("title", "").lower()]
        assert len(company_problems) == 1
        assert "SIMILAR FIRMA" in company_problems[0]["what_found"]


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
        assert "trust_factors" in result
        assert "signal_explanations" in result
        assert "educational_tips" in result

    def test_verdict_fraud_fallback(self):
        from modules.verify import generate_verdict
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(80, {"urlhaus": {"blacklisted": True}}, "evil.com")
        assert result["verdict"] == "OSZUSTWO"
        assert len(result["red_flags"]) > 0

    def test_verdict_thresholds(self):
        """New thresholds: <20 BEZPIECZNE, 20-50 PODEJRZANE, >50 OSZUSTWO."""
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            assert generate_verdict(0, {}, "t")["verdict"] == "BEZPIECZNE"
            assert generate_verdict(19, {}, "t")["verdict"] == "BEZPIECZNE"
            assert generate_verdict(20, {}, "t")["verdict"] == "PODEJRZANE"
            assert generate_verdict(50, {}, "t")["verdict"] == "PODEJRZANE"
            assert generate_verdict(51, {}, "t")["verdict"] == "OSZUSTWO"
            assert generate_verdict(100, {}, "t")["verdict"] == "OSZUSTWO"

    def test_verdict_has_narrative(self):
        """generate_verdict returns narrative string."""
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(60, {"urlhaus": {"blacklisted": True}}, "evil.com")
        assert "narrative" in result
        assert isinstance(result["narrative"], str)
        assert len(result["narrative"]) > 20

    def test_verdict_has_problems_positives(self):
        """generate_verdict returns problems and positives as list[dict] with v3 fields."""
        signals = {
            "urlhaus": {"blacklisted": True},
            "whois": {"age_days": 5000, "available": False},
        }
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(30, signals, "test.com")
        assert isinstance(result["problems"], list)
        assert isinstance(result["positives"], list)
        # With blacklisted urlhaus there should be at least 1 problem
        assert len(result["problems"]) >= 1
        p = result["problems"][0]
        assert "title" in p
        assert "what_found" in p
        assert "what_means" in p
        assert "real_risk" in p
        # With age 5000 days there should be at least 1 positive
        assert len(result["positives"]) >= 1
        pos = result["positives"][0]
        assert "title" in pos
        assert "what_found" in pos
        assert "what_means" in pos

    def test_verdict_has_action(self):
        """generate_verdict returns action string."""
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(10, {}, "safe.com")
        assert "action" in result
        assert isinstance(result["action"], str)
        assert len(result["action"]) > 10

    def test_educational_tips_dict_format(self):
        """educational_tips are list[dict] with icon/title/text/example."""
        signals = {"whois": {"age_days": 100}, "virustotal": {"available": True, "positives": 0, "total": 70}}
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(20, signals, "test.com")
        tips = result["educational_tips"]
        assert isinstance(tips, list)
        assert len(tips) >= 3
        for tip in tips:
            assert isinstance(tip, dict)
            assert "icon" in tip
            assert "title" in tip
            assert "text" in tip
            assert "example" in tip

    def test_verdict_has_immediate_actions(self):
        """generate_verdict returns immediate_actions list."""
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(80, {"urlhaus": {"blacklisted": True}}, "evil.com")
        assert "immediate_actions" in result
        assert isinstance(result["immediate_actions"], list)
        assert len(result["immediate_actions"]) >= 3

    def test_verdict_has_if_paid_already(self):
        """generate_verdict returns if_paid_already for fraud."""
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(80, {}, "evil.com")
        assert "if_paid_already" in result
        assert isinstance(result["if_paid_already"], list)
        assert len(result["if_paid_already"]) >= 3

    def test_verdict_safe_no_if_paid(self):
        """BEZPIECZNE verdict has empty if_paid_already."""
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(5, {}, "safe.com")
        assert result["if_paid_already"] == []

    def test_verdict_has_report_to(self):
        """OSZUSTWO verdict has report_to with institutions."""
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(80, {}, "evil.com")
        assert "report_to" in result
        assert isinstance(result["report_to"], list)
        assert len(result["report_to"]) >= 3
        inst = result["report_to"][0]
        assert "institution" in inst
        assert "url" in inst
        assert "description" in inst

    def test_verdict_safe_no_report_to(self):
        """BEZPIECZNE verdict has empty report_to."""
        with patch("modules.llm_provider.ClaudeProvider", side_effect=ImportError):
            result = generate_verdict(5, {}, "safe.com")
        assert result["report_to"] == []


# ═══════════════════════════════════════════════════════════════
#  Bug fix tests
# ═══════════════════════════════════════════════════════════════


class TestWhoisDatetimeBug:
    """Bug #1: offset-naive vs offset-aware datetime comparison."""

    def test_timezone_aware_creation_date(self):
        """WHOIS with timezone-aware creation_date should not crash."""
        from datetime import timezone, timedelta
        import sys

        aware_dt = datetime(2020, 1, 1, tzinfo=timezone.utc)
        mock_whois_result = MagicMock()
        mock_whois_result.creation_date = aware_dt
        mock_whois_result.expiration_date = None
        mock_whois_result.registrar = "Test"
        mock_whois_result.org = ""
        mock_whois_result.country = "PL"

        mock_whois_mod = MagicMock()
        mock_whois_mod.whois.return_value = mock_whois_result

        with patch.dict(sys.modules, {"whois": mock_whois_mod}):
            result = _whois_lookup("example.com")
        assert result["age_days"] is not None
        assert result["age_days"] > 0

    def test_timezone_naive_creation_date(self):
        """WHOIS with timezone-naive creation_date still works."""
        import sys

        naive_dt = datetime(2020, 6, 15)
        mock_whois_result = MagicMock()
        mock_whois_result.creation_date = naive_dt
        mock_whois_result.expiration_date = None
        mock_whois_result.registrar = "Test"
        mock_whois_result.org = ""
        mock_whois_result.country = ""

        mock_whois_mod = MagicMock()
        mock_whois_mod.whois.return_value = mock_whois_result

        with patch.dict(sys.modules, {"whois": mock_whois_mod}):
            result = _whois_lookup("example.com")
        assert result["age_days"] is not None
        assert result["age_days"] > 0

    def test_timezone_aware_with_offset(self):
        """WHOIS with non-UTC timezone offset should not crash."""
        from datetime import timezone, timedelta
        import sys

        offset_dt = datetime(2019, 3, 10, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        mock_whois_result = MagicMock()
        mock_whois_result.creation_date = offset_dt
        mock_whois_result.expiration_date = None
        mock_whois_result.registrar = ""
        mock_whois_result.org = ""
        mock_whois_result.country = ""

        mock_whois_mod = MagicMock()
        mock_whois_mod.whois.return_value = mock_whois_result

        with patch.dict(sys.modules, {"whois": mock_whois_mod}):
            result = _whois_lookup("example.com")
        assert result["age_days"] is not None


class TestUrlhausEmailBug:
    """Bug #2: URLhaus 401 for email addresses."""

    def test_urlhaus_strips_email(self):
        """_urlhaus_lookup with email should extract domain — not send full email."""
        # _urlhaus_lookup imports sync_urlhaus inside the function
        mock_sync = MagicMock(return_value={"urls_count": 0, "blacklisted": False})
        mock_intel_mod = MagicMock()
        mock_intel_mod.sync_urlhaus = mock_sync

        import sys
        with patch.dict(sys.modules, {"modules.intelligence_sync": mock_intel_mod}):
            result = _urlhaus_lookup("user@example.com")
        mock_sync.assert_called_once_with("example.com")
        assert result["blacklisted"] is False

    def test_urlhaus_plain_domain(self):
        """_urlhaus_lookup with plain domain works as before."""
        mock_sync = MagicMock(return_value={"urls_count": 0, "blacklisted": False})
        mock_intel_mod = MagicMock()
        mock_intel_mod.sync_urlhaus = mock_sync

        import sys
        with patch.dict(sys.modules, {"modules.intelligence_sync": mock_intel_mod}):
            result = _urlhaus_lookup("example.com")
        mock_sync.assert_called_once_with("example.com")


class TestJsonRepairBug:
    """Bug #3: AI verdict JSON parse error — repair logic."""

    def test_trailing_comma_repair(self):
        """JSON with trailing commas should be repaired."""
        mock_provider = MagicMock()
        mock_provider.chat.return_value = '{"verdict": "BEZPIECZNE", "summary": "Ok", "red_flags": [],}'

        with patch("modules.llm_provider.ClaudeProvider", return_value=mock_provider):
            result = generate_verdict(10, {}, "test.com")
        assert result["verdict"] == "BEZPIECZNE"

    def test_json_with_prefix_text(self):
        """JSON embedded in surrounding text should be extracted."""
        mock_provider = MagicMock()
        mock_provider.chat.return_value = 'Here is the result:\n{"verdict": "OSZUSTWO", "summary": "Bad"}\nDone.'

        with patch("modules.llm_provider.ClaudeProvider", return_value=mock_provider):
            result = generate_verdict(80, {}, "evil.com")
        assert result["verdict"] == "OSZUSTWO"

    def test_signals_truncation(self):
        """Signals JSON longer than 2000 chars should be truncated in prompt."""
        big_signals = {"key_" + str(i): "x" * 100 for i in range(30)}
        mock_provider = MagicMock()
        mock_provider.chat.return_value = '{"verdict": "PODEJRZANE", "summary": "Test"}'

        with patch("modules.llm_provider.ClaudeProvider", return_value=mock_provider):
            result = generate_verdict(30, big_signals, "test.com")
        # Should not crash, should return valid result
        assert result["verdict"] == "PODEJRZANE"


class TestSafeEmailDomains:
    """Additional fix: safe email domain whitelist."""

    def test_safe_domains_constant(self):
        """SAFE_EMAIL_DOMAINS contains expected providers."""
        assert "gmail.com" in SAFE_EMAIL_DOMAINS
        assert "wp.pl" in SAFE_EMAIL_DOMAINS
        assert "proton.me" in SAFE_EMAIL_DOMAINS
        assert "onet.pl" in SAFE_EMAIL_DOMAINS

    def test_calculate_risk_safe_domain_cap(self):
        """Safe email domain caps risk score at 15."""
        signals = {
            "whois": {"age_days": 100, "domain": "gmail.com", "available": False},
            "spf_dmarc": {"has_spf": False, "has_dmarc": False},
        }
        score = calculate_risk(signals)
        assert score <= 15

    @patch("modules.verify._check_spf_dmarc")
    @patch("modules.verify._whois_lookup")
    @patch("modules.verify._check_mx")
    @patch("modules.verify._load_disposable_domains")
    def test_verify_email_gmail_safe(self, mock_disp, mock_mx, mock_whois, mock_spf):
        """Verifying test@gmail.com should return BEZPIECZNE with score ≤ 15."""
        mock_disp.return_value = set()
        mock_mx.return_value = {"has_mx": True, "records": [{"host": "mx.google.com", "priority": 5}]}
        mock_whois.return_value = {"age_days": 8000, "domain": "gmail.com", "available": False}
        mock_spf.return_value = {"has_spf": True, "has_dmarc": True}

        with patch("modules.verify._urlhaus_lookup", return_value={"urls_count": 0, "blacklisted": False}):
            v = CyrberVerify()
            result = v.verify_email("test@gmail.com")

        assert result["risk_score"] <= 15
        assert result["verdict"] == "BEZPIECZNE"
        assert "Znany bezpieczny dostawca poczty" in result.get("trust_factors", [])

    @patch("modules.verify._check_spf_dmarc")
    @patch("modules.verify._whois_lookup")
    @patch("modules.verify._check_mx")
    @patch("modules.verify._load_disposable_domains")
    def test_verify_email_unknown_domain_not_safe(self, mock_disp, mock_mx, mock_whois, mock_spf):
        """Unknown domain should NOT get safe email treatment."""
        mock_disp.return_value = set()
        mock_mx.return_value = {"has_mx": False, "records": []}
        mock_whois.return_value = {"age_days": 30, "domain": "shadymail.xyz", "available": False}
        mock_spf.return_value = {"has_spf": False, "has_dmarc": False}

        with patch("modules.verify._urlhaus_lookup", return_value={"urls_count": 0, "blacklisted": False}):
            v = CyrberVerify()
            result = v.verify_email("user@shadymail.xyz")

        assert result["risk_score"] > 15
        assert result["verdict"] != "BEZPIECZNE"
