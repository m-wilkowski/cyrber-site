"""Tests for SARIF converter."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from sarif_convert import convert_to_sarif, _extract_findings


def test_empty_results():
    """Empty scan results should produce valid SARIF with 0 results."""
    sarif = convert_to_sarif({})
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "CYRBER"
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_nuclei_findings():
    results = {
        "target": "http://example.com",
        "nuclei": {
            "findings": [
                {
                    "info": {
                        "name": "XSS Reflected",
                        "severity": "high",
                        "description": "Reflected XSS found",
                        "classification": {
                            "cve-id": ["CVE-2024-1234"],
                            "cwe-id": ["CWE-79"],
                        },
                    },
                    "matched-at": "http://example.com/search",
                },
                {
                    "info": {
                        "name": "Info Disclosure",
                        "severity": "info",
                        "description": "Server version exposed",
                        "classification": {},
                    },
                    "host": "http://example.com",
                },
            ]
        },
    }
    sarif = convert_to_sarif(results)
    assert len(sarif["runs"][0]["results"]) == 2

    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2

    # Check severity mapping
    high_result = sarif["runs"][0]["results"][0]
    assert high_result["level"] == "error"

    info_result = sarif["runs"][0]["results"][1]
    assert info_result["level"] == "note"


def test_zap_alerts():
    results = {
        "zap": {
            "alerts": [
                {"name": "SQL Injection", "risk": "High", "description": "SQLi found", "cweid": "89"},
                {"name": "Cookie No HttpOnly", "risk": "Low", "description": "Missing flag", "cweid": "1004"},
            ]
        },
    }
    sarif = convert_to_sarif(results)
    assert len(sarif["runs"][0]["results"]) == 2


def test_testssl_findings():
    results = {
        "target": "https://example.com",
        "testssl": {
            "findings": [
                {"id": "BEAST", "severity": "medium", "finding": "BEAST vulnerable", "cve": "CVE-2011-3389"},
                {"id": "RC4", "severity": "high", "finding": "RC4 cipher found"},
            ]
        },
    }
    sarif = convert_to_sarif(results)
    assert len(sarif["runs"][0]["results"]) == 2


def test_cwe_tags():
    results = {
        "nuclei": {
            "findings": [{
                "info": {
                    "name": "SQLi",
                    "severity": "critical",
                    "description": "SQL Injection",
                    "classification": {"cwe-id": ["CWE-89"]},
                },
            }]
        },
    }
    sarif = convert_to_sarif(results)
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    tags = rule["properties"]["tags"]
    assert "external/cwe/CWE-89" in tags


def test_sqlmap_vulnerable():
    results = {
        "target": "http://example.com",
        "sqlmap": {"vulnerable": True, "injection_type": "UNION", "target": "http://example.com/id=1"},
    }
    sarif = convert_to_sarif(results)
    assert len(sarif["runs"][0]["results"]) == 1
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "external/cwe/CWE-89" in rule["properties"]["tags"]
    assert rule["defaultConfiguration"]["level"] == "error"


def test_mixed_modules():
    """Multiple modules combined should produce correct total."""
    results = {
        "target": "http://example.com",
        "nuclei": {"findings": [
            {"info": {"name": "A", "severity": "high", "description": "a", "classification": {}}},
        ]},
        "zap": {"alerts": [
            {"name": "B", "risk": "Medium", "description": "b", "cweid": "79"},
        ]},
        "testssl": {"findings": [
            {"id": "C", "severity": "low", "finding": "c"},
        ]},
    }
    sarif = convert_to_sarif(results)
    assert len(sarif["runs"][0]["results"]) == 3


def test_security_severity_score():
    results = {
        "nuclei": {"findings": [
            {"info": {"name": "Critical Bug", "severity": "critical", "description": "x", "classification": {}}},
        ]},
    }
    sarif = convert_to_sarif(results)
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert float(rule["properties"]["security-severity"]) == 9.5
