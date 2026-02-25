"""Tests for security gate logic."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

# Import the gate function from ci-scan
# Since the filename has a hyphen, use importlib
import importlib.util
spec = importlib.util.spec_from_file_location(
    "ci_scan",
    os.path.join(os.path.dirname(__file__), "..", "scripts", "ci-scan.py"),
)
ci_scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci_scan)

apply_security_gate = ci_scan.apply_security_gate


def test_gate_pass_zero_findings():
    """No findings should always pass."""
    results = {"severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
    assert apply_security_gate(results, max_critical=0, max_high=5) is True


def test_gate_fail_critical():
    """1 critical with threshold 0 should fail."""
    results = {"severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}}
    assert apply_security_gate(results, max_critical=0, max_high=5) is False


def test_gate_pass_critical_within_threshold():
    """1 critical with threshold 1 should pass."""
    results = {"severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}}
    assert apply_security_gate(results, max_critical=1, max_high=5) is True


def test_gate_pass_high_at_threshold():
    """2 high with threshold 2 should pass."""
    results = {"severity_counts": {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0}}
    assert apply_security_gate(results, max_critical=0, max_high=2) is True


def test_gate_fail_high_over_threshold():
    """3 high with threshold 2 should fail."""
    results = {"severity_counts": {"critical": 0, "high": 3, "medium": 0, "low": 0, "info": 0}}
    assert apply_security_gate(results, max_critical=0, max_high=2) is False


def test_gate_ignores_medium_low():
    """Medium/low/info should not trigger gate failure."""
    results = {"severity_counts": {"critical": 0, "high": 0, "medium": 100, "low": 200, "info": 500}}
    assert apply_security_gate(results, max_critical=0, max_high=0) is True


def test_gate_fallback_count():
    """When severity_counts is missing, should compute from raw findings."""
    results = {
        "nuclei": {"findings": [
            {"info": {"severity": "critical"}},
            {"info": {"severity": "high"}},
        ]},
        "zap": {"alerts": [
            {"risk": "High"},
        ]},
    }
    # max_critical=0 → 1 critical found → fail
    assert apply_security_gate(results, max_critical=0, max_high=5) is False


def test_gate_both_thresholds():
    """Both critical and high should be checked independently."""
    results = {"severity_counts": {"critical": 1, "high": 10, "medium": 0, "low": 0, "info": 0}}
    # critical=1 > 0 → fail (even though high would pass)
    assert apply_security_gate(results, max_critical=0, max_high=20) is False
