"""Tests for CI scan profile."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.scan_profiles import (
    get_all_modules, get_profile, get_profiles_list, should_run_module, PROFILES
)


def test_ci_profile_exists():
    assert "CI" in PROFILES
    assert get_profile("CI") is not None
    assert get_profile("ci") is not None


def test_ci_modules():
    expected = {"nmap", "nuclei", "whatweb", "gobuster", "testssl", "zap"}
    assert get_all_modules("CI") == expected


def test_ci_should_run_included():
    assert should_run_module("nuclei", "CI") is True
    assert should_run_module("nmap", "CI") is True
    assert should_run_module("zap", "CI") is True
    assert should_run_module("testssl", "CI") is True
    assert should_run_module("whatweb", "CI") is True
    assert should_run_module("gobuster", "CI") is True


def test_ci_should_not_run_excluded():
    assert should_run_module("bloodhound", "CI") is False
    assert should_run_module("sqlmap", "CI") is False
    assert should_run_module("nikto", "CI") is False
    assert should_run_module("amass", "CI") is False
    assert should_run_module("impacket", "CI") is False


def test_ci_not_in_profiles_list():
    """CI should not appear in the tier-based profiles list (automation-only)."""
    profiles = get_profiles_list()
    keys = [p["key"] for p in profiles]
    assert "CI" not in keys


def test_ci_standalone_no_hierarchy_modules():
    """CI should NOT include SZCZENIAK/STRAZNIK modules via hierarchy."""
    ci_mods = get_all_modules("CI")
    # sqlmap is in SZCZENIAK but NOT in CI
    assert "sqlmap" not in ci_mods
    # wpscan is in STRAZNIK but NOT in CI
    assert "wpscan" not in ci_mods


def test_hierarchy_profiles_unchanged():
    """Adding CI should not break existing hierarchy profiles."""
    szczeniak = get_all_modules("SZCZENIAK")
    assert "nmap" in szczeniak
    assert "sqlmap" in szczeniak

    straznik = get_all_modules("STRAZNIK")
    assert "zap" in straznik
    assert "nmap" in straznik  # inherited from SZCZENIAK

    cerber = get_all_modules("CERBER")
    assert "bloodhound" in cerber
    assert "nmap" in cerber  # inherited
