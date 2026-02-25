"""Tests for Shodan InternetDB, URLhaus, and GreyNoise intelligence sources."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch, MagicMock

# Mock modules.database before importing intelligence_sync
_db_mock = MagicMock()
_original_db = sys.modules.get("modules.database")
if _original_db is None:
    sys.modules["modules.database"] = _db_mock

import modules.intelligence_sync as intel

if _original_db is not None:
    sys.modules["modules.database"] = _original_db


# ── Shodan InternetDB ─────────────────────────────────────

class TestShodanSync:

    def test_sync_shodan_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "ip": "8.8.8.8",
            "ports": [53, 443],
            "cpes": ["cpe:/a:google:dns"],
            "hostnames": ["dns.google"],
            "tags": ["cloud"],
            "vulns": ["CVE-2021-44228"],
        }

        with patch("modules.intelligence_sync.requests.get", return_value=mock_resp), \
             patch.object(intel, "upsert_shodan_cache") as mock_upsert:
            result = intel.sync_shodan("8.8.8.8")
            assert result is not None
            assert result["ports"] == [53, 443]
            assert result["vulns"] == ["CVE-2021-44228"]
            assert result["hostnames"] == ["dns.google"]
            mock_upsert.assert_called_once()

    def test_sync_shodan_404_empty(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("modules.intelligence_sync.requests.get", return_value=mock_resp), \
             patch.object(intel, "upsert_shodan_cache") as mock_upsert:
            result = intel.sync_shodan("10.0.0.1")
            assert result is not None
            assert result["ports"] == []
            assert result["vulns"] == []
            mock_upsert.assert_called_once()

    def test_sync_shodan_network_error(self):
        with patch("modules.intelligence_sync.requests.get", side_effect=Exception("timeout")):
            result = intel.sync_shodan("8.8.8.8")
            assert result is None

    def test_cache_hit_skips_fetch(self):
        cached = {"ip": "8.8.8.8", "ports": [53], "cpes": [], "hostnames": [],
                  "tags": [], "vulns": [], "fetched_at": "2026-02-25"}

        with patch.object(intel, "get_shodan_cache", return_value=cached):
            result = intel.enrich_target("8.8.8.8")
            assert result.get("shodan") == cached


# ── URLhaus ────────────────────────────────────────────────

class TestUrlhausSync:

    def test_sync_urlhaus_found(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "query_status": "ok",
            "urls_online": 3,
            "blacklists": {"surbl": "listed", "spamhaus_dbl": ""},
            "urls": [
                {"url": "http://evil.com/mal.exe", "url_status": "online",
                 "threat": "malware_download", "tags": ["elf", "mozi"], "date_added": "2026-01-01"},
                {"url": "http://evil.com/c2", "url_status": "offline",
                 "threat": "malware_download", "tags": ["mirai"], "date_added": "2026-01-02"},
            ],
        }

        with patch("modules.intelligence_sync.requests.post", return_value=mock_resp), \
             patch.object(intel, "upsert_urlhaus_cache") as mock_upsert:
            result = intel.sync_urlhaus("evil.com")
            assert result is not None
            assert result["urls_count"] == 3
            assert result["blacklisted"] is True
            assert "elf" in result["tags"] or "mozi" in result["tags"]
            mock_upsert.assert_called_once()

    def test_sync_urlhaus_no_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"query_status": "no_results"}

        with patch("modules.intelligence_sync.requests.post", return_value=mock_resp), \
             patch.object(intel, "upsert_urlhaus_cache") as mock_upsert:
            result = intel.sync_urlhaus("clean-site.com")
            assert result is not None
            assert result["urls_count"] == 0
            assert result["blacklisted"] is False
            mock_upsert.assert_called_once()

    def test_sync_urlhaus_network_error(self):
        with patch("modules.intelligence_sync.requests.post", side_effect=Exception("connection error")):
            result = intel.sync_urlhaus("example.com")
            assert result is None

    def test_batch_sync(self):
        with patch.object(intel, "sync_urlhaus", return_value={"urls_count": 0}) as mock_sync, \
             patch.object(intel, "save_intel_sync_log"):
            result = intel.sync_urlhaus_batch(["a.com", "b.com", "c.com"])
            assert result["synced"] == 3
            assert result["errors"] == 0
            assert mock_sync.call_count == 3


# ── GreyNoise Community ───────────────────────────────────

class TestGreynoiseSync:

    def test_sync_greynoise_malicious(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "ip": "1.2.3.4",
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "name": "Scanner",
            "link": "https://viz.greynoise.io/ip/1.2.3.4",
        }

        with patch("modules.intelligence_sync.requests.get", return_value=mock_resp), \
             patch.object(intel, "upsert_greynoise_cache") as mock_upsert:
            result = intel.sync_greynoise("1.2.3.4")
            assert result is not None
            assert result["noise"] is True
            assert result["classification"] == "malicious"
            assert result["link"] == "https://viz.greynoise.io/ip/1.2.3.4"
            mock_upsert.assert_called_once()

    def test_sync_greynoise_benign_riot(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "ip": "8.8.8.8",
            "noise": False,
            "riot": True,
            "classification": "benign",
            "name": "Google DNS",
            "link": "https://viz.greynoise.io/ip/8.8.8.8",
        }

        with patch("modules.intelligence_sync.requests.get", return_value=mock_resp), \
             patch.object(intel, "upsert_greynoise_cache"):
            result = intel.sync_greynoise("8.8.8.8")
            assert result["riot"] is True
            assert result["classification"] == "benign"

    def test_sync_greynoise_404_unknown(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("modules.intelligence_sync.requests.get", return_value=mock_resp), \
             patch.object(intel, "upsert_greynoise_cache") as mock_upsert:
            result = intel.sync_greynoise("192.168.1.1")
            assert result is not None
            assert result["classification"] == "unknown"
            mock_upsert.assert_called_once()

    def test_sync_greynoise_network_error(self):
        with patch("modules.intelligence_sync.requests.get", side_effect=Exception("timeout")):
            result = intel.sync_greynoise("8.8.8.8")
            assert result is None


# ── enrich_target ──────────────────────────────────────────

class TestEnrichTarget:

    def test_enrich_ip_all_sources(self):
        shodan_data = {"ip": "1.2.3.4", "ports": [80], "cpes": [], "hostnames": [],
                       "tags": [], "vulns": [], "fetched_at": "now"}
        urlhaus_data = {"host": "1.2.3.4", "urls_count": 2, "blacklisted": True,
                        "tags": ["botnet"], "urls": [], "fetched_at": "now"}
        gn_data = {"ip": "1.2.3.4", "noise": True, "riot": False,
                   "classification": "malicious", "name": "Scanner",
                   "link": "", "fetched_at": "now"}

        with patch.object(intel, "get_shodan_cache", return_value=shodan_data), \
             patch.object(intel, "get_urlhaus_cache", return_value=urlhaus_data), \
             patch.object(intel, "get_greynoise_cache", return_value=gn_data):
            result = intel.enrich_target("1.2.3.4")
            assert result["shodan"]["ports"] == [80]
            assert result["in_urlhaus"] is True
            assert result["greynoise_classification"] == "malicious"

    def test_enrich_hostname_only_urlhaus(self):
        """Hostnames should only get URLhaus enrichment, not Shodan/GreyNoise."""
        urlhaus_data = {"host": "example.com", "urls_count": 0, "blacklisted": False,
                        "tags": [], "urls": [], "fetched_at": "now"}

        with patch.object(intel, "get_urlhaus_cache", return_value=urlhaus_data):
            result = intel.enrich_target("example.com")
            assert "shodan" not in result
            assert "greynoise" not in result
            assert result["in_urlhaus"] is False

    def test_enrich_all_fail_graceful(self):
        """All sources failing should return partial result, not crash."""
        with patch.object(intel, "get_shodan_cache", return_value=None), \
             patch.object(intel, "sync_shodan", side_effect=Exception("fail")), \
             patch.object(intel, "get_urlhaus_cache", return_value=None), \
             patch.object(intel, "sync_urlhaus", side_effect=Exception("fail")), \
             patch.object(intel, "get_greynoise_cache", return_value=None), \
             patch.object(intel, "sync_greynoise", side_effect=Exception("fail")):
            result = intel.enrich_target("1.2.3.4")
            assert result.get("in_urlhaus") is False
            assert result.get("greynoise_classification") == "unknown"
