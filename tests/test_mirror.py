"""Integration tests for MIRROR API router (/api/mirror/*)."""

import sys
import os
import uuid
from unittest.mock import MagicMock, patch
import pytest

# ── Ensure real modules.database is loaded ──
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if isinstance(sys.modules.get("modules.database"), MagicMock):
    del sys.modules["modules.database"]

# ── Pre-mock scan tool and service modules ──
_SCAN_TOOL_MODULES = [
    "modules.nmap_scan", "modules.nuclei_scan", "modules.llm_analyze",
    "modules.gobuster_scan", "modules.whatweb_scan", "modules.testssl_scan",
    "modules.sqlmap_scan", "modules.nikto_scan", "modules.harvester_scan",
    "modules.masscan_scan", "modules.ipinfo_scan", "modules.enum4linux_scan",
    "modules.mitre_attack", "modules.abuseipdb_scan", "modules.otx_scan",
    "modules.exploitdb_scan", "modules.nvd_scan", "modules.whois_scan",
    "modules.dnsrecon_scan", "modules.amass_scan", "modules.cwe_mapping",
    "modules.owasp_mapping", "modules.wpscan_scan", "modules.zap_scan",
    "modules.wapiti_scan", "modules.joomscan_scan", "modules.cmsmap_scan",
    "modules.droopescan_scan", "modules.retirejs_scan", "modules.subfinder_scan",
    "modules.httpx_scan", "modules.naabu_scan", "modules.katana_scan",
    "modules.dnsx_scan", "modules.netdiscover_scan", "modules.arpscan_scan",
    "modules.fping_scan", "modules.traceroute_scan", "modules.nbtscan_scan",
    "modules.snmpwalk_scan", "modules.netexec_scan", "modules.bloodhound_scan",
    "modules.responder_scan", "modules.fierce_scan", "modules.smbmap_scan",
    "modules.onesixtyone_scan", "modules.ikescan_scan", "modules.sslyze_scan",
    "modules.searchsploit_scan", "modules.impacket_scan", "modules.certipy_scan",
]
for _mod in _SCAN_TOOL_MODULES:
    sys.modules.setdefault(_mod, MagicMock())

for _mod in [
    "modules.tasks", "modules.pdf_report", "modules.compliance_map",
    "modules.exploit_chains", "modules.hacker_narrative",
    "modules.rag_knowledge", "modules.llm_provider",
    "modules.misp_integration", "modules.intelligence_sync",
    "modules.mens_task",
]:
    sys.modules.setdefault(_mod, MagicMock())

if "modules.notify" not in sys.modules:
    _nm = MagicMock()
    for _attr in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS", "SMTP_TO",
                   "SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL",
                   "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        setattr(_nm, _attr, "")
    sys.modules["modules.notify"] = _nm

# ── Import app ──
from fastapi.testclient import TestClient
from backend.deps import get_current_user
from backend.main import app

client = TestClient(app, raise_server_exceptions=False)

# ── User fixtures ──
_ADMIN = {"id": 1, "username": "admin", "role": "admin", "is_active": True, "email": "a@test"}
_OPERATOR = {"id": 2, "username": "operator", "role": "operator", "is_active": True, "email": "o@test"}
_VIEWER = {"id": 3, "username": "viewer", "role": "viewer", "is_active": True, "email": "v@test"}

_PROFILE_ID = str(uuid.uuid4())
_TARGET = "10.0.0.1"


@pytest.fixture(autouse=True)
def _cleanup_overrides():
    yield
    app.dependency_overrides.clear()


def _as_admin():
    app.dependency_overrides[get_current_user] = lambda: _ADMIN


def _as_operator():
    app.dependency_overrides[get_current_user] = lambda: _OPERATOR


def _as_viewer():
    app.dependency_overrides[get_current_user] = lambda: _VIEWER


# ── Mock helpers ─────────────────────────────────────────────────

def _mock_profile(target=_TARGET, genome_report=None, genome_generated_at=None):
    p = MagicMock()
    p.id = _PROFILE_ID
    p.target = target
    p.last_updated = "2026-02-27T12:00:00"
    p.missions_count = 3
    p.patch_cycle_days = 45.0
    p.phishing_click_rate = 0.15
    p.credential_reuse_incidents = 1
    p.unreviewed_services = 2
    p.predispositions = {"ransomware": 0.4, "supply_chain": 0.3, "phishing": 0.22}
    p.patterns = ["Slow patching cycle (>90 days)"]
    p.genome_report = genome_report
    p.genome_generated_at = genome_generated_at
    return p


_DB_PATCH = "backend.routers.mirror.SessionLocal"


# ═══════════════════════════════════════════════════════════════════
# List profiles
# ═══════════════════════════════════════════════════════════════════


class TestListProfiles:
    def test_list_profiles_empty(self):
        _as_admin()
        mock_db = MagicMock()
        mock_db.query.return_value.order_by.return_value.limit.return_value.all.return_value = []

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get("/api/mirror/profiles")
        assert r.status_code == 200
        assert r.json() == []

    def test_list_profiles_with_data(self):
        _as_admin()
        mock_db = MagicMock()
        mock_db.query.return_value.order_by.return_value.limit.return_value.all.return_value = [
            _mock_profile(),
        ]

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get("/api/mirror/profiles")
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["target"] == _TARGET
        assert data[0]["missions_count"] == 3

    def test_list_profiles_no_auth(self):
        r = client.get("/api/mirror/profiles")
        assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════
# Get profile
# ═══════════════════════════════════════════════════════════════════


class TestGetProfile:
    def test_get_profile_found(self):
        _as_viewer()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = _mock_profile()

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get(f"/api/mirror/profiles/{_TARGET}")
        assert r.status_code == 200
        data = r.json()
        assert data["target"] == _TARGET
        assert "predispositions" in data
        assert data["predispositions"]["ransomware"] == 0.4

    def test_get_profile_not_found(self):
        _as_admin()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get("/api/mirror/profiles/unknown.example.com")
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════
# Generate genome
# ═══════════════════════════════════════════════════════════════════


class TestGenerateGenome:
    def test_generate_genome_success(self):
        _as_operator()
        mock_db = MagicMock()
        profile = _mock_profile()

        # First query: _get_profile_or_404, second: inside generate_genome
        call_idx = [0]

        def side_effect(*args):
            idx = call_idx[0]
            call_idx[0] += 1
            m = MagicMock()
            m.filter.return_value.first.return_value = profile
            return m

        mock_db.query.side_effect = side_effect

        with patch(_DB_PATCH, return_value=mock_db), \
                patch("backend.mirror.MirrorEngine.generate_genome", return_value="## PREDYSPOZYCJE\nTest genome report"):
            r = client.post(f"/api/mirror/profiles/{_TARGET}/genome")
        assert r.status_code == 200
        data = r.json()
        assert "genome" in data
        assert "PREDYSPOZYCJE" in data["genome"]
        assert "generated_at" in data

    def test_generate_genome_viewer_forbidden(self):
        _as_viewer()
        r = client.post(f"/api/mirror/profiles/{_TARGET}/genome")
        assert r.status_code == 403

    def test_generate_genome_profile_not_found(self):
        _as_admin()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.post("/api/mirror/profiles/nonexistent/genome")
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════
# Get genome
# ═══════════════════════════════════════════════════════════════════


class TestGetGenome:
    def test_get_genome_success(self):
        _as_admin()
        mock_db = MagicMock()
        profile = _mock_profile(
            genome_report="## PREDYSPOZYCJE\nFull report here",
            genome_generated_at="2026-02-27T14:00:00",
        )
        mock_db.query.return_value.filter.return_value.first.return_value = profile

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get(f"/api/mirror/profiles/{_TARGET}/genome")
        assert r.status_code == 200
        data = r.json()
        assert "genome" in data
        assert "PREDYSPOZYCJE" in data["genome"]
        assert data["generated_at"] == "2026-02-27T14:00:00"

    def test_get_genome_not_generated(self):
        _as_admin()
        mock_db = MagicMock()
        profile = _mock_profile(genome_report=None)
        mock_db.query.return_value.filter.return_value.first.return_value = profile

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get(f"/api/mirror/profiles/{_TARGET}/genome")
        assert r.status_code == 404
        assert "not yet generated" in r.json()["detail"]

    def test_get_genome_profile_not_found(self):
        _as_admin()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get("/api/mirror/profiles/nope/genome")
        assert r.status_code == 404
