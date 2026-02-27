"""Integration tests for CYRBER API routers using FastAPI TestClient.

Tests cover key endpoints from all 13 routers + RBAC enforcement.
Auth: app.dependency_overrides[get_current_user].
DB/service calls: patched at router import site per test.
"""

import sys
import os
from unittest.mock import MagicMock, patch
import pytest

# ── Pre-mock scan tool modules (may need system binaries) ──
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

# Pre-mock service modules that connect to external services at import time
for _mod in [
    "modules.tasks", "modules.pdf_report", "modules.compliance_map",
    "modules.exploit_chains", "modules.hacker_narrative",
    "modules.rag_knowledge", "modules.llm_provider",
    "modules.misp_integration", "modules.intelligence_sync",
]:
    sys.modules.setdefault(_mod, MagicMock())

# modules.notify — dashboard.py reads constants at import time
if "modules.notify" not in sys.modules:
    _nm = MagicMock()
    for _attr in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS", "SMTP_TO",
                   "SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL",
                   "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        setattr(_nm, _attr, "")
    sys.modules["modules.notify"] = _nm

# ── Import app ──
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from backend.deps import get_current_user
from backend.main import app

client = TestClient(app, raise_server_exceptions=False)

# ── User fixtures ──
_ADMIN = {"id": 1, "username": "admin", "role": "admin", "is_active": True, "email": "a@test"}
_OPERATOR = {"id": 2, "username": "operator", "role": "operator", "is_active": True, "email": "o@test"}
_VIEWER = {"id": 3, "username": "viewer", "role": "viewer", "is_active": True, "email": "v@test"}


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


# ═══════════════════════════════════════════════════════════════════
# pages.py
# ═══════════════════════════════════════════════════════════════════


class TestPages:
    def test_health(self):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_root_redirects_to_ui(self):
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 307
        assert "/ui" in r.headers["location"]

    def test_ui_page(self):
        r = client.get("/ui")
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# auth.py
# ═══════════════════════════════════════════════════════════════════


class TestAuth:
    def test_login_valid(self):
        from passlib.hash import sha256_crypt
        hashed = sha256_crypt.hash("testpass123")
        with patch("backend.routers.auth.get_user_by_username_raw", return_value={
            "id": 1, "username": "admin", "role": "admin",
            "is_active": True, "password_hash": hashed,
        }), patch("backend.routers.auth.update_user"), \
                patch("backend.routers.auth.save_audit_log"):
            r = client.post("/auth/login", json={
                "username": "admin", "password": "testpass123",
            })
        assert r.status_code == 200
        data = r.json()
        assert "token" in data
        assert data["role"] == "admin"
        assert data["username"] == "admin"

    def test_login_invalid(self):
        with patch("backend.routers.auth.get_user_by_username_raw", return_value=None), \
                patch("backend.routers.auth.save_audit_log"):
            r = client.post("/auth/login", json={
                "username": "bad", "password": "bad",
            })
        assert r.status_code == 401

    def test_me_authenticated(self):
        _as_admin()
        r = client.get("/auth/me")
        assert r.status_code == 200
        assert r.json()["username"] == "admin"

    def test_me_no_token(self):
        r = client.get("/auth/me")
        assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════
# admin.py
# ═══════════════════════════════════════════════════════════════════


class TestAdmin:
    def test_list_users_admin(self):
        _as_admin()
        with patch("backend.routers.admin.list_users", return_value=[_ADMIN]):
            r = client.get("/admin/users")
        assert r.status_code == 200

    def test_list_users_viewer_forbidden(self):
        _as_viewer()
        r = client.get("/admin/users")
        assert r.status_code == 403

    def test_license_info(self):
        _as_admin()
        with patch("backend.routers.admin.get_license_info", return_value={
            "tier": "community", "max_scans_per_month": 10, "max_users": 3,
        }), patch("backend.routers.admin.get_scans_this_month", return_value=0), \
                patch("backend.routers.admin.count_active_users", return_value=1):
            r = client.get("/license")
        assert r.status_code == 200
        assert "tier" in r.json()


# ═══════════════════════════════════════════════════════════════════
# scans.py
# ═══════════════════════════════════════════════════════════════════


class TestScans:
    def test_scan_profiles(self):
        _as_admin()
        with patch("backend.routers.scans.get_profiles_list", return_value=[
            {"name": "STRAZNIK"}, {"name": "CERBER"},
        ]):
            r = client.get("/scan/profiles")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_scan_start_operator(self):
        _as_admin()
        mock_result = MagicMock(id="test-task-001")
        with patch("backend.routers.scans.get_profile", return_value={"name": "STRAZNIK"}), \
                patch("backend.routers.scans.full_scan_task") as mock_task, \
                patch("backend.routers.scans.increment_scan_count"), \
                patch("backend.routers.scans.audit"):
            mock_task.delay.return_value = mock_result
            r = client.post("/scan/start", json={
                "target": "example.com", "profile": "STRAZNIK",
            })
        assert r.status_code == 200
        data = r.json()
        assert data["task_id"] == "test-task-001"
        assert data["status"] == "started"

    def test_scan_start_viewer_forbidden(self):
        _as_viewer()
        r = client.post("/scan/start", json={"target": "example.com"})
        assert r.status_code == 403

    def test_scans_history(self):
        _as_admin()
        with patch("backend.routers.scans.get_scan_history", return_value=[]):
            r = client.get("/scans")
        assert r.status_code == 200

    def test_scan_detail_not_found(self):
        _as_admin()
        with patch("backend.routers.scans.get_scan_by_task_id", return_value=None):
            r = client.get("/scans/nonexistent-id")
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════
# scan_tools.py
# ═══════════════════════════════════════════════════════════════════


class TestScanTools:
    def test_nmap_operator(self):
        _as_operator()
        with patch("backend.routers.scan_tools.nmap_scan", return_value={
            "target": "example.com", "ports": [],
        }):
            r = client.get("/scan/nmap?target=example.com")
        assert r.status_code == 200

    def test_nmap_no_auth(self):
        r = client.get("/scan/nmap?target=example.com")
        assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════
# topology.py
# ═══════════════════════════════════════════════════════════════════


class TestTopology:
    def test_topology_endpoint(self):
        _as_admin()
        with patch("backend.routers.topology.get_scan_by_task_id", return_value={
            "task_id": "t-001", "target": "10.0.0.1", "status": "completed",
        }):
            r = client.get("/api/scan/t-001/topology")
        assert r.status_code == 200
        data = r.json()
        assert "nodes" in data
        assert "edges" in data


# ═══════════════════════════════════════════════════════════════════
# osint.py
# ═══════════════════════════════════════════════════════════════════


class TestOsint:
    def test_osint_start(self):
        _as_operator()
        mock_result = MagicMock(id="osint-task-001")
        with patch("backend.routers.osint.osint_scan_task") as mock_task, \
                patch("backend.routers.osint.audit"):
            mock_task.delay.return_value = mock_result
            r = client.get("/osint/start?target=example.com")
        assert r.status_code == 200
        assert r.json()["task_id"] == "osint-task-001"


# ═══════════════════════════════════════════════════════════════════
# remediation.py
# ═══════════════════════════════════════════════════════════════════


class TestRemediation:
    def test_get_remediation(self):
        _as_admin()
        with patch("backend.routers.remediation.get_remediation_tasks", return_value=[]), \
                patch("backend.routers.remediation.get_remediation_stats", return_value={
                    "open": 0, "fixed": 0, "verified": 0,
                }):
            r = client.get("/api/scan/t-001/remediation")
        assert r.status_code == 200
        data = r.json()
        assert "tasks" in data
        assert "stats" in data


# ═══════════════════════════════════════════════════════════════════
# intelligence.py
# ═══════════════════════════════════════════════════════════════════


class TestIntelligence:
    def test_attack_tactics(self):
        _as_admin()
        with patch("backend.routers.intelligence.get_attack_tactics", return_value=[
            {"tactic_id": "TA0001", "name": "Initial Access"},
        ]):
            r = client.get("/api/attack/tactics")
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# dashboard.py
# ═══════════════════════════════════════════════════════════════════


class TestDashboard:
    def test_schedules(self):
        _as_admin()
        with patch("backend.routers.dashboard.get_schedules", return_value=[]):
            r = client.get("/schedules")
        assert r.status_code == 200

    def test_notifications_status(self):
        _as_admin()
        r = client.get("/notifications/status")
        assert r.status_code == 200
        data = r.json()
        assert "email" in data
        assert "slack" in data


# ═══════════════════════════════════════════════════════════════════
# verify.py
# ═══════════════════════════════════════════════════════════════════


class TestVerify:
    def test_verify_history(self):
        _as_operator()
        with patch("modules.database.get_verify_history", return_value=[]):
            r = client.get("/api/verify/history")
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# phishing.py
# ═══════════════════════════════════════════════════════════════════


class TestPhishing:
    def test_campaigns_gophish_down(self):
        """GoPhish not running → 503."""
        _as_admin()
        import requests as http_requests
        with patch(
            "backend.routers.phishing._gophish_get",
            side_effect=http_requests.ConnectionError("Connection refused"),
        ):
            r = client.get("/phishing/campaigns")
        assert r.status_code == 503
