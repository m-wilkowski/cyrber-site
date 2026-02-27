"""Integration tests for MENS API router (/api/mind/*)."""

import sys
import os
import uuid
from unittest.mock import MagicMock, patch
import pytest

# ── Ensure real modules.database is loaded ──
# test_malwarebazaar.py may replace it with MagicMock during collection.
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
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from backend.deps import get_current_user
from backend.main import app

client = TestClient(app, raise_server_exceptions=False)

# ── User fixtures ──
_ADMIN = {"id": 1, "username": "admin", "role": "admin", "is_active": True, "email": "a@test"}
_OPERATOR = {"id": 2, "username": "operator", "role": "operator", "is_active": True, "email": "o@test"}
_VIEWER = {"id": 3, "username": "viewer", "role": "viewer", "is_active": True, "email": "v@test"}

_RULE_ID = str(uuid.uuid4())
_MISSION_ID = str(uuid.uuid4())
_ITERATION_ID = str(uuid.uuid4())


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

def _mock_lex_rule(rule_id=_RULE_ID):
    rule = MagicMock()
    rule.id = rule_id
    rule.name = "test-rule"
    rule.mission_id = None
    rule.scope_cidrs = ["10.0.0.0/24"]
    rule.excluded_hosts = []
    rule.allowed_hours = None
    rule.max_cvss_without_approval = 7.0
    rule.max_duration_minutes = 480
    rule.allowed_modules = None
    rule.require_comes_mode = False
    rule.active = True
    rule.created_at = "2026-02-27T00:00:00"
    rule.created_by = "admin"
    return rule


def _mock_mission(mission_id=_MISSION_ID, status="pending", mode="comes"):
    m = MagicMock()
    m.id = mission_id
    m.target = "10.0.0.1"
    m.objective = "Full recon"
    m.lex_rule_id = _RULE_ID
    m.mode = mode
    m.status = status
    m.fiducia = 0.0
    m.started_at = "2026-02-27T10:00:00"
    m.completed_at = None
    m.created_by = "admin"
    return m


def _mock_iteration(iteration_id=_ITERATION_ID, approved=None):
    it = MagicMock()
    it.id = iteration_id
    it.mission_id = _MISSION_ID
    it.iteration_number = 1
    it.phase = "think"
    it.module_selected = "nmap"
    it.module_args = {"target": "10.0.0.1"}
    it.cogitatio = "Starting with port scan"
    it.result_summary = None
    it.findings_count = 0
    it.approved = approved
    it.created_at = "2026-02-27T10:01:00"
    return it


def _make_mock_db():
    """Create a fresh mock DB session."""
    return MagicMock()


def _setup_db_queries(mock_db, responses):
    """Set up mock_db.query() to return different results per call."""
    call_idx = [0]

    def side_effect(*args):
        idx = call_idx[0]
        call_idx[0] += 1
        if idx < len(responses):
            return responses[idx]()
        return MagicMock()

    mock_db.query.side_effect = side_effect


# Patch target for SessionLocal in mind.py (used by _get_db generator)
_DB_PATCH = "backend.routers.mind.SessionLocal"


# ═══════════════════════════════════════════════════════════════════
# Missions
# ═══════════════════════════════════════════════════════════════════


class TestMissionCreate:
    def test_create_mission(self):
        _as_admin()
        mock_db = _make_mock_db()
        mock_db.query.return_value.filter.return_value.first.return_value = _mock_lex_rule()

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.post("/api/mind/missions", json={
                "target": "10.0.0.1",
                "objective": "Full recon",
                "lex_rule_id": _RULE_ID,
                "mode": "comes",
            })
        assert r.status_code == 200
        data = r.json()
        assert data["target"] == "10.0.0.1"
        assert data["status"] == "pending"
        assert data["mode"] == "comes"

    def test_create_mission_viewer_forbidden(self):
        _as_viewer()
        r = client.post("/api/mind/missions", json={
            "target": "10.0.0.1",
            "objective": "Recon",
            "lex_rule_id": _RULE_ID,
        })
        assert r.status_code == 403

    def test_create_mission_invalid_rule(self):
        _as_admin()
        mock_db = _make_mock_db()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.post("/api/mind/missions", json={
                "target": "10.0.0.1",
                "objective": "Recon",
                "lex_rule_id": str(uuid.uuid4()),
            })
        assert r.status_code == 400
        assert "LEX rule" in r.json()["detail"]


class TestMissionList:
    def test_list_missions(self):
        _as_admin()
        mock_db = _make_mock_db()
        mock_db.query.return_value.order_by.return_value.limit.return_value.all.return_value = [
            _mock_mission(),
        ]

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get("/api/mind/missions")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["target"] == "10.0.0.1"

    def test_list_missions_no_auth(self):
        r = client.get("/api/mind/missions")
        assert r.status_code == 401


class TestMissionDetail:
    def test_get_mission_detail(self):
        _as_admin()
        mock_db = _make_mock_db()
        mission_mock = _mock_mission()
        iteration_mock = _mock_iteration()

        def q1():
            m = MagicMock()
            m.filter.return_value.first.return_value = mission_mock
            return m

        def q2():
            m = MagicMock()
            m.filter.return_value.order_by.return_value.all.return_value = [iteration_mock]
            return m

        _setup_db_queries(mock_db, [q1, q2])

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get(f"/api/mind/missions/{_MISSION_ID}")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == _MISSION_ID
        assert "iterations" in data
        assert len(data["iterations"]) == 1

    def test_get_mission_not_found(self):
        _as_admin()
        mock_db = _make_mock_db()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get(f"/api/mind/missions/{uuid.uuid4()}")
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════
# Start / Abort
# ═══════════════════════════════════════════════════════════════════


class TestMissionStartAbort:
    def test_start_mission(self):
        _as_operator()
        mock_db = _make_mock_db()
        mission = _mock_mission(status="pending")
        mock_db.query.return_value.filter.return_value.first.return_value = mission

        with patch(_DB_PATCH, return_value=mock_db), \
                patch("modules.mens_task.mens_run_task") as mock_task:
            mock_task.delay.return_value = MagicMock(id="celery-task-001")
            r = client.post(f"/api/mind/missions/{_MISSION_ID}/start")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "started"
        mock_task.delay.assert_called_once_with(_MISSION_ID)

    def test_abort_mission(self):
        _as_operator()
        mock_db = _make_mock_db()
        mission = _mock_mission(status="running")
        mock_db.query.return_value.filter.return_value.first.return_value = mission

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.post(f"/api/mind/missions/{_MISSION_ID}/abort")
        assert r.status_code == 200
        assert r.json()["status"] == "aborted"


# ═══════════════════════════════════════════════════════════════════
# Approve / Reject
# ═══════════════════════════════════════════════════════════════════


class TestIterationApproval:
    def test_approve_iteration(self):
        _as_admin()
        mock_db = _make_mock_db()
        mission = _mock_mission(status="running", mode="comes")
        iteration = _mock_iteration(approved=None)

        def q1():
            m = MagicMock()
            m.filter.return_value.first.return_value = mission
            return m

        def q2():
            m = MagicMock()
            m.filter.return_value.first.return_value = iteration
            return m

        _setup_db_queries(mock_db, [q1, q2])

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.post(
                f"/api/mind/missions/{_MISSION_ID}/iterations/{_ITERATION_ID}/approve"
            )
        assert r.status_code == 200
        assert r.json()["status"] == "approved"
        assert iteration.approved is True

    def test_reject_iteration_with_reason(self):
        _as_admin()
        mock_db = _make_mock_db()
        mission = _mock_mission(status="running")
        iteration = _mock_iteration(approved=None)

        def q1():
            m = MagicMock()
            m.filter.return_value.first.return_value = mission
            return m

        def q2():
            m = MagicMock()
            m.filter.return_value.first.return_value = iteration
            return m

        _setup_db_queries(mock_db, [q1, q2])

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.post(
                f"/api/mind/missions/{_MISSION_ID}/iterations/{_ITERATION_ID}/reject",
                json={"reason": "Too risky"},
            )
        assert r.status_code == 200
        assert r.json()["status"] == "rejected"
        assert iteration.approved is False

    def test_approve_non_comes_fails(self):
        _as_admin()
        mock_db = _make_mock_db()
        mission = _mock_mission(mode="liber")
        mock_db.query.return_value.filter.return_value.first.return_value = mission

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.post(
                f"/api/mind/missions/{_MISSION_ID}/iterations/{_ITERATION_ID}/approve"
            )
        assert r.status_code == 400
        assert "COMES" in r.json()["detail"]


# ═══════════════════════════════════════════════════════════════════
# LEX rules
# ═══════════════════════════════════════════════════════════════════


class TestLexRules:
    def test_list_lex_rules(self):
        _as_operator()
        mock_db = _make_mock_db()
        mock_db.query.return_value.filter.return_value.all.return_value = [_mock_lex_rule()]

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get("/api/mind/lex/rules")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "test-rule"

    def test_create_lex_rule_admin(self):
        _as_admin()
        mock_db = _make_mock_db()

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.post("/api/mind/lex/rules", json={
                "name": "new-rule",
                "scope_cidrs": ["192.168.1.0/24"],
                "max_cvss_without_approval": 5.0,
            })
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "new-rule"
        assert data["scope_cidrs"] == ["192.168.1.0/24"]
        assert data["max_cvss_without_approval"] == 5.0
        assert data["active"] is True

    def test_create_lex_rule_operator_forbidden(self):
        _as_operator()
        r = client.post("/api/mind/lex/rules", json={
            "name": "hacked-rule",
            "scope_cidrs": ["0.0.0.0/0"],
        })
        assert r.status_code == 403

    def test_create_lex_rule_no_auth(self):
        r = client.post("/api/mind/lex/rules", json={
            "name": "anon-rule",
        })
        assert r.status_code == 401
