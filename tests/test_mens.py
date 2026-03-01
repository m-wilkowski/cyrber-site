"""Tests for MENS v2 — agent logic + API endpoints."""

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

_MISSION_UUID = str(uuid.uuid4())
_POLICY_ID = 1
_ORG_ID = 1


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


def _mock_policy_row(policy_id=_POLICY_ID):
    row = MagicMock()
    row.id = policy_id
    row.organization_id = _ORG_ID
    row.mission_id = None
    row.name = "test-policy"
    row.scope_cidrs = ["10.0.0.0/24"]
    row.excluded_hosts = []
    row.allowed_modules = []
    row.excluded_modules = []
    row.time_windows = []
    row.require_approval_cvss = 9.0
    row.max_duration_seconds = 28800
    row.max_targets = 50
    row.mode = "COMES"
    row.is_active = True
    row.created_at = "2026-03-01T00:00:00"
    row.created_by = "admin"
    return row


def _mock_mission(mission_id=_MISSION_UUID, status="pending", mode="COMES", db_id=1):
    m = MagicMock()
    m.id = db_id
    m.organization_id = _ORG_ID
    m.mission_id = mission_id
    m.target = "10.0.0.1"
    m.policy_id = _POLICY_ID
    m.mode = mode
    m.status = status
    m.started_at = "2026-03-01T10:00:00"
    m.completed_at = None
    m.iterations_count = 0
    m.findings_count = 0
    m.summary = None
    m.created_by = "admin"
    return m


def _mock_iteration(iteration_id=1, module="nmap"):
    it = MagicMock()
    it.id = iteration_id
    it.mission_id = 1
    it.iteration_number = 1
    it.module_used = module
    it.target = "10.0.0.1"
    it.reason = "Starting with port scan"
    it.confidence = 0.5
    it.result_summary = "nmap: 3 open ports"
    it.created_at = "2026-03-01T10:01:00"
    return it


def _make_mock_db():
    return MagicMock()


def _setup_db_queries(mock_db, responses):
    call_idx = [0]

    def side_effect(*args):
        idx = call_idx[0]
        call_idx[0] += 1
        if idx < len(responses):
            return responses[idx]()
        return MagicMock()

    mock_db.query.side_effect = side_effect


_DB_PATCH = "backend.routers.mens.SessionLocal"
_LEX_MODEL_PATCH = "backend.routers.mens.LexPolicyModel"
_MISSION_MODEL_PATCH = "backend.routers.mens.MensMissionModel"


# ═══════════════════════════════════════════════════════════════════
# Agent unit tests
# ═══════════════════════════════════════════════════════════════════


class TestMensAgentObserve:
    """Test observe phase builds context from DB."""

    def test_observe_builds_context(self):
        from modules.mind_agent import MensAgent, MensMissionModel
        from modules.lex import LexPolicy

        mock_db = MagicMock()
        policy = LexPolicy(scope_cidrs=["10.0.0.0/24"])

        # Mock scan query
        scan_mock = MagicMock()
        scan_mock.target = "10.0.0.1"
        scan_mock.risk_level = "HIGH"
        scan_mock.findings_count = 5
        scan_mock.profile = "STRAZNIK"
        scan_mock.created_at = "2026-03-01"
        scan_mock.raw_data = None

        # Mock mission query
        mission_mock = MagicMock()
        mission_mock.id = 1

        # Mock iteration query
        iter_mock = MagicMock()
        iter_mock.iteration_number = 1
        iter_mock.module_used = "nmap"
        iter_mock.result_summary = "3 ports open"
        iter_mock.target = "10.0.0.1"

        # Setup queries: Scan, MensMissionModel, MensIterationModel
        call_idx = [0]
        def query_side_effect(*args):
            idx = call_idx[0]
            call_idx[0] += 1
            result = MagicMock()
            if idx == 0:  # Scan query
                result.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [scan_mock]
            elif idx == 1:  # MensMissionModel query
                result.filter.return_value.first.return_value = mission_mock
            elif idx == 2:  # MensIterationModel query
                result.filter.return_value.order_by.return_value.all.return_value = [iter_mock]
            return result
        mock_db.query.side_effect = query_side_effect

        agent = MensAgent(mission_id="test-uuid", policy=policy, db=mock_db)
        context = agent.observe("10.0.0.1")

        assert len(context["recent_scans"]) == 1
        assert context["recent_scans"][0]["risk_level"] == "HIGH"
        assert len(context["iterations"]) == 1
        assert context["iterations"][0]["module"] == "nmap"


class TestMensAgentThink:
    """Test think phase parses LLM response and validates via LEX."""

    def test_think_parses_json(self):
        from modules.mind_agent import MensAgent
        from modules.lex import LexPolicy

        mock_db = MagicMock()
        policy = LexPolicy(scope_cidrs=["10.0.0.0/24"])

        mock_llm = MagicMock()
        mock_llm.chat.return_value = '{"module": "nmap", "target": "10.0.0.1", "reasoning": "Port scan first", "confidence": 0.6}'

        agent = MensAgent(mission_id="test-uuid", policy=policy, db=mock_db, llm_client=mock_llm)

        context = {"recent_scans": [], "intel": {}, "iterations": [], "target_model": {}}
        decision = agent.think("10.0.0.1", context)

        assert decision.module == "nmap"
        assert decision.confidence == 0.6
        assert not decision.done
        assert decision.reason == "Port scan first"

    def test_think_lex_blocks_excluded_module(self):
        from modules.mind_agent import MensAgent
        from modules.lex import LexPolicy

        mock_db = MagicMock()
        policy = LexPolicy(
            scope_cidrs=["10.0.0.0/24"],
            excluded_modules=["sqlmap"],
        )

        mock_llm = MagicMock()
        mock_llm.chat.return_value = '{"module": "sqlmap", "target": "10.0.0.1", "reasoning": "Test SQL injection", "confidence": 0.7}'

        agent = MensAgent(mission_id="test-uuid", policy=policy, db=mock_db, llm_client=mock_llm)

        context = {"recent_scans": [], "intel": {}, "iterations": [], "target_model": {}}
        decision = agent.think("10.0.0.1", context)

        assert decision.module == ""  # Blocked
        assert any("BLOCKED" in w for w in decision.lex_warnings)

    def test_think_done_decision(self):
        from modules.mind_agent import MensAgent
        from modules.lex import LexPolicy

        mock_db = MagicMock()
        policy = LexPolicy()

        mock_llm = MagicMock()
        mock_llm.chat.return_value = '{"module": "DONE", "reasoning": "All done", "confidence": 1.0}'

        agent = MensAgent(mission_id="test-uuid", policy=policy, db=mock_db, llm_client=mock_llm)

        context = {"recent_scans": [], "intel": {}, "iterations": [], "target_model": {}}
        decision = agent.think("10.0.0.1", context)

        assert decision.done is True


class TestMensAgentAct:
    """Test act phase dispatches scan functions."""

    def test_act_calls_scan_function(self):
        from modules.mind_agent import MensAgent, MensDecision
        from modules.lex import LexPolicy

        mock_db = MagicMock()
        policy = LexPolicy()

        agent = MensAgent(mission_id="test-uuid", policy=policy, db=mock_db)

        decision = MensDecision(module="nmap", target="10.0.0.1", reason="Port scan", confidence=0.6)

        with patch("modules.mind_agent._get_scan_function") as mock_get:
            mock_fn = MagicMock(return_value={"ports": [22, 80, 443], "findings": [{"port": 22}]})
            mock_get.return_value = mock_fn

            result = agent.act(decision)

        assert result["status"] == "completed"
        mock_fn.assert_called_once_with("10.0.0.1")

    def test_act_done_returns_done(self):
        from modules.mind_agent import MensAgent, MensDecision
        from modules.lex import LexPolicy

        mock_db = MagicMock()
        policy = LexPolicy()

        agent = MensAgent(mission_id="test-uuid", policy=policy, db=mock_db)
        decision = MensDecision(done=True)

        result = agent.act(decision)
        assert result["status"] == "done"


class TestMensAgentLearn:
    """Test learn phase persists iterations."""

    def test_learn_saves_iteration(self):
        from modules.mind_agent import MensAgent, MensDecision
        from modules.lex import LexPolicy

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        policy = LexPolicy()

        agent = MensAgent(mission_id="test-uuid", policy=policy, db=mock_db)
        decision = MensDecision(module="nmap", target="10.0.0.1", reason="Port scan", confidence=0.6)
        result = {"status": "completed", "result": {"findings": [{"port": 22}, {"port": 80}]}}

        findings = agent.learn(decision, result, mission_db_id=1)

        assert findings == 2
        assert mock_db.add.called
        assert mock_db.commit.called

    def test_learn_updates_target_model(self):
        from modules.mind_agent import MensAgent, MensDecision
        from modules.lex import LexPolicy

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        policy = LexPolicy()

        agent = MensAgent(mission_id="test-uuid", policy=policy, db=mock_db)
        decision = MensDecision(module="nmap", target="10.0.0.1", reason="Port scan", confidence=0.6)
        result = {"status": "completed", "result": {"findings": [{"port": 22}]}}

        agent.learn(decision, result, mission_db_id=1)

        assert "nmap" in agent._target_model
        assert agent._target_model["nmap"]["findings"] == 1


class TestMensAgentRun:
    """Test full run loop."""

    def test_run_stops_on_done(self):
        from modules.mind_agent import MensAgent
        from modules.lex import LexPolicy

        mock_db = MagicMock()
        policy = LexPolicy()

        # Mission row
        mission_row = MagicMock()
        mission_row.id = 1
        mission_row.mission_id = "test-uuid"
        mission_row.status = "running"

        # DB queries: first for mission lookup, then repeated for loop
        def query_side_effect(*args):
            m = MagicMock()
            # All filter().first() returns mission_row
            m.filter.return_value.first.return_value = mission_row
            # count returns 0
            m.filter.return_value.count.return_value = 0
            # For observe: empty results
            m.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
            m.filter.return_value.order_by.return_value.all.return_value = []
            return m
        mock_db.query.side_effect = query_side_effect

        mock_llm = MagicMock()
        mock_llm.chat.return_value = '{"module": "DONE", "reasoning": "All done", "confidence": 1.0}'

        agent = MensAgent(mission_id="test-uuid", policy=policy, db=mock_db, llm_client=mock_llm)
        result = agent.run("10.0.0.1")

        assert result.status == "completed"
        assert result.mission_id == "test-uuid"

    def test_run_stops_on_max_iterations(self):
        from modules.mind_agent import MensAgent
        import modules.mind_agent as ma
        from modules.lex import LexPolicy

        mock_db = MagicMock()
        policy = LexPolicy()

        mission_row = MagicMock()
        mission_row.id = 1
        mission_row.mission_id = "test-uuid"
        mission_row.status = "running"

        def query_side_effect(*args):
            m = MagicMock()
            m.filter.return_value.first.return_value = mission_row
            m.filter.return_value.count.return_value = 0
            m.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
            m.filter.return_value.order_by.return_value.all.return_value = []
            return m
        mock_db.query.side_effect = query_side_effect

        mock_llm = MagicMock()
        mock_llm.chat.return_value = '{"module": "nmap", "target": "10.0.0.1", "reasoning": "Keep scanning", "confidence": 0.5}'

        agent = MensAgent(mission_id="test-uuid", policy=policy, db=mock_db, llm_client=mock_llm)

        # Temporarily set low max
        old_max = ma.MAX_ITERATIONS
        ma.MAX_ITERATIONS = 3
        try:
            with patch("modules.mind_agent._get_scan_function") as mock_get:
                mock_fn = MagicMock(return_value={"findings": []})
                mock_get.return_value = mock_fn

                result = agent.run("10.0.0.1")
        finally:
            ma.MAX_ITERATIONS = old_max

        assert result.iterations == 3
        assert result.status == "completed"


class TestClassifyHead:
    """Test Cerberus head classification."""

    def test_ratio_module(self):
        from modules.mind_agent import classify_head
        assert classify_head("nmap") == "RATIO"
        assert classify_head("nuclei") == "RATIO"

    def test_animus_module(self):
        from modules.mind_agent import classify_head
        assert classify_head("harvester") == "ANIMUS"
        assert classify_head("gophish") == "ANIMUS"

    def test_fatum_module(self):
        from modules.mind_agent import classify_head
        assert classify_head("bloodhound") == "FATUM"
        assert classify_head("subfinder") == "FATUM"

    def test_unknown_defaults_ratio(self):
        from modules.mind_agent import classify_head
        assert classify_head("unknown_module") == "RATIO"


class TestParseDecision:
    """Test JSON parsing from Claude responses."""

    def test_parse_clean_json(self):
        from modules.mind_agent import _parse_decision
        result = _parse_decision('{"module": "nmap", "reasoning": "test", "confidence": 0.5}')
        assert result["module"] == "nmap"

    def test_parse_with_markdown_fences(self):
        from modules.mind_agent import _parse_decision
        result = _parse_decision('```json\n{"module": "nmap", "reasoning": "test", "confidence": 0.5}\n```')
        assert result["module"] == "nmap"

    def test_parse_garbage_returns_done(self):
        from modules.mind_agent import _parse_decision
        result = _parse_decision("This is not JSON at all")
        assert result["module"] == "DONE"


# ═══════════════════════════════════════════════════════════════════
# API endpoint tests
# ═══════════════════════════════════════════════════════════════════


class TestMensAPICreate:
    """Test POST /api/mens/missions."""

    def test_create_mission(self):
        _as_admin()
        mock_db = _make_mock_db()
        mock_db.query.return_value.filter.return_value.first.return_value = _mock_policy_row()

        mock_lex_model = MagicMock()
        with patch(_DB_PATCH, return_value=mock_db), \
                patch(_LEX_MODEL_PATCH, mock_lex_model), \
                patch("modules.mens_task.run_mens_mission") as mock_task:
            mock_task.delay.return_value = MagicMock(id="celery-001")
            r = client.post("/api/mens/missions", json={
                "target": "10.0.0.1",
                "policy_id": _POLICY_ID,
                "mode": "COMES",
            })
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        data = r.json()
        assert data["target"] == "10.0.0.1"
        assert data["status"] == "pending"
        assert data["mode"] == "COMES"
        assert data["policy_id"] == _POLICY_ID

    def test_create_mission_viewer_forbidden(self):
        _as_viewer()
        r = client.post("/api/mens/missions", json={
            "target": "10.0.0.1",
            "policy_id": _POLICY_ID,
        })
        assert r.status_code == 403

    def test_create_mission_invalid_policy(self):
        _as_admin()
        mock_db = _make_mock_db()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        mock_lex_model = MagicMock()
        with patch(_DB_PATCH, return_value=mock_db), \
                patch(_LEX_MODEL_PATCH, mock_lex_model):
            r = client.post("/api/mens/missions", json={
                "target": "10.0.0.1",
                "policy_id": 999,
            })
        assert r.status_code == 400
        assert "policy" in r.json()["detail"].lower()


class TestMensAPIList:
    """Test GET /api/mens/missions."""

    def test_list_missions(self):
        _as_admin()
        mock_db = _make_mock_db()
        mock_db.query.return_value.order_by.return_value.limit.return_value.all.return_value = [
            _mock_mission(),
        ]

        mock_mission_model = MagicMock()
        with patch(_DB_PATCH, return_value=mock_db), \
                patch(_MISSION_MODEL_PATCH, mock_mission_model):
            r = client.get("/api/mens/missions")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_list_missions_no_auth(self):
        r = client.get("/api/mens/missions")
        assert r.status_code == 401


class TestMensAPIDetail:
    """Test GET /api/mens/missions/{mission_id}."""

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

        mock_mission_model = MagicMock()
        mock_iter_model = MagicMock()
        with patch(_DB_PATCH, return_value=mock_db), \
                patch(_MISSION_MODEL_PATCH, mock_mission_model), \
                patch("backend.routers.mens.MensIterationModel", mock_iter_model):
            r = client.get(f"/api/mens/missions/{_MISSION_UUID}")
        assert r.status_code == 200
        data = r.json()
        assert data["mission_id"] == _MISSION_UUID
        assert "iterations" in data
        assert len(data["iterations"]) == 1

    def test_get_mission_not_found(self):
        _as_admin()
        mock_db = _make_mock_db()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        mock_mission_model = MagicMock()
        with patch(_DB_PATCH, return_value=mock_db), \
                patch(_MISSION_MODEL_PATCH, mock_mission_model):
            r = client.get(f"/api/mens/missions/{uuid.uuid4()}")
        assert r.status_code == 404


class TestMensAPIAbort:
    """Test POST /api/mens/missions/{mission_id}/abort."""

    def test_abort_mission(self):
        _as_operator()
        mock_db = _make_mock_db()
        mission = _mock_mission(status="running")
        mock_db.query.return_value.filter.return_value.first.return_value = mission

        mock_mission_model = MagicMock()
        with patch(_DB_PATCH, return_value=mock_db), \
                patch(_MISSION_MODEL_PATCH, mock_mission_model):
            r = client.post(f"/api/mens/missions/{_MISSION_UUID}/abort")
        assert r.status_code == 200
        assert r.json()["status"] == "aborted"


class TestMensAPIApprove:
    """Test POST /api/mens/missions/{mission_id}/approve."""

    def test_approve_paused_mission(self):
        _as_admin()
        mock_db = _make_mock_db()
        mission = _mock_mission(status="paused")
        policy_row = _mock_policy_row()

        def q1():
            m = MagicMock()
            m.filter.return_value.first.return_value = mission
            return m

        def q2():
            m = MagicMock()
            m.filter.return_value.first.return_value = policy_row
            return m

        _setup_db_queries(mock_db, [q1, q2])

        mock_mission_model = MagicMock()
        mock_lex_model = MagicMock()
        with patch(_DB_PATCH, return_value=mock_db), \
                patch(_MISSION_MODEL_PATCH, mock_mission_model), \
                patch(_LEX_MODEL_PATCH, mock_lex_model), \
                patch("modules.mens_task.run_mens_mission") as mock_task:
            mock_task.delay.return_value = MagicMock(id="celery-002")
            r = client.post(f"/api/mens/missions/{_MISSION_UUID}/approve")
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        assert r.json()["status"] == "approved"

    def test_approve_non_paused_fails(self):
        _as_admin()
        mock_db = _make_mock_db()
        mission = _mock_mission(status="running")
        mock_db.query.return_value.filter.return_value.first.return_value = mission

        mock_mission_model = MagicMock()
        with patch(_DB_PATCH, return_value=mock_db), \
                patch(_MISSION_MODEL_PATCH, mock_mission_model):
            r = client.post(f"/api/mens/missions/{_MISSION_UUID}/approve")
        assert r.status_code == 400
