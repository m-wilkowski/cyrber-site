"""Integration tests for PROOF API router (/api/proof/*)."""

import sys
import os
import uuid
import hashlib
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
from backend.proof import ProofEngine

client = TestClient(app, raise_server_exceptions=False)

# ── User fixtures ──
_ADMIN = {"id": 1, "username": "admin", "role": "admin", "is_active": True, "email": "a@test"}
_OPERATOR = {"id": 2, "username": "operator", "role": "operator", "is_active": True, "email": "o@test"}
_VIEWER = {"id": 3, "username": "viewer", "role": "viewer", "is_active": True, "email": "v@test"}

_SCAN_ID = "test-scan-001"
_FINDING_ID = "vuln-xss-001"
_TREE_ID = str(uuid.uuid4())
_LEAF_ID = str(uuid.uuid4())


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


_DB_PATCH = "backend.routers.proof.SessionLocal"
_PROOF_KEY_HEADER = {"X-Proof-Key": "proof_demo_key"}


# ═══════════════════════════════════════════════════════════════════
# Unit tests — ProofEngine crypto
# ═══════════════════════════════════════════════════════════════════


class TestProofEngineCrypto:
    def test_hash_finding_deterministic(self):
        finding = {"name": "XSS", "severity": "high", "module": "nuclei"}
        h1 = ProofEngine.hash_finding(finding)
        h2 = ProofEngine.hash_finding(finding)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest

    def test_hash_finding_different_for_different_input(self):
        f1 = {"name": "XSS", "severity": "high"}
        f2 = {"name": "SQLi", "severity": "critical"}
        assert ProofEngine.hash_finding(f1) != ProofEngine.hash_finding(f2)

    def test_build_merkle_tree_single_leaf(self):
        leaves = ["abc123"]
        root, levels = ProofEngine.build_merkle_tree(leaves)
        assert root == "abc123"
        assert len(levels) == 1

    def test_build_merkle_tree_two_leaves(self):
        leaves = ["aaa", "bbb"]
        root, levels = ProofEngine.build_merkle_tree(leaves)
        assert len(levels) == 2
        assert root == levels[-1][0]

    def test_build_merkle_tree_four_leaves(self):
        leaves = ["a", "b", "c", "d"]
        root, levels = ProofEngine.build_merkle_tree(leaves)
        assert len(levels) == 3  # leaves, mid, root
        assert len(levels[-1]) == 1

    def test_verify_leaf_valid(self):
        leaves = ["a", "b", "c", "d"]
        root, levels = ProofEngine.build_merkle_tree(leaves)
        for i in range(4):
            path = ProofEngine.get_merkle_path(i, levels)
            assert ProofEngine.verify_leaf(leaves[i], path, root) is True

    def test_verify_leaf_invalid_tampered(self):
        leaves = ["a", "b", "c", "d"]
        root, levels = ProofEngine.build_merkle_tree(leaves)
        path = ProofEngine.get_merkle_path(0, levels)
        assert ProofEngine.verify_leaf("tampered", path, root) is False

    def test_verify_leaf_odd_count(self):
        leaves = ["x", "y", "z"]
        root, levels = ProofEngine.build_merkle_tree(leaves)
        for i in range(3):
            path = ProofEngine.get_merkle_path(i, levels)
            assert ProofEngine.verify_leaf(leaves[i], path, root) is True


# ═══════════════════════════════════════════════════════════════════
# API tests — /api/proof/*
# ═══════════════════════════════════════════════════════════════════


def _mock_tree(scan_id=_SCAN_ID):
    t = MagicMock()
    t.id = _TREE_ID
    t.root_hash = "a" * 64
    t.leaves_count = 3
    t.created_at = "2026-02-27T12:00:00"
    t.scan_id = scan_id
    t.target = "10.0.0.1"
    return t


def _mock_leaf(finding_id=_FINDING_ID):
    l = MagicMock()
    l.id = _LEAF_ID
    l.finding_id = finding_id
    l.scan_id = _SCAN_ID
    l.target = "10.0.0.1"
    l.finding_hash = "b" * 64
    l.timestamp = "2026-02-27T12:00:00"
    l.signature = "c" * 64
    l.leaf_index = 0
    l.merkle_path = ["d" * 64]
    return l


class TestListTrees:
    def test_list_trees_empty(self):
        _as_admin()
        mock_db = MagicMock()
        mock_db.query.return_value.order_by.return_value.limit.return_value.all.return_value = []

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get("/api/proof/trees")
        assert r.status_code == 200
        assert r.json() == []

    def test_list_trees_with_data(self):
        _as_admin()
        mock_db = MagicMock()
        mock_db.query.return_value.order_by.return_value.limit.return_value.all.return_value = [
            _mock_tree(),
        ]

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get("/api/proof/trees")
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["root_hash"] == "a" * 64

    def test_list_trees_no_auth(self):
        r = client.get("/api/proof/trees")
        assert r.status_code == 401


class TestGetTree:
    def test_get_tree_found(self):
        _as_admin()
        mock_db = MagicMock()
        tree = _mock_tree()
        leaf = _mock_leaf()

        call_idx = [0]
        def side_effect(*args):
            idx = call_idx[0]
            call_idx[0] += 1
            m = MagicMock()
            if idx == 0:
                m.filter.return_value.first.return_value = tree
            else:
                m.filter.return_value.order_by.return_value.all.return_value = [leaf]
            return m
        mock_db.query.side_effect = side_effect

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get(f"/api/proof/trees/{_SCAN_ID}")
        assert r.status_code == 200
        data = r.json()
        assert data["root_hash"] == "a" * 64
        assert "leaves" in data
        assert len(data["leaves"]) == 1

    def test_get_tree_not_found(self):
        _as_admin()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get("/api/proof/trees/nonexistent")
        assert r.status_code == 404


class TestVerifyFinding:
    def test_verify_with_proof_key(self):
        mock_db = MagicMock()
        tree = _mock_tree()
        leaf = _mock_leaf()

        call_idx = [0]
        def side_effect(*args):
            idx = call_idx[0]
            call_idx[0] += 1
            m = MagicMock()
            if idx == 0:
                m.filter.return_value.first.return_value = tree
            else:
                m.filter.return_value.first.return_value = leaf
            return m
        mock_db.query.side_effect = side_effect

        with patch(_DB_PATCH, return_value=mock_db), \
                patch("backend.proof.ProofEngine.verify_leaf", return_value=True):
            r = client.get(
                f"/api/proof/verify/{_SCAN_ID}/{_FINDING_ID}",
                headers=_PROOF_KEY_HEADER,
            )
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is True
        assert "root_hash" in data

    def test_verify_invalid_key(self):
        r = client.get(
            f"/api/proof/verify/{_SCAN_ID}/{_FINDING_ID}",
            headers={"X-Proof-Key": "wrong_key"},
        )
        assert r.status_code == 403

    def test_verify_no_key(self):
        r = client.get(f"/api/proof/verify/{_SCAN_ID}/{_FINDING_ID}")
        assert r.status_code == 422  # Missing required header


class TestFeed:
    def test_feed_success(self):
        mock_db = MagicMock()
        mock_db.query.return_value.order_by.return_value.limit.return_value.all.return_value = [
            _mock_tree(),
        ]
        mock_db.query.return_value.count.return_value = 1

        with patch(_DB_PATCH, return_value=mock_db):
            r = client.get("/api/proof/feed", headers=_PROOF_KEY_HEADER)
        assert r.status_code == 200
        data = r.json()
        assert "scans" in data
        assert "total_sealed" in data
        assert "generated_at" in data

    def test_feed_invalid_key(self):
        r = client.get("/api/proof/feed", headers={"X-Proof-Key": "bad"})
        assert r.status_code == 403


class TestSealScan:
    def test_seal_viewer_forbidden(self):
        _as_viewer()
        r = client.post(f"/api/proof/seal/{_SCAN_ID}")
        assert r.status_code == 403

    def test_seal_success(self):
        _as_operator()
        mock_db = MagicMock()
        from backend.proof import MerkleTree
        from datetime import datetime, timezone

        mock_tree = MerkleTree(
            root_hash="e" * 64,
            leaves_count=5,
            created_at=datetime.now(timezone.utc),
            scan_id=_SCAN_ID,
            target="10.0.0.1",
        )

        with patch(_DB_PATCH, return_value=mock_db), \
                patch("backend.routers.proof.ProofEngine") as MockEngine:
            MockEngine.return_value.seal_scan.return_value = mock_tree
            r = client.post(f"/api/proof/seal/{_SCAN_ID}")
        assert r.status_code == 200
        data = r.json()
        assert data["root_hash"] == "e" * 64
        assert data["leaves_count"] == 5

    def test_seal_not_found(self):
        _as_admin()
        mock_db = MagicMock()

        with patch(_DB_PATCH, return_value=mock_db), \
                patch("backend.routers.proof.ProofEngine") as MockEngine:
            MockEngine.return_value.seal_scan.side_effect = ValueError("Scan test not found")
            r = client.post("/api/proof/seal/nonexistent")
        assert r.status_code == 404

    def test_seal_already_sealed(self):
        _as_admin()
        mock_db = MagicMock()

        with patch(_DB_PATCH, return_value=mock_db), \
                patch("backend.routers.proof.ProofEngine") as MockEngine:
            MockEngine.return_value.seal_scan.side_effect = ValueError("Scan x already sealed")
            r = client.post(f"/api/proof/seal/{_SCAN_ID}")
        assert r.status_code == 409
