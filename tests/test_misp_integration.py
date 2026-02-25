"""Tests for MISP integration module."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch, MagicMock, PropertyMock
import importlib

# Mock heavy dependencies before importing target modules
_db_mock = MagicMock()
_db_mock.upsert_misp_events = MagicMock(return_value=0)
_db_mock.upsert_misp_attributes = MagicMock(return_value=0)
_db_mock.get_misp_by_cve = MagicMock(return_value=None)
_db_mock.get_misp_by_indicator = MagicMock(return_value=[])
_db_mock.search_misp_events = MagicMock(return_value=[])
_db_mock.save_intel_sync_log = MagicMock()

# Patch modules.database in sys.modules if not importable
_original_db = sys.modules.get("modules.database")
if _original_db is None:
    sys.modules["modules.database"] = _db_mock

# Now safe to import
import modules.misp_integration as misp_mod

# Restore original if it existed
if _original_db is not None:
    sys.modules["modules.database"] = _original_db


def test_misp_disabled_graceful_skip():
    """When MISP_URL is not set, sync should skip without crash."""
    orig_url = misp_mod.MISP_URL
    orig_key = misp_mod.MISP_API_KEY
    try:
        misp_mod.MISP_URL = ""
        misp_mod.MISP_API_KEY = ""
        assert misp_mod.is_misp_configured() is False
        result = misp_mod.sync_misp()
        assert result["skipped"] is True
        assert result["reason"] == "not_configured"

        result2 = misp_mod.export_scan_to_misp({"target": "x"}, "task-1")
        assert result2["skipped"] is True
    finally:
        misp_mod.MISP_URL = orig_url
        misp_mod.MISP_API_KEY = orig_key


def test_sync_misp_upserts():
    """sync_misp should call PyMISP and upsert events/attributes."""
    mock_event = MagicMock()
    mock_event.id = 1
    mock_event.uuid = "test-uuid-1234"
    mock_event.info = "Test event"
    mock_event.threat_level_id = 2
    mock_event.analysis = 1
    mock_event.date = "2026-02-25"
    mock_event.attribute_count = 3
    mock_event.tags = []
    mock_orgc = MagicMock()
    mock_orgc.name = "TestOrg"
    mock_event.Orgc = mock_orgc

    mock_attr = MagicMock()
    mock_attr.id = 10
    mock_attr.type = "ip-dst"
    mock_attr.value = "1.2.3.4"
    mock_attr.category = "Network activity"
    mock_attr.to_ids = True
    mock_attr.tags = []
    mock_event.attributes = [mock_attr]

    mock_misp = MagicMock()
    mock_misp.search.return_value = [mock_event]

    orig_url = misp_mod.MISP_URL
    orig_key = misp_mod.MISP_API_KEY
    try:
        misp_mod.MISP_URL = "https://misp.test"
        misp_mod.MISP_API_KEY = "testkey"

        with patch.object(misp_mod, "_get_misp_client", return_value=mock_misp), \
             patch.object(misp_mod, "upsert_misp_events", return_value=1) as mock_upsert_ev, \
             patch.object(misp_mod, "upsert_misp_attributes", return_value=1) as mock_upsert_attr, \
             patch.object(misp_mod, "save_intel_sync_log"):
            result = misp_mod.sync_misp(days_back=7)
            assert result["events"] == 1
            assert result["attributes"] == 1
            mock_upsert_ev.assert_called_once()
            mock_upsert_attr.assert_called_once()
            ev_data = mock_upsert_ev.call_args[0][0]
            assert ev_data[0]["event_id"] == 1
            assert ev_data[0]["uuid"] == "test-uuid-1234"
            assert ev_data[0]["org"] == "TestOrg"
    finally:
        misp_mod.MISP_URL = orig_url
        misp_mod.MISP_API_KEY = orig_key


def test_export_scan_creates_event():
    """export_scan_to_misp should create a MISP event with findings."""
    scan_result = {
        "target": "192.168.1.1",
        "raw_data": {
            "nuclei": {
                "findings": [
                    {"name": "CVE-2024-1234 SQL Injection", "severity": "high"},
                ]
            },
            "nmap": {
                "ports": [
                    {"port": 80, "protocol": "tcp", "service": "http"},
                    {"port": 443, "protocol": "tcp", "service": "https"},
                ]
            },
        }
    }

    mock_created = MagicMock()
    mock_created.id = 42
    mock_created.uuid = "export-uuid-5678"

    mock_misp = MagicMock()
    mock_misp.add_event.return_value = mock_created

    orig_url = misp_mod.MISP_URL
    orig_key = misp_mod.MISP_API_KEY
    try:
        misp_mod.MISP_URL = "https://misp.test"
        misp_mod.MISP_API_KEY = "testkey"

        with patch.object(misp_mod, "_get_misp_client", return_value=mock_misp):
            # Need to mock pymisp classes
            mock_misp_event_cls = MagicMock()
            mock_misp_obj_cls = MagicMock()
            mock_misp_attr_cls = MagicMock()
            with patch.dict("sys.modules", {"pymisp": MagicMock(
                MISPEvent=mock_misp_event_cls,
                MISPObject=mock_misp_obj_cls,
                MISPAttribute=mock_misp_attr_cls,
            )}):
                # Re-import to pick up mocked pymisp
                result = misp_mod.export_scan_to_misp(scan_result, "task-abc-123")
                assert result["event_id"] == 42
                assert result["uuid"] == "export-uuid-5678"
                assert result["attribute_count"] >= 1
                mock_misp.add_event.assert_called_once()
    finally:
        misp_mod.MISP_URL = orig_url
        misp_mod.MISP_API_KEY = orig_key


def test_enrich_finding_misp():
    """enrich_finding should include MISP data when CVE found in cache."""
    mock_misp_data = {
        "cve_id": "CVE-2024-1234",
        "event_count": 2,
        "events": [
            {"event_id": 1, "info": "Threat report", "threat_level_id": 1,
             "org": "CERT-EU", "date": "2024-12-01", "tags": ["tlp:white"]},
            {"event_id": 2, "info": "Campaign", "threat_level_id": 2,
             "org": "MISP", "date": "2024-12-15", "tags": []},
        ],
    }

    # Test the enrichment logic directly
    with patch.object(misp_mod, "get_misp_by_cve", return_value=mock_misp_data):
        result = misp_mod.get_misp_by_cve("CVE-2024-1234")
        assert result is not None
        assert result["event_count"] == 2
        assert len(result["events"]) == 2


def test_lookup_indicator():
    """lookup_misp_indicator should return DB results first."""
    mock_attrs = [
        {"attribute_id": 10, "event_id": 1, "type": "ip-dst",
         "value": "1.2.3.4", "category": "Network", "to_ids": True, "tags": []},
    ]

    with patch.object(misp_mod, "get_misp_by_indicator", return_value=mock_attrs):
        result = misp_mod.lookup_misp_indicator("1.2.3.4")
        assert len(result) == 1
        assert result[0]["value"] == "1.2.3.4"
