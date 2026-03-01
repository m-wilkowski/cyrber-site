"""Tests for CYRBER Integration Layer — ELS, Webhook, IntegrationManager."""

import hashlib
import hmac
import json
import socket
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, ANY

import pytest

from modules.integrations.base import BaseIntegration, IntegrationResult
from modules.integrations.els import ELSIntegration, _SEVERITY_MAP, _MISSION_EVENT_SEV
from modules.integrations.webhook import WebhookIntegration


# ── ELS CEF format tests ──


class TestELSCEFFormat:
    """CEF message generation."""

    def test_cef_critical_severity(self):
        els = ELSIntegration({"enabled": "true"})
        cef = els._build_cef("CVE-2021-44228", "Log4Shell", 10, {"src": "10.0.0.1"})
        assert cef.startswith("CEF:0|CYRBER|AdversaryReasoningPlatform|1.0|")
        assert "|Log4Shell|10|" in cef
        assert "src=10.0.0.1" in cef

    def test_cef_low_severity(self):
        els = ELSIntegration({"enabled": "true"})
        cef = els._build_cef("INFO-001", "Info finding", 1, {"msg": "test"})
        assert "|Info finding|1|" in cef

    def test_severity_mapping_all_levels(self):
        assert _SEVERITY_MAP["CRITICAL"] == 10
        assert _SEVERITY_MAP["HIGH"] == 7
        assert _SEVERITY_MAP["MEDIUM"] == 5
        assert _SEVERITY_MAP["LOW"] == 3
        assert _SEVERITY_MAP["INFO"] == 1

    def test_mission_event_severity(self):
        assert _MISSION_EVENT_SEV["mission_start"] == 3
        assert _MISSION_EVENT_SEV["mission_complete"] == 5
        assert _MISSION_EVENT_SEV["mission_abort"] == 7

    def test_cef_per_severity_finding(self):
        els = ELSIntegration({"enabled": "true"})
        for sev, num in _SEVERITY_MAP.items():
            finding = {"severity": sev, "name": f"test-{sev}", "target": "1.2.3.4"}
            with patch.object(els, "_send_syslog", return_value=True):
                result = els.send_finding(finding, org_id=1)
            assert result.success


class TestELSSyslog:
    """Syslog send behavior."""

    def test_send_finding_disabled(self):
        els = ELSIntegration({"enabled": "false"})
        result = els.send_finding({"severity": "HIGH", "name": "test"}, org_id=1)
        assert not result.success
        assert "disabled" in result.message

    def test_send_finding_syslog_network_error_no_exception(self):
        """Syslog failure should NOT raise, just log warning."""
        els = ELSIntegration({
            "enabled": "true",
            "syslog_host": "192.0.2.1",  # RFC 5737 test address
            "syslog_port": "1",
        })
        # UDP sendto to unreachable host — should not raise
        result = els.send_finding(
            {"severity": "CRITICAL", "name": "test", "target": "10.0.0.1"},
            org_id=1,
        )
        # Might succeed (UDP is fire-and-forget) or fail, but never raises
        assert isinstance(result, IntegrationResult)

    def test_send_mission_event_disabled(self):
        els = ELSIntegration({"enabled": "false"})
        result = els.send_mission_event({"target": "x"}, "mission_start")
        assert not result.success

    def test_send_mission_event_types(self):
        els = ELSIntegration({"enabled": "true"})
        for event_type in ("mission_start", "mission_complete", "mission_abort"):
            with patch.object(els, "_send_syslog", return_value=True) as mock_syslog:
                result = els.send_mission_event(
                    {"target": "10.0.0.1", "mission_id": "m1", "organization_id": 1},
                    event_type,
                )
            assert result.success
            cef_msg = mock_syslog.call_args[0][0]
            assert event_type.upper() in cef_msg

    def test_es_skip_when_host_empty(self):
        els = ELSIntegration({"enabled": "true", "es_host": ""})
        assert els.send_to_elasticsearch({"test": True}) is False

    def test_test_connection_disabled(self):
        els = ELSIntegration({"enabled": "false"})
        result = els.test_connection()
        assert result["enabled"] is False
        assert result["syslog"] is False
        assert result["elasticsearch"] is False

    def test_test_connection_returns_dict(self):
        els = ELSIntegration({"enabled": "true"})
        with patch.object(els, "_send_syslog", return_value=True):
            result = els.test_connection()
        assert isinstance(result, dict)
        assert "syslog" in result
        assert "elasticsearch" in result


# ── Webhook tests ──


class TestWebhook:
    """Webhook integration."""

    def test_hmac_signature_correct(self):
        wh = WebhookIntegration({"webhook_url": "http://localhost", "webhook_secret": "s3cret"})
        payload = b'{"test": true}'
        sig = wh._sign(payload)
        expected = hmac.new(b"s3cret", payload, hashlib.sha256).hexdigest()
        assert sig == expected

    def test_hmac_empty_secret(self):
        wh = WebhookIntegration({"webhook_url": "http://localhost", "webhook_secret": ""})
        assert wh._sign(b"data") == ""

    def test_no_url_configured(self):
        wh = WebhookIntegration({"webhook_url": ""})
        result = wh.send_finding({"severity": "HIGH", "name": "test"}, org_id=1)
        assert not result.success
        assert "No webhook URL" in result.message

    @patch("modules.integrations.webhook.urllib.request.urlopen")
    def test_send_finding_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        wh = WebhookIntegration({"webhook_url": "http://hooks.example.com/test"})
        result = wh.send_finding(
            {"severity": "CRITICAL", "name": "CVE-2021-44228", "target": "10.0.0.1"},
            org_id=1,
            mission_id="m-123",
        )
        assert result.success

        # Verify payload
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        body = json.loads(req.data)
        assert body["source"] == "CYRBER"
        assert body["event_type"] == "finding_detected"
        assert body["severity"] == "CRITICAL"

    @patch("modules.integrations.webhook.urllib.request.urlopen")
    def test_send_finding_with_signature(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        wh = WebhookIntegration({
            "webhook_url": "http://hooks.example.com/test",
            "webhook_secret": "my_secret",
        })
        result = wh.send_finding({"severity": "HIGH", "name": "test"}, org_id=1)
        assert result.success

        req = mock_urlopen.call_args[0][0]
        # urllib.Request normalizes header keys to title case
        assert "X-cyrber-signature" in req.headers or "X-CYRBER-Signature" in req.headers

    def test_test_connection_no_url(self):
        wh = WebhookIntegration({"webhook_url": ""})
        result = wh.test_connection()
        assert result["reachable"] is False


# ── IntegrationManager tests ──


class TestIntegrationManager:
    """IntegrationManager dispatching."""

    @patch("modules.integrations.IntegrationManager.get_integrations")
    def test_notify_finding_calls_all_active(self, mock_get):
        from modules.integrations import IntegrationManager

        mock_int1 = MagicMock(spec=BaseIntegration)
        mock_int1.name = "els"
        mock_int1.send_finding.return_value = IntegrationResult(success=True, message="OK")

        mock_int2 = MagicMock(spec=BaseIntegration)
        mock_int2.name = "webhook"
        mock_int2.send_finding.return_value = IntegrationResult(success=True, message="OK")

        mock_get.return_value = [mock_int1, mock_int2]

        # Reset singleton state for test isolation
        mgr = IntegrationManager.__new__(IntegrationManager)
        mgr._initialized = True
        mgr.get_integrations = mock_get

        results = mgr.notify_finding({"severity": "CRITICAL", "name": "test"}, org_id=1)
        assert len(results) == 2
        assert all(r.success for r in results)
        mock_int1.send_finding.assert_called_once()
        mock_int2.send_finding.assert_called_once()

    @patch("modules.integrations.IntegrationManager.get_integrations")
    def test_notify_finding_handles_error(self, mock_get):
        from modules.integrations import IntegrationManager

        mock_int = MagicMock(spec=BaseIntegration)
        mock_int.name = "broken"
        mock_int.send_finding.side_effect = RuntimeError("connection refused")
        mock_get.return_value = [mock_int]

        mgr = IntegrationManager.__new__(IntegrationManager)
        mgr._initialized = True
        mgr.get_integrations = mock_get

        results = mgr.notify_finding({"severity": "HIGH"}, org_id=1)
        assert len(results) == 1
        assert not results[0].success

    @patch("modules.integrations.IntegrationManager.get_integrations")
    def test_notify_mission_dispatches(self, mock_get):
        from modules.integrations import IntegrationManager

        mock_int = MagicMock(spec=BaseIntegration)
        mock_int.name = "webhook"
        mock_int.send_mission_event.return_value = IntegrationResult(success=True, message="OK")
        mock_get.return_value = [mock_int]

        mgr = IntegrationManager.__new__(IntegrationManager)
        mgr._initialized = True
        mgr.get_integrations = mock_get

        results = mgr.notify_mission(
            {"target": "10.0.0.1", "organization_id": 1, "mission_id": "m1"},
            "mission_complete",
        )
        assert len(results) == 1
        mock_int.send_mission_event.assert_called_once_with(
            {"target": "10.0.0.1", "organization_id": 1, "mission_id": "m1"},
            "mission_complete",
        )


# ── Factory test ──


class TestFactory:
    """create_integration factory."""

    def test_create_els(self):
        from modules.integrations import create_integration
        inst = create_integration("els", {"enabled": "true"})
        assert inst is not None
        assert inst.name == "energylogserver"

    def test_create_webhook(self):
        from modules.integrations import create_integration
        inst = create_integration("webhook", {"webhook_url": "http://test"})
        assert inst is not None
        assert inst.name == "webhook"

    def test_create_unknown(self):
        from modules.integrations import create_integration
        assert create_integration("nonexistent", {}) is None
