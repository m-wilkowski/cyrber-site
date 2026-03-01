"""Generic webhook integration — POST JSON to any URL.

Works with Slack, Teams, Discord, custom endpoints.
Supports HMAC-SHA256 signature for request verification.
"""

import hashlib
import hmac
import json
import logging
import time
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from modules.integrations.base import BaseIntegration, IntegrationResult

_log = logging.getLogger("cyrber.integrations.webhook")

_MAX_RETRIES = 2
_TIMEOUT = 10


class WebhookIntegration(BaseIntegration):
    """Generic webhook — POST JSON with optional HMAC-SHA256 signature."""

    name = "webhook"

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self.webhook_url = cfg.get("webhook_url", "")
        self.webhook_secret = cfg.get("webhook_secret", "")
        self.timeout = int(cfg.get("timeout", _TIMEOUT))

    def _sign(self, payload: bytes) -> str:
        """Compute HMAC-SHA256 signature for the payload."""
        if not self.webhook_secret:
            return ""
        return hmac.new(
            self.webhook_secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()

    def _post(self, payload: dict) -> IntegrationResult:
        """POST JSON to webhook URL with retries."""
        if not self.webhook_url:
            return IntegrationResult(success=False, message="No webhook URL configured")

        data = json.dumps(payload, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        sig = self._sign(data)
        if sig:
            headers["X-CYRBER-Signature"] = sig

        last_error = ""
        for attempt in range(_MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(
                    self.webhook_url,
                    data=data,
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status < 400:
                        return IntegrationResult(
                            success=True,
                            message=f"HTTP {resp.status}",
                            details={"status_code": resp.status, "attempt": attempt + 1},
                        )
                    last_error = f"HTTP {resp.status}"
            except Exception as exc:
                last_error = str(exc)
                _log.warning(
                    "Webhook POST failed (attempt %d/%d): %s",
                    attempt + 1, _MAX_RETRIES + 1, exc,
                )
                if attempt < _MAX_RETRIES:
                    time.sleep(1)

        return IntegrationResult(
            success=False,
            message=f"Failed after {_MAX_RETRIES + 1} attempts: {last_error}",
        )

    def send_finding(
        self,
        finding: dict,
        org_id: int,
        mission_id: Optional[str] = None,
    ) -> IntegrationResult:
        """Send a finding as JSON webhook."""
        payload = {
            "source": "CYRBER",
            "event_type": "finding_detected",
            "severity": (finding.get("severity") or "INFO").upper(),
            "target": finding.get("target") or finding.get("host") or "",
            "finding": finding.get("name") or finding.get("title") or "",
            "cve_id": finding.get("cve_id") or finding.get("cve") or "",
            "organization_id": org_id,
            "mission_id": mission_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": finding.get("description") or finding.get("info") or "",
        }
        return self._post(payload)

    def send_mission_event(
        self,
        mission: dict,
        event_type: str,
    ) -> IntegrationResult:
        """Send a mission lifecycle event as JSON webhook."""
        payload = {
            "source": "CYRBER",
            "event_type": event_type,
            "severity": "INFO",
            "target": mission.get("target", ""),
            "organization_id": mission.get("organization_id", 0),
            "mission_id": mission.get("mission_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": f"MENS mission {event_type}",
        }
        return self._post(payload)

    def test_connection(self) -> dict:
        """Test webhook connectivity with a test payload."""
        if not self.webhook_url:
            return {"reachable": False, "error": "No webhook URL configured"}

        result = self._post({
            "source": "CYRBER",
            "event_type": "test",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "CYRBER integration test",
        })

        return {
            "reachable": result.success,
            "message": result.message,
            "url": self.webhook_url,
        }
