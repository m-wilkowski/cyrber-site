"""Energy Logserver / Elasticsearch SIEM integration.

Sends findings and mission events via:
  1. Syslog (CEF format) — UDP or TCP
  2. Elasticsearch API — POST to daily index
"""

import json
import logging
import os
import socket
from datetime import datetime, timezone
from typing import Optional

from modules.integrations.base import BaseIntegration, IntegrationResult

_log = logging.getLogger("cyrber.integrations.els")

_SEVERITY_MAP = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 5,
    "LOW": 3,
    "INFO": 1,
}

_MISSION_EVENT_SEV = {
    "mission_start": 3,
    "mission_complete": 5,
    "mission_abort": 7,
}


class ELSIntegration(BaseIntegration):
    """Energy Logserver SIEM — CEF syslog + Elasticsearch."""

    name = "energylogserver"

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self.enabled = cfg.get("enabled", os.getenv("ELS_ENABLED", "false")).lower() == "true"
        self.syslog_host = cfg.get("syslog_host", os.getenv("ELS_SYSLOG_HOST", "127.0.0.1"))
        self.syslog_port = int(cfg.get("syslog_port", os.getenv("ELS_SYSLOG_PORT", "514")))
        self.syslog_protocol = cfg.get("syslog_protocol", os.getenv("ELS_SYSLOG_PROTOCOL", "udp")).lower()
        self.es_host = cfg.get("es_host", os.getenv("ELS_HOST", ""))
        self.es_port = int(cfg.get("es_port", os.getenv("ELS_PORT", "9200")))
        self.es_user = cfg.get("es_user", os.getenv("ELS_USER", "logstash"))
        self.es_password = cfg.get("es_password", os.getenv("ELS_PASSWORD", "logstash"))
        self.es_index_prefix = cfg.get("es_index_prefix", os.getenv("ELS_INDEX_PREFIX", "cyrber"))
        self.es_verify_ssl = cfg.get("es_verify_ssl", os.getenv("ELS_VERIFY_SSL", "false")).lower() == "true"

    def _build_cef(
        self,
        event_id: str,
        name: str,
        severity: int,
        extension: dict,
    ) -> str:
        """Build a CEF:0 formatted message."""
        ext_str = " ".join(f"{k}={v}" for k, v in extension.items() if v is not None)
        return (
            f"CEF:0|CYRBER|AdversaryReasoningPlatform|1.0|{event_id}|{name}|{severity}|{ext_str}"
        )

    def _send_syslog(self, msg: str) -> bool:
        """Send a message via syslog (UDP or TCP). Returns success."""
        try:
            sock_type = socket.SOCK_DGRAM if self.syslog_protocol == "udp" else socket.SOCK_STREAM
            with socket.socket(socket.AF_INET, sock_type) as sock:
                sock.settimeout(5)
                if self.syslog_protocol == "tcp":
                    sock.connect((self.syslog_host, self.syslog_port))
                    sock.sendall((msg + "\n").encode("utf-8"))
                else:
                    sock.sendto(msg.encode("utf-8"), (self.syslog_host, self.syslog_port))
            return True
        except Exception as exc:
            _log.warning("Syslog send failed (%s:%d): %s", self.syslog_host, self.syslog_port, exc)
            return False

    def send_to_elasticsearch(self, doc: dict) -> bool:
        """POST document to Elasticsearch daily index. Returns success."""
        if not self.es_host:
            return False

        try:
            import urllib.request
            import ssl

            today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
            index = f"{self.es_index_prefix}-findings-{today}"
            scheme = "https" if self.es_verify_ssl else "http"
            url = f"{scheme}://{self.es_host}:{self.es_port}/{index}/_doc"

            data = json.dumps(doc, default=str).encode("utf-8")

            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            # Basic auth
            if self.es_user:
                import base64
                credentials = base64.b64encode(
                    f"{self.es_user}:{self.es_password}".encode()
                ).decode()
                req.add_header("Authorization", f"Basic {credentials}")

            ctx = None
            if not self.es_verify_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                return resp.status in (200, 201)
        except Exception as exc:
            _log.warning("ES send failed (%s:%d): %s", self.es_host, self.es_port, exc)
            return False

    def send_finding(
        self,
        finding: dict,
        org_id: int,
        mission_id: Optional[str] = None,
    ) -> IntegrationResult:
        """Send a finding as CEF syslog + ES document."""
        if not self.enabled:
            return IntegrationResult(success=False, message="ELS disabled")

        severity_str = (finding.get("severity") or "INFO").upper()
        severity_int = _SEVERITY_MAP.get(severity_str, 1)
        finding_name = finding.get("name") or finding.get("title") or "Unknown"
        target = finding.get("target") or finding.get("host") or ""
        cve_id = finding.get("cve_id") or finding.get("cve") or ""
        epss = finding.get("epss") or ""
        module = finding.get("module") or finding.get("source") or ""
        description = finding.get("description") or finding.get("info") or ""

        ext = {
            "src": target,
            "dst": target,
            "cs1": cve_id,
            "cs1Label": "CVE",
            "cs2": str(epss),
            "cs2Label": "EPSS",
            "cs3": module,
            "cs3Label": "Module",
            "cs4": str(org_id),
            "cs4Label": "OrgID",
            "cs5": mission_id or "",
            "cs5Label": "MissionID",
            "msg": description[:500],
        }

        cef = self._build_cef(
            event_id=cve_id or "FINDING",
            name=finding_name,
            severity=severity_int,
            extension=ext,
        )

        syslog_ok = self._send_syslog(cef)

        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "finding_detected",
            "severity": severity_str,
            "severity_int": severity_int,
            "target": target,
            "finding_name": finding_name,
            "cve_id": cve_id,
            "epss": epss,
            "module": module,
            "organization_id": org_id,
            "mission_id": mission_id,
            "description": description[:2000],
        }
        es_ok = self.send_to_elasticsearch(doc)

        return IntegrationResult(
            success=syslog_ok or es_ok,
            message=f"syslog={'OK' if syslog_ok else 'FAIL'} es={'OK' if es_ok else 'SKIP'}",
            details={"syslog": syslog_ok, "elasticsearch": es_ok},
        )

    def send_mission_event(
        self,
        mission: dict,
        event_type: str,
    ) -> IntegrationResult:
        """Send a mission lifecycle event via CEF syslog."""
        if not self.enabled:
            return IntegrationResult(success=False, message="ELS disabled")

        severity_int = _MISSION_EVENT_SEV.get(event_type, 3)
        target = mission.get("target", "")
        mission_id = mission.get("mission_id", "")
        org_id = mission.get("organization_id", 0)

        ext = {
            "src": target,
            "dst": target,
            "cs4": str(org_id),
            "cs4Label": "OrgID",
            "cs5": mission_id,
            "cs5Label": "MissionID",
            "msg": f"MENS mission {event_type}",
        }

        cef = self._build_cef(
            event_id=event_type.upper(),
            name=f"MENS {event_type}",
            severity=severity_int,
            extension=ext,
        )

        syslog_ok = self._send_syslog(cef)

        return IntegrationResult(
            success=syslog_ok,
            message=f"syslog={'OK' if syslog_ok else 'FAIL'}",
            details={"syslog": syslog_ok},
        )

    def test_connection(self) -> dict:
        """Test syslog and ES connectivity."""
        result = {"syslog": False, "elasticsearch": False, "enabled": self.enabled}

        if not self.enabled:
            return result

        # Test syslog
        result["syslog"] = self._send_syslog(
            "CEF:0|CYRBER|AdversaryReasoningPlatform|1.0|TEST|Connection Test|1|msg=CYRBER integration test"
        )

        # Test ES
        if self.es_host:
            try:
                import urllib.request
                import ssl

                scheme = "https" if self.es_verify_ssl else "http"
                url = f"{scheme}://{self.es_host}:{self.es_port}/"
                req = urllib.request.Request(url, method="GET")
                ctx = None
                if not self.es_verify_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    result["elasticsearch"] = resp.status == 200
            except Exception as exc:
                _log.warning("ES test failed: %s", exc)

        return result
