"""
CYRBER MISP Integration — bidirectional sync with MISP threat intel platform.
Import IOCs from MISP, export scan findings as MISP events.
Enterprise tier. Graceful skip when MISP_URL not configured.
"""
import os
import time
import logging
from datetime import datetime, timedelta

from modules.database import (
    upsert_misp_events, upsert_misp_attributes,
    get_misp_by_cve, get_misp_by_indicator,
    save_intel_sync_log,
)

log = logging.getLogger("cyrber.misp")

MISP_URL = os.getenv("MISP_URL", "")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
MISP_PUBLISH = os.getenv("MISP_PUBLISH", "false").lower() == "true"
MISP_TLP = os.getenv("MISP_TLP", "tlp:amber")


def is_misp_configured() -> bool:
    return bool(MISP_URL and MISP_API_KEY)


def _get_misp_client():
    """Create PyMISP client. Import here to avoid hard dependency."""
    from pymisp import PyMISP
    return PyMISP(MISP_URL, MISP_API_KEY, ssl=MISP_VERIFY_SSL)


def sync_misp(days_back: int = 7) -> dict:
    """Sync recent MISP events + attributes into local cache."""
    if not is_misp_configured():
        log.info("MISP not configured — skipping sync")
        return {"skipped": True, "reason": "not_configured"}

    t0 = time.time()
    try:
        misp = _get_misp_client()
        since = (datetime.now(tz=None) - timedelta(days=days_back)).strftime("%Y-%m-%d")
        log.info(f"MISP sync: fetching events since {since}...")

        results = misp.search(controller="events", date_from=since,
                              limit=500, pythonify=True)

        events_data = []
        attrs_data = []

        for event in results:
            ev = {
                "event_id": int(event.id),
                "uuid": event.uuid,
                "info": event.info,
                "threat_level_id": int(event.threat_level_id),
                "analysis": int(event.analysis),
                "date": str(event.date),
                "org": event.Orgc.name if hasattr(event, "Orgc") and event.Orgc else "",
                "tags": [t.name for t in (event.tags or [])],
                "attribute_count": int(event.attribute_count) if event.attribute_count else 0,
            }
            events_data.append(ev)

            for attr in (event.attributes or []):
                attrs_data.append({
                    "attribute_id": int(attr.id),
                    "event_id": int(event.id),
                    "type": attr.type,
                    "value": attr.value,
                    "category": attr.category,
                    "to_ids": bool(attr.to_ids),
                    "tags": [t.name for t in (attr.tags or [])],
                })

        ev_count = upsert_misp_events(events_data)
        attr_count = upsert_misp_attributes(attrs_data)

        duration = time.time() - t0
        save_intel_sync_log("MISP", "success", ev_count, duration)
        log.info(f"MISP sync complete: {ev_count} events, {attr_count} attributes in {duration:.1f}s")

        return {"events": ev_count, "attributes": attr_count, "duration": round(duration, 1)}

    except Exception as exc:
        duration = time.time() - t0
        save_intel_sync_log("MISP", "error", 0, duration, str(exc))
        log.error(f"MISP sync failed: {exc}")
        raise


def export_scan_to_misp(scan_result: dict, task_id: str) -> dict:
    """Export scan findings as a MISP event with typed objects."""
    if not is_misp_configured():
        return {"skipped": True, "reason": "not_configured"}

    from pymisp import MISPEvent, MISPObject, MISPAttribute

    misp = _get_misp_client()
    event = MISPEvent()
    event.info = f"CYRBER Scan: {scan_result.get('target', 'unknown')} [{task_id[:8]}]"
    event.threat_level_id = _severity_to_threat_level(scan_result)
    event.analysis = 2  # completed
    event.add_tag(MISP_TLP)
    event.add_tag("cyrber:auto-export")

    target = scan_result.get("target", "")
    if target:
        event.add_attribute("ip-dst", target, comment="Scan target")

    attr_count = 0

    # nuclei CVEs → vulnerability objects
    for finding in _extract_findings(scan_result, "nuclei"):
        cve = _extract_cve(finding)
        if cve:
            vuln = MISPObject("vulnerability")
            vuln.add_attribute("id", cve)
            vuln.add_attribute("summary", finding.get("name", finding.get("info", "")))
            severity = finding.get("severity", "medium")
            vuln.add_attribute("cvss-score", _severity_to_cvss(severity))
            vuln.comment = f"Detected by Nuclei ({severity})"
            event.add_object(vuln)
            attr_count += 1

    # nmap ports → ip-port objects
    for port_info in _extract_ports(scan_result):
        ip_port = MISPObject("ip-port")
        ip_port.add_attribute("ip", target)
        ip_port.add_attribute("dst-port", str(port_info["port"]))
        ip_port.add_attribute("protocol", port_info.get("protocol", "tcp"))
        if port_info.get("service"):
            ip_port.add_attribute("text", port_info["service"])
        event.add_object(ip_port)
        attr_count += 1

    # testssl findings → x509 objects
    for cert_info in _extract_ssl_findings(scan_result):
        x509 = MISPObject("x509")
        if cert_info.get("subject"):
            x509.add_attribute("subject", cert_info["subject"])
        if cert_info.get("issuer"):
            x509.add_attribute("issuer", cert_info["issuer"])
        if cert_info.get("serial"):
            x509.add_attribute("serial-number", cert_info["serial"])
        x509.comment = cert_info.get("finding", "SSL/TLS finding")
        event.add_object(x509)
        attr_count += 1

    # zap alerts → vulnerability attributes
    for alert in _extract_findings(scan_result, "zap"):
        attr = MISPAttribute()
        attr.type = "vulnerability"
        attr.value = alert.get("name", alert.get("alert", "ZAP finding"))
        attr.comment = f"ZAP: {alert.get('risk', 'medium')} - {alert.get('url', '')}"
        event.add_attribute(**{"type": attr.type, "value": attr.value, "comment": attr.comment})
        attr_count += 1

    created = misp.add_event(event, pythonify=True)

    if MISP_PUBLISH:
        misp.publish(created)

    return {
        "event_id": int(created.id),
        "uuid": created.uuid,
        "attribute_count": attr_count,
        "url": f"{MISP_URL}/events/view/{created.id}",
    }


def lookup_misp_indicator(value: str, attr_type: str | None = None) -> list[dict]:
    """Lookup indicator: DB-first, fallback to live MISP search."""
    # DB lookup
    results = get_misp_by_indicator(value)
    if results:
        return results

    # Live fallback
    if not is_misp_configured():
        return []

    try:
        misp = _get_misp_client()
        search_args = {"value": value, "limit": 20, "pythonify": True}
        if attr_type:
            search_args["type_attribute"] = attr_type
        attrs = misp.search(controller="attributes", **search_args)
        return [
            {"attribute_id": int(a.id), "event_id": int(a.event_id),
             "type": a.type, "value": a.value, "category": a.category,
             "to_ids": bool(a.to_ids), "tags": [t.name for t in (a.tags or [])]}
            for a in attrs
        ]
    except Exception as exc:
        log.warning(f"MISP live lookup failed: {exc}")
        return []


# ── Helpers ──────────────────────────────────────────────────────

def _severity_to_threat_level(scan_result: dict) -> int:
    """Map scan severity to MISP threat level (1=high, 2=medium, 3=low, 4=undefined)."""
    raw = scan_result.get("raw_data", {})
    findings = []
    for mod in raw.values():
        if isinstance(mod, dict):
            findings.extend(mod.get("findings", []))
        elif isinstance(mod, list):
            findings.extend(mod)
    severities = [f.get("severity", "").lower() for f in findings if isinstance(f, dict)]
    if "critical" in severities or "high" in severities:
        return 1
    if "medium" in severities:
        return 2
    if "low" in severities:
        return 3
    return 4


def _severity_to_cvss(severity: str) -> str:
    return {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.5", "info": "0.0"}.get(
        severity.lower(), "5.0"
    )


def _extract_findings(scan_result: dict, module: str) -> list[dict]:
    raw = scan_result.get("raw_data", {})
    mod_data = raw.get(module, {})
    if isinstance(mod_data, dict):
        return mod_data.get("findings", [])
    if isinstance(mod_data, list):
        return mod_data
    return []


def _extract_cve(finding: dict) -> str | None:
    """Extract CVE ID from a finding dict."""
    import re
    for field in ("name", "info", "template_id", "matched_at", "description"):
        val = finding.get(field, "")
        if val:
            m = re.search(r"CVE-\d{4}-\d{4,7}", str(val))
            if m:
                return m.group()
    cve_list = finding.get("classification", {}).get("cve-id") if isinstance(finding.get("classification"), dict) else None
    if cve_list and isinstance(cve_list, list) and cve_list:
        return cve_list[0]
    return None


def _extract_ports(scan_result: dict) -> list[dict]:
    raw = scan_result.get("raw_data", {})
    nmap = raw.get("nmap", {})
    if isinstance(nmap, dict):
        ports = nmap.get("ports", nmap.get("open_ports", []))
        if isinstance(ports, list):
            return [p for p in ports if isinstance(p, dict) and "port" in p]
    return []


def _extract_ssl_findings(scan_result: dict) -> list[dict]:
    raw = scan_result.get("raw_data", {})
    ssl = raw.get("testssl", {})
    if isinstance(ssl, dict):
        findings = ssl.get("findings", [])
        return [f for f in findings if isinstance(f, dict)]
    return []
