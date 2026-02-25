import os
import time
import requests

ZAP_BASE_URL = os.getenv("ZAP_BASE_URL", "http://zap:8090")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "cyrber-zap-key")

SPIDER_TIMEOUT = 300
ACTIVE_SCAN_TIMEOUT = 600
POLL_INTERVAL = 5


def _zap_get(path: str, params: dict = None) -> dict:
    params = params or {}
    params["apikey"] = ZAP_API_KEY
    r = requests.get(f"{ZAP_BASE_URL}{path}", params=params, timeout=15)
    r.raise_for_status()
    return r.json()


def zap_scan(target: str) -> dict:
    if not target.startswith("http"):
        target = f"http://{target}"

    # Check if ZAP is available
    try:
        _zap_get("/JSON/core/view/version/")
    except Exception:
        return {"skipped": True, "reason": "ZAP not available"}

    # Spider (crawl)
    try:
        resp = _zap_get("/JSON/spider/action/scan/", {"url": target, "maxChildren": "0", "recurse": "true", "subtreeOnly": "false"})
        spider_id = resp.get("scan", "0")
    except Exception as e:
        return {"skipped": True, "reason": f"Spider start failed: {e}"}

    start = time.time()
    while time.time() - start < SPIDER_TIMEOUT:
        try:
            status = _zap_get("/JSON/spider/view/status/", {"scanId": spider_id})
            progress = int(status.get("status", "0"))
            if progress >= 100:
                break
        except Exception:
            break
        time.sleep(POLL_INTERVAL)

    # Get spider results count
    try:
        spider_results = _zap_get("/JSON/spider/view/results/", {"scanId": spider_id})
        spider_urls_found = len(spider_results.get("results", []))
    except Exception:
        spider_urls_found = 0

    # Active Scan
    try:
        resp = _zap_get("/JSON/ascan/action/scan/", {"url": target, "recurse": "true", "inScopeOnly": "false"})
        scan_id = resp.get("scan", "0")
    except Exception as e:
        return {"skipped": True, "reason": f"Active scan start failed: {e}"}

    scan_progress = 0
    start = time.time()
    while time.time() - start < ACTIVE_SCAN_TIMEOUT:
        try:
            status = _zap_get("/JSON/ascan/view/status/", {"scanId": scan_id})
            scan_progress = int(status.get("status", "0"))
            if scan_progress >= 100:
                break
        except Exception:
            break
        time.sleep(POLL_INTERVAL)

    # Fetch alerts
    try:
        alerts_resp = _zap_get("/JSON/alert/view/alerts/", {"baseurl": target, "start": "0", "count": "500"})
        raw_alerts = alerts_resp.get("alerts", [])
    except Exception:
        raw_alerts = []

    # Filter out False Positives and build result
    risk_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    alerts = []
    summary = {"total": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}

    for a in raw_alerts:
        confidence = a.get("confidence", "")
        if confidence == "False Positive":
            continue

        risk = a.get("risk", "Informational")
        alert_entry = {
            "alert_name": a.get("alert", a.get("name", "")),
            "risk": risk,
            "confidence": confidence,
            "url": a.get("url", ""),
            "description": a.get("description", ""),
            "solution": a.get("solution", ""),
            "reference": a.get("reference", ""),
            "cweid": a.get("cweid", ""),
            "wascid": a.get("wascid", ""),
        }
        alerts.append(alert_entry)

        risk_lower = risk.lower()
        if risk_lower in summary:
            summary[risk_lower] += 1
        summary["total"] += 1

    # Sort: High -> Medium -> Low -> Informational
    alerts.sort(key=lambda x: risk_order.get(x["risk"], 4))

    return {
        "target": target,
        "alerts": alerts,
        "summary": summary,
        "spider_urls_found": spider_urls_found,
        "scan_progress": scan_progress,
    }
