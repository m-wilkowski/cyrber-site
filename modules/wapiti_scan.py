import subprocess
import json
import os
import re
from datetime import datetime


def wapiti_scan(target: str) -> dict:
    """
    Scan target with Wapiti web application vulnerability scanner.

    Returns:
        {
            "target": str,
            "vulnerabilities": list,
            "summary": {"total": int, "critical": int, "high": int, "medium": int, "low": int},
            "infos": {"target": str, "date": str, "scope": str}
        }
    """
    url = target if target.startswith("http") else f"http://{target}"
    safe_name = re.sub(r'[^\w\-.]', '_', target)
    json_out = f"/tmp/wapiti_{safe_name}.json"

    # Clean up previous output
    if os.path.exists(json_out):
        os.remove(json_out)

    try:
        subprocess.run(
            [
                "wapiti",
                "-u", url,
                "-f", "json",
                "-o", json_out,
                "--flush-session",
                "--timeout", "30",
                "--max-scan-time", "300",
            ],
            capture_output=True,
            text=True,
            timeout=360,
        )
    except FileNotFoundError:
        return {"skipped": True, "reason": "wapiti not installed"}
    except subprocess.TimeoutExpired:
        pass  # still try to parse partial results

    if not os.path.exists(json_out):
        return {"skipped": True, "reason": "No Wapiti output generated"}

    try:
        with open(json_out, "r") as f:
            data = json.load(f)
    except Exception:
        return {"skipped": True, "reason": "Failed to parse Wapiti JSON output"}
    finally:
        try:
            os.remove(json_out)
        except OSError:
            pass

    vulnerabilities = []
    summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    # Wapiti JSON: {"vulnerabilities": {"category_name": [...]}, "infos": {...}}
    vuln_categories = data.get("vulnerabilities", {})
    if isinstance(vuln_categories, dict):
        for category_name, items in vuln_categories.items():
            if not isinstance(items, list):
                continue
            for item in items:
                level = item.get("level", "0")
                # Wapiti levels: 1=Low, 2=Medium, 3=High; map to severity
                level_map = {"1": "Low", "2": "Medium", "3": "High"}
                severity = level_map.get(str(level), "Medium")

                wstg_refs = []
                for ref in item.get("wstg", item.get("references", {}).get("wstg", [])) or []:
                    if isinstance(ref, str):
                        wstg_refs.append(ref)

                vuln = {
                    "name": category_name,
                    "level": severity,
                    "url": item.get("path", item.get("url", "")),
                    "method": item.get("http_request", "").split(" ")[0] if item.get("http_request") else item.get("method", ""),
                    "parameter": item.get("parameter", ""),
                    "info": item.get("info", item.get("description", "")),
                    "solution": item.get("solution", item.get("remediation", "")),
                    "wstg": wstg_refs,
                }
                vulnerabilities.append(vuln)

                sev_key = severity.lower()
                if sev_key in summary:
                    summary[sev_key] += 1
                summary["total"] += 1

    # Check anomalies section too
    anomalies = data.get("anomalies", {})
    if isinstance(anomalies, dict):
        for category_name, items in anomalies.items():
            if not isinstance(items, list):
                continue
            for item in items:
                level = item.get("level", "0")
                level_map = {"1": "Low", "2": "Medium", "3": "High"}
                severity = level_map.get(str(level), "Low")

                vuln = {
                    "name": f"{category_name} (anomaly)",
                    "level": severity,
                    "url": item.get("path", item.get("url", "")),
                    "method": item.get("http_request", "").split(" ")[0] if item.get("http_request") else item.get("method", ""),
                    "parameter": item.get("parameter", ""),
                    "info": item.get("info", ""),
                    "solution": item.get("solution", ""),
                    "wstg": [],
                }
                vulnerabilities.append(vuln)

                sev_key = severity.lower()
                if sev_key in summary:
                    summary[sev_key] += 1
                summary["total"] += 1

    # Mark criticals: SQL Injection, Command Execution, SSRF with High level -> Critical
    critical_categories = ["SQL Injection", "Command execution", "SSRF", "XXE"]
    for v in vulnerabilities:
        if v["level"] == "High" and any(c.lower() in v["name"].lower() for c in critical_categories):
            v["level"] = "Critical"
            summary["high"] -= 1
            summary["critical"] += 1

    # Sort by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    vulnerabilities.sort(key=lambda x: sev_order.get(x["level"], 4))

    infos = data.get("infos", {})
    scan_infos = {
        "target": infos.get("target", url),
        "date": infos.get("date", datetime.utcnow().isoformat()),
        "scope": infos.get("scope", ""),
    }

    return {
        "target": target,
        "vulnerabilities": vulnerabilities,
        "summary": summary,
        "infos": scan_infos,
    }
