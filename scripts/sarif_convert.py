#!/usr/bin/env python3
"""Convert CYRBER scan results to SARIF 2.1.0 format for GitHub Security tab."""

import hashlib
import json
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}

SEVERITY_TO_SCORE = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
    "informational": 0.5,
}


def _make_rule_id(name: str, module: str) -> str:
    """Create a stable rule ID from finding name and module."""
    slug = f"{module}/{name}".lower().replace(" ", "-")
    # Keep it readable but truncated if too long
    if len(slug) > 80:
        h = hashlib.md5(slug.encode()).hexdigest()[:8]
        slug = slug[:70] + "-" + h
    return slug


def _extract_findings(results: dict) -> list[dict]:
    """Normalize findings from all CYRBER scan modules into a flat list."""
    findings = []

    # Nuclei findings
    for f in results.get("nuclei", {}).get("findings", []):
        info = f.get("info", {})
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id") or []
        cwe_ids = classification.get("cwe-id") or []
        findings.append({
            "module": "nuclei",
            "name": info.get("name", "Unknown"),
            "severity": info.get("severity", "info").lower(),
            "description": info.get("description", ""),
            "url": f.get("matched-at", f.get("host", "")),
            "cve": cve_ids if isinstance(cve_ids, list) else [cve_ids] if cve_ids else [],
            "cwe": cwe_ids if isinstance(cwe_ids, list) else [cwe_ids] if cwe_ids else [],
            "reference": info.get("reference") or [],
        })

    # ZAP alerts
    for a in results.get("zap", {}).get("alerts", []):
        risk = a.get("risk", "Informational").lower()
        sev_map = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}
        cweid = a.get("cweid")
        findings.append({
            "module": "zap",
            "name": a.get("name", "Unknown"),
            "severity": sev_map.get(risk, "info"),
            "description": a.get("description", ""),
            "url": a.get("url", ""),
            "cve": [],
            "cwe": [f"CWE-{cweid}"] if cweid and str(cweid) != "0" else [],
            "reference": [],
        })

    # testssl findings
    for f in results.get("testssl", {}).get("findings", []):
        cve = f.get("cve")
        findings.append({
            "module": "testssl",
            "name": f.get("id", f.get("name", "Unknown")),
            "severity": f.get("severity", "info").lower(),
            "description": f.get("finding", ""),
            "url": results.get("target", ""),
            "cve": [cve] if cve else [],
            "cwe": [],
            "reference": [],
        })

    # SQLMap
    sqlmap = results.get("sqlmap", {})
    if sqlmap.get("vulnerable"):
        findings.append({
            "module": "sqlmap",
            "name": "SQL Injection",
            "severity": "critical",
            "description": f"SQL injection found: {sqlmap.get('injection_type', 'unknown')}",
            "url": sqlmap.get("target", results.get("target", "")),
            "cve": [],
            "cwe": ["CWE-89"],
            "reference": [],
        })

    # Generic module findings (gobuster, nikto, whatweb, wapiti, etc.)
    for mod_name in ("gobuster", "nikto", "whatweb", "wapiti", "wpscan",
                     "joomscan", "cmsmap", "droopescan", "retirejs"):
        mod_data = results.get(mod_name, {})
        if mod_data.get("skipped"):
            continue
        for f in mod_data.get("findings", []):
            findings.append({
                "module": mod_name,
                "name": f.get("name", f.get("id", "Unknown")),
                "severity": f.get("severity", "info").lower(),
                "description": f.get("description", f.get("finding", "")),
                "url": f.get("url", results.get("target", "")),
                "cve": [],
                "cwe": [],
                "reference": [],
            })

    return findings


def convert_to_sarif(results: dict) -> dict:
    """Convert CYRBER scan results to SARIF 2.1.0."""
    findings = _extract_findings(results)

    # Deduplicate rules
    rules_map: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for f in findings:
        rule_id = _make_rule_id(f["name"], f["module"])
        severity = f["severity"]
        level = SEVERITY_TO_LEVEL.get(severity, "note")
        score = SEVERITY_TO_SCORE.get(severity, 0.5)

        # Build tags
        tags = [f["module"]]
        for cwe in f["cwe"]:
            cwe_num = cwe.replace("CWE-", "") if cwe.startswith("CWE-") else cwe
            tags.append(f"external/cwe/CWE-{cwe_num}")

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f["name"],
                "shortDescription": {"text": f["name"]},
                "fullDescription": {"text": f["description"][:1000] or f["name"]},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "security-severity": str(score),
                    "tags": tags,
                },
            }

        result_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f["description"] or f["name"]},
        }

        if f["url"]:
            result_entry["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["url"]},
                },
            }]

        sarif_results.append(result_entry)

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CYRBER",
                    "informationUri": "https://github.com/m-wilkowski/cyrber-site",
                    "version": "1.0.0",
                    "rules": list(rules_map.values()),
                },
            },
            "results": sarif_results,
        }],
    }

    return sarif


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: sarif_convert.py <cyrber-results.json> [output.sarif]")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        data = json.load(f)
    sarif = convert_to_sarif(data)
    out = sys.argv[2] if len(sys.argv) > 2 else "cyrber.sarif"
    with open(out, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"SARIF written to {out}: {len(sarif['runs'][0]['results'])} results")
