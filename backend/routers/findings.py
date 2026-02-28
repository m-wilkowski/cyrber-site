"""Aggregated findings browser — cross-scan finding extraction, filtering, pagination."""

from fastapi import APIRouter, Depends, Query
import json

from backend.deps import get_current_user
from modules.database import SessionLocal, Scan

router = APIRouter(prefix="/api/findings", tags=["findings"])

_SEV_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _extract_findings(raw: dict, target: str, task_id: str, created_at, scan_id: int):
    """Extract normalised findings from a single scan's raw_data dict."""
    findings = []

    # nuclei
    for f in (raw.get("nuclei", {}).get("findings", []) if isinstance(raw.get("nuclei"), dict) else []):
        if not isinstance(f, dict):
            continue
        info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
        name = info.get("name") or f.get("name", "")
        sev = info.get("severity") or f.get("severity", "info")
        desc = info.get("description", "") or f.get("description", "")
        refs = info.get("reference", [])
        cve = ""
        if isinstance(refs, list):
            for r in refs:
                if isinstance(r, str) and r.upper().startswith("CVE-"):
                    cve = r.upper()
                    break
        if not cve:
            tags = info.get("tags", [])
            if isinstance(tags, list):
                for t in tags:
                    if isinstance(t, str) and t.upper().startswith("CVE-"):
                        cve = t.upper()
                        break
        cve = cve or f.get("cve", "")
        findings.append({
            "name": name, "severity": sev, "module": "nuclei",
            "description": desc, "remediation": info.get("remediation", ""),
            "cve": cve, "epss": f.get("epss", None),
            "target": target, "task_id": task_id, "scan_id": scan_id,
            "created_at": str(created_at) if created_at else "",
        })

    # zap
    for a in (raw.get("zap", {}).get("alerts", []) if isinstance(raw.get("zap"), dict) else []):
        if not isinstance(a, dict):
            continue
        findings.append({
            "name": a.get("name") or a.get("alert", ""), "severity": a.get("risk", "info"),
            "module": "zap",
            "description": a.get("description", ""), "remediation": a.get("solution", ""),
            "cve": a.get("cweid", ""), "epss": None,
            "target": target, "task_id": task_id, "scan_id": scan_id,
            "created_at": str(created_at) if created_at else "",
        })

    # sqlmap
    if isinstance(raw.get("sqlmap"), dict) and raw["sqlmap"].get("vulnerable"):
        findings.append({
            "name": "SQL Injection", "severity": "critical", "module": "sqlmap",
            "description": "Target is vulnerable to SQL injection.",
            "remediation": "Use parameterized queries / prepared statements.",
            "cve": "", "epss": None,
            "target": target, "task_id": task_id, "scan_id": scan_id,
            "created_at": str(created_at) if created_at else "",
        })

    # testssl
    for f in (raw.get("testssl", {}).get("findings", []) if isinstance(raw.get("testssl"), dict) else []):
        if not isinstance(f, dict):
            continue
        findings.append({
            "name": f.get("name") or f.get("id", ""), "severity": f.get("severity", "info"),
            "module": "testssl",
            "description": f.get("description", ""), "remediation": f.get("remediation", ""),
            "cve": f.get("cve", ""), "epss": None,
            "target": target, "task_id": task_id, "scan_id": scan_id,
            "created_at": str(created_at) if created_at else "",
        })

    # nikto
    for f in (raw.get("nikto", {}).get("findings", []) if isinstance(raw.get("nikto"), dict) else []):
        if not isinstance(f, dict):
            continue
        findings.append({
            "name": f.get("name") or f.get("msg", ""), "severity": "medium",
            "module": "nikto",
            "description": f.get("description", ""), "remediation": f.get("remediation", ""),
            "cve": f.get("cve", ""), "epss": None,
            "target": target, "task_id": task_id, "scan_id": scan_id,
            "created_at": str(created_at) if created_at else "",
        })

    # generic modules
    for mod_key in raw:
        if mod_key in ("nuclei", "zap", "sqlmap", "testssl", "nikto", "ai_analysis"):
            continue
        mod_data = raw[mod_key]
        if not isinstance(mod_data, dict):
            continue
        for f in mod_data.get("findings", []):
            if isinstance(f, dict) and f.get("name"):
                findings.append({
                    "name": f["name"], "severity": f.get("severity", "info"),
                    "module": mod_key,
                    "description": f.get("description", ""),
                    "remediation": f.get("remediation", ""),
                    "cve": f.get("cve", ""), "epss": f.get("epss", None),
                    "target": target, "task_id": task_id, "scan_id": scan_id,
                    "created_at": str(created_at) if created_at else "",
                })

    # normalise severity
    for f in findings:
        f["severity"] = (f["severity"] or "INFO").upper()

    return findings


@router.get("")
async def list_findings(
    severity: str = Query(None),
    module: str = Query(None),
    target: str = Query(None),
    search: str = Query(None),
    sort: str = Query("severity"),
    order: str = Query("desc"),
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    _user=Depends(get_current_user),
):
    db = SessionLocal()
    try:
        rows = (
            db.query(Scan.id, Scan.task_id, Scan.target, Scan.raw_data, Scan.created_at)
            .filter(Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .all()
        )
    finally:
        db.close()

    all_findings = []
    for row in rows:
        raw_text = row.raw_data
        if not raw_text:
            continue
        try:
            raw = json.loads(raw_text) if isinstance(raw_text, str) else raw_text
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(raw, dict):
            continue
        all_findings.extend(_extract_findings(raw, row.target, row.task_id, row.created_at, row.id))

    # assign sequential IDs
    for idx, f in enumerate(all_findings):
        f["id"] = idx + 1

    # filters
    if severity:
        sev_set = {s.strip().upper() for s in severity.split(",")}
        all_findings = [f for f in all_findings if f["severity"] in sev_set]
    if module:
        all_findings = [f for f in all_findings if f["module"] == module]
    if target:
        all_findings = [f for f in all_findings if f["target"] == target]
    if search:
        q = search.lower()
        all_findings = [f for f in all_findings if q in (f["name"] or "").lower() or q in (f["description"] or "").lower() or q in (f["cve"] or "").lower()]

    # sort
    if sort == "date":
        all_findings.sort(key=lambda f: f["created_at"] or "", reverse=(order == "desc"))
    elif sort == "epss":
        all_findings.sort(key=lambda f: float(f["epss"] or 0), reverse=(order == "desc"))
    else:
        all_findings.sort(key=lambda f: _SEV_WEIGHT.get(f["severity"], 0), reverse=(order == "desc"))

    total = len(all_findings)
    pages = max(1, (total + limit - 1) // limit)
    offset = (page - 1) * limit
    items = all_findings[offset:offset + limit]

    return {"total": total, "page": page, "pages": pages, "items": items}


@router.get("/targets")
async def list_targets(_user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = (
            db.query(Scan.target)
            .filter(Scan.status == "completed")
            .distinct()
            .order_by(Scan.target)
            .all()
        )
    finally:
        db.close()
    return [r.target for r in rows if r.target]


@router.get("/modules")
async def list_modules(_user=Depends(get_current_user)):
    """Return distinct module names found across all completed scans."""
    db = SessionLocal()
    try:
        rows = (
            db.query(Scan.raw_data)
            .filter(Scan.status == "completed")
            .all()
        )
    finally:
        db.close()

    modules_set = set()
    for row in rows:
        if not row.raw_data:
            continue
        try:
            raw = json.loads(row.raw_data) if isinstance(row.raw_data, str) else row.raw_data
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(raw, dict):
            continue
        for key in raw:
            if key == "ai_analysis":
                continue
            val = raw[key]
            if isinstance(val, dict) and (val.get("findings") or val.get("alerts") or val.get("vulnerable")):
                modules_set.add(key)
    return sorted(modules_set)
