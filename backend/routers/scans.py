"""Scan orchestration, history, reports, PDF, chains, narrative, autoflow, client report."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials
from sse_starlette.sse import EventSourceResponse
from datetime import datetime, timezone
import unicodedata
import re as _re
import html as _html
import json
import ipaddress

from backend.deps import (
    limiter, get_current_user, require_role, audit,
    bearer_scheme, _get_user_or_share_token, _get_user_from_token,
    REDIS_URL, _normalize_risk, _FINDING_NAMES, _FINDING_DESCS,
    _classify_finding, _NO_CACHE,
)
from backend.schemas import ScanStartRequest, MultiTargetScan
from modules.tasks import full_scan_task
from modules.scan_profiles import get_profiles_list, get_profile
from modules.database import (
    get_scan_history, get_scan_by_task_id, increment_scan_count,
    get_scans_this_month, get_remediation_tasks,
)
from modules.pdf_report import generate_report
from modules.compliance_map import generate_compliance_summary
from modules.exploit_chains import generate_exploit_chains
from modules.hacker_narrative import generate_hacker_narrative
from modules.license import check_profile, check_scan_limit

router = APIRouter(tags=["scans"])


@router.get("/scan/profiles")
async def scan_profiles(user: dict = Depends(get_current_user)):
    return get_profiles_list()


@router.post("/scan/start")
@limiter.limit("30/minute")
async def scan_start_post(request: Request, body: ScanStartRequest, user: dict = Depends(require_role("admin", "operator"))):
    if not get_profile(body.profile):
        raise HTTPException(status_code=400, detail=f"Invalid profile: {body.profile}")
    is_admin = user.get("role") == "admin"
    is_ci_profile = body.profile.upper() == "CI"
    if not is_admin and not is_ci_profile and not check_profile(body.profile.upper()):
        raise HTTPException(status_code=402, detail=f"Profile {body.profile.upper()} not available in your license tier")
    if not is_admin and not is_ci_profile and not check_scan_limit(get_scans_this_month()):
        raise HTTPException(status_code=402, detail="Monthly scan limit reached — upgrade your license")
    task = full_scan_task.delay(body.target, profile=body.profile.upper())
    increment_scan_count()
    audit(request, user, "scan_start", body.target)
    return {"task_id": task.id, "status": "started", "target": body.target, "profile": body.profile.upper()}


@router.get("/scan/start")
@limiter.limit("30/minute")
async def scan_start(request: Request, target: str = Query(...), profile: str = Query("STRAZNIK"), user: dict = Depends(require_role("admin", "operator"))):
    if not get_profile(profile):
        profile = "STRAZNIK"
    is_admin = user.get("role") == "admin"
    is_ci_profile = profile.upper() == "CI"
    if not is_admin and not is_ci_profile and not check_profile(profile.upper()):
        raise HTTPException(status_code=402, detail=f"Profile {profile.upper()} not available in your license tier")
    if not is_admin and not is_ci_profile and not check_scan_limit(get_scans_this_month()):
        raise HTTPException(status_code=402, detail="Monthly scan limit reached — upgrade your license")
    task = full_scan_task.delay(target, profile=profile.upper())
    increment_scan_count()
    audit(request, user, "scan_start", target)
    return {"task_id": task.id, "status": "started", "target": target, "profile": profile.upper()}


@router.get("/scan/status/{task_id}")
async def scan_status(task_id: str, user: dict = Depends(get_current_user)):
    task = full_scan_task.AsyncResult(task_id)
    if task.state == "PENDING":
        return {"task_id": task_id, "status": "pending"}
    elif task.state == "SUCCESS":
        return {"task_id": task_id, "status": "completed", "result": task.result}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "failed", "error": str(task.info)}
    else:
        return {"task_id": task_id, "status": task.state}


@router.get("/scan/stream/{task_id}")
async def scan_stream(task_id: str, token: str = Query(...)):
    import redis.asyncio as aioredis
    import asyncio as _asyncio

    _get_user_from_token(token)
    _redis_url = REDIS_URL

    async def event_generator():
        r = aioredis.from_url(_redis_url)
        pubsub = r.pubsub()
        await pubsub.subscribe(f"scan_progress:{task_id}")
        try:
            idle = 0
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message["type"] == "message":
                    data_str = message["data"].decode()
                    yield {"data": data_str}
                    idle = 0
                    if '"module": "complete"' in data_str:
                        break
                else:
                    idle += 1
                    if idle > 300:  # 5 minut timeout
                        break
                    await _asyncio.sleep(0.5)
        finally:
            await pubsub.unsubscribe(f"scan_progress:{task_id}")
            await r.aclose()

    return EventSourceResponse(event_generator())


@router.get("/scans")
async def scans_history(limit: int = 20, user: dict = Depends(get_current_user)):
    return get_scan_history(limit)


@router.get("/scans/{task_id}")
async def scan_detail(task_id: str, user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{task_id}/pdf")
async def scan_pdf(request: Request, task_id: str, user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    pdf_bytes = generate_report(scan)
    audit(request, user, "pdf_download", scan.get("target"))
    raw_t = scan.get("target", "unknown")
    safe_t = unicodedata.normalize("NFKD", raw_t).encode("ascii", "ignore").decode("ascii")
    safe_t = _re.sub(r'[^\w\-.]', '_', safe_t).strip('_') or "scan"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cyrber_{safe_t}_{task_id[:8]}.pdf"}
    )


@router.get("/scans/{task_id}/chains")
async def scan_chains(task_id: str, user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("exploit_chains"):
        return {"target": scan["target"], "exploit_chains": scan["exploit_chains"], "cached": True}
    chains = generate_exploit_chains(scan)
    return chains


@router.get("/scans/{task_id}/narrative")
async def scan_narrative(task_id: str, user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("hacker_narrative"):
        return {"target": scan["target"], **scan["hacker_narrative"], "cached": True}
    narrative = generate_hacker_narrative(scan)
    return narrative


@router.get("/scan/{task_id}/autoflow")
async def scan_autoflow(task_id: str, user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    actions = []
    target = scan.get("target", "")
    risk = (scan.get("risk_level") or "").upper()
    risk_norm = risk.replace("Ą","A").replace("Ć","C").replace("Ę","E").replace("Ł","L") \
        .replace("Ń","N").replace("Ó","O").replace("Ś","S").replace("Ź","Z").replace("Ż","Z")

    # Collect all text for keyword matching
    nuclei_findings = []
    if scan.get("nuclei") and isinstance(scan["nuclei"], dict):
        nuclei_findings = scan["nuclei"].get("findings") or []
    finding_texts = " ".join(
        (f.get("name") or "") + " " + (f.get("template_id") or "") + " " +
        ((f.get("info") or {}).get("name") or "") + " " +
        ((f.get("info") or {}).get("description") or "")
        for f in nuclei_findings
    ).lower()
    summary = (scan.get("summary") or "").lower()
    top_issues = " ".join(scan.get("top_issues") or []).lower()
    all_text = finding_texts + " " + summary + " " + top_issues

    has_ad = bool(scan.get("bloodhound") or scan.get("certipy") or scan.get("netexec")
                  or scan.get("impacket") or scan.get("responder"))
    has_xss = "xss" in all_text or "cross-site scripting" in all_text
    has_phishing_signal = any(kw in all_text for kw in ["phishing", "email", "login", "credential", "smtp", "spf", "dmarc", "dkim"])
    has_sqli = "sql" in all_text and ("inject" in all_text or "sqli" in all_text or "sqlmap" in all_text)

    if has_xss:
        actions.append({
            "action": "beef", "label": "Launch BeEF Session",
            "reason": "XSS vulnerabilities detected — hook target browsers",
            "url": "/phishing?tab=beef&target=" + target,
            "icon": "hook", "priority": "high",
        })

    if has_phishing_signal:
        actions.append({
            "action": "phishing", "label": "Create Phishing Campaign",
            "reason": "Email/login infrastructure exposed — test user awareness",
            "url": "/phishing?target=" + target,
            "icon": "email", "priority": "high" if risk_norm in ("CRITICAL", "KRYTYCZNE", "HIGH", "WYSOKIE") else "medium",
        })

    has_login_page = any(kw in all_text for kw in ["login", "sign-in", "signin", "authenticate", "oauth", "sso"])
    has_https = "443" in str(scan.get("nmap", {}).get("ports", []))
    if has_login_page and has_https:
        actions.append({
            "action": "evilginx", "label": "Deploy Evilginx2 MITM Proxy",
            "reason": "Login page on HTTPS detected — intercept credentials with reverse proxy",
            "url": "/phishing?vector=evilginx&target=" + target,
            "icon": "shield", "priority": "high" if risk_norm in ("CRITICAL", "KRYTYCZNE", "HIGH", "WYSOKIE") else "medium",
        })

    if risk_norm in ("CRITICAL", "KRYTYCZNE", "HIGH", "WYSOKIE"):
        actions.append({
            "action": "report", "label": "Generate Client Report",
            "reason": risk + " risk level — document findings for stakeholders",
            "url": "/scans/" + task_id + "/pdf",
            "icon": "report", "priority": "high",
        })

    if has_sqli:
        actions.append({
            "action": "sqli", "label": "Deep SQL Injection Test",
            "reason": "SQL injection indicators found — run targeted sqlmap",
            "url": "/ui?target=" + target + "&profile=CERBER",
            "icon": "database", "priority": "high",
        })

    if has_ad:
        ad_modules = [m for m in ["bloodhound", "certipy", "netexec", "impacket", "responder"] if scan.get(m)]
        actions.append({
            "action": "ad_paths", "label": "View AD Attack Paths",
            "reason": "Active Directory findings from: " + ", ".join(ad_modules),
            "url": "/ui?task_id=" + task_id + "&section=bloodhound",
            "icon": "ad", "priority": "high",
        })

    actions.append({
        "action": "schedule", "label": "Schedule Follow-up Scan",
        "reason": "Monitor target for changes and new vulnerabilities",
        "url": "/scheduler?target=" + target,
        "icon": "schedule", "priority": "low",
    })

    return {"task_id": task_id, "target": target, "risk_level": risk, "actions": actions}


# ── Client report API (no auth — shareable link) ──

@router.get("/api/report/{task_id}")
async def api_report(task_id: str, token: str = Query(None),
                     credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    _get_user_or_share_token(task_id, token, credentials)
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    risk = _normalize_risk(scan.get("risk_level") or "LOW")
    narrative = scan.get("hacker_narrative") or {}

    nuclei_findings = []
    if scan.get("nuclei") and isinstance(scan["nuclei"], dict):
        nuclei_findings = scan["nuclei"].get("findings") or []

    client_findings = []
    critical_count = 0
    for f in nuclei_findings:
        sev = ((f.get("info") or {}).get("severity") or f.get("severity") or "info").lower()
        if sev not in ("critical", "high"):
            continue
        if sev == "critical":
            critical_count += 1
        raw_name = (f.get("info") or {}).get("name") or f.get("name") or f.get("template_id") or ""
        cat = _classify_finding(raw_name.lower())
        client_findings.append({
            "name": _FINDING_NAMES.get(cat, raw_name),
            "description": _FINDING_DESCS.get(cat, "A security issue was detected that requires analysis."),
            "severity": "critical" if sev == "critical" else "high",
        })

    seen = set()
    deduped = []
    for cf in client_findings:
        if cf["name"] not in seen:
            seen.add(cf["name"])
            deduped.append(cf)
    client_findings = deduped[:10]

    recs_text = scan.get("recommendations") or ""
    top_issues = scan.get("top_issues") or []
    recs_list = []
    for i, issue in enumerate(top_issues[:5]):
        pri = "URGENT" if i == 0 else "IMPORTANT" if i < 3 else "RECOMMENDED"
        time_est = "1-3 days" if i == 0 else "1-2 weeks" if i < 3 else "1 month"
        clean = issue.split(".")[0].split(" - ")[0].split(":")[0].strip()
        if len(clean) < 10:
            clean = issue[:120]
        recs_list.append({"priority": pri, "text": clean, "time": time_est})

    if not recs_list and recs_text:
        recs_list.append({"priority": "IMPORTANT", "text": recs_text[:200], "time": "-"})

    risk_norm = risk.replace("\u015a", "S").replace("\u015b", "S")
    is_crit = risk_norm in ("KRYTYCZNE", "CRITICAL")
    is_high = risk_norm in ("WYSOKIE", "HIGH")
    compliance = [
        {"name": "GDPR", "icon": "\U0001F6E1", "status": "Violation" if is_crit else "At Risk" if is_high else "Compliant"},
        {"name": "NIS2", "icon": "\U0001F3DB", "status": "Violation" if is_crit else "At Risk" if is_high else "Compliant"},
    ]

    return {
        "task_id": task_id,
        "target": scan.get("target", ""),
        "date": scan.get("completed_at") or scan.get("created_at"),
        "risk_level": risk,
        "findings_count": scan.get("findings_count") or 0,
        "critical_count": critical_count,
        "summary": scan.get("summary") or "",
        "executive_summary": narrative.get("executive_summary") or scan.get("summary") or "",
        "time_to_compromise": narrative.get("time_to_compromise"),
        "potential_loss": narrative.get("potential_loss"),
        "fix_cost": narrative.get("fix_cost"),
        "findings": client_findings,
        "recommendations_text": recs_text,
        "recommendations_list": recs_list,
        "compliance": compliance,
    }


# ── Compliance PDF ──

@router.get("/report/{task_id}/compliance")
async def compliance_pdf(task_id: str, token: str = Query(None),
                         credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    """Generate Compliance Evidence PDF (NIS2 / ISO 27001)."""
    _get_user_or_share_token(task_id, token, credentials)
    import hashlib
    from weasyprint import HTML

    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target = _html.escape(scan.get("target", "unknown"))
    risk_level = scan.get("risk_level", "N/A")
    findings_count = scan.get("findings_count", 0)
    created_at = scan.get("created_at", "")[:10] if scan.get("created_at") else "N/A"
    completed_at = scan.get("completed_at", "")[:10] if scan.get("completed_at") else "N/A"
    profile = _html.escape(scan.get("profile", "STRAZNIK"))
    safe_task_id = _html.escape(task_id)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc_hash = hashlib.sha256(f"{task_id}:{now_str}".encode()).hexdigest()

    raw = scan

    findings_list = []
    for f in (raw.get("nuclei", {}).get("findings", []) if isinstance(raw.get("nuclei"), dict) else []):
        name = (f.get("info", {}).get("name") if isinstance(f, dict) else "") or (f.get("name", "") if isinstance(f, dict) else str(f))
        sev = (f.get("info", {}).get("severity") if isinstance(f, dict) else "") or (f.get("severity", "info") if isinstance(f, dict) else "info")
        findings_list.append({"name": name, "severity": sev, "module": "nuclei"})
    for a in (raw.get("zap", {}).get("alerts", []) if isinstance(raw.get("zap"), dict) else []):
        if isinstance(a, dict):
            findings_list.append({"name": a.get("name") or a.get("alert", ""), "severity": a.get("risk", "info"), "module": "zap"})
    if isinstance(raw.get("sqlmap"), dict) and raw["sqlmap"].get("vulnerable"):
        findings_list.append({"name": "SQL Injection", "severity": "critical", "module": "sqlmap"})
    for f in (raw.get("testssl", {}).get("findings", []) if isinstance(raw.get("testssl"), dict) else []):
        if isinstance(f, dict):
            findings_list.append({"name": f.get("name") or f.get("id", ""), "severity": f.get("severity", "info"), "module": "testssl"})
    for f in (raw.get("nikto", {}).get("findings", []) if isinstance(raw.get("nikto"), dict) else []):
        if isinstance(f, dict):
            findings_list.append({"name": f.get("name") or f.get("msg", ""), "severity": "medium", "module": "nikto"})
    for mod_key in raw:
        if mod_key in ("nuclei", "zap", "sqlmap", "testssl", "nikto", "ai_analysis"):
            continue
        mod_data = raw[mod_key]
        if not isinstance(mod_data, dict):
            continue
        for f in mod_data.get("findings", []):
            if isinstance(f, dict) and f.get("name"):
                findings_list.append({"name": f["name"], "severity": f.get("severity", "info"), "module": mod_key})

    rem_tasks = get_remediation_tasks(task_id)
    summary = generate_compliance_summary(findings_list, rem_tasks)
    stats = summary["stats"]

    def _status_symbol(s):
        return {"OK": "✓", "PARTIAL": "~", "FAIL": "✗"}.get(s, "?")

    def _status_color(s):
        return {"OK": "#3ddc84", "PARTIAL": "#f5c518", "FAIL": "#ff4444"}.get(s, "#4a8fd4")

    def _overall_color(s):
        return {"COMPLIANT": "#3ddc84", "PARTIALLY COMPLIANT": "#f5c518", "NON-COMPLIANT": "#ff4444",
                "ZGODNY": "#3ddc84", "CZĘŚCIOWO ZGODNY": "#f5c518", "NIEZGODNY": "#ff4444"}.get(s, "#4a8fd4")

    def _sev_color(s):
        sl = (s or "").lower()
        return {"critical": "#ff4444", "high": "#ff8c00", "medium": "#f5c518", "low": "#3ddc84"}.get(sl, "#4a8fd4")

    def _rem_status_label(s):
        return {"open": "Open", "in_progress": "In Progress", "fixed": "Fixed", "verified": "Verified", "wontfix": "Accepted"}.get(s, s)

    nis2_rows = ""
    for r in summary["nis2_articles"]:
        sc = _status_color(r["status"])
        sym = _status_symbol(r["status"])
        detail = f'{r["findings_count"]} found, {r["fixed_count"]} fixed' if r["findings_count"] else "No vulnerabilities"
        nis2_rows += f"""<tr>
            <td style="color:{sc};font-weight:700;font-size:16px;text-align:center;width:30px">{sym}</td>
            <td class="mono" style="white-space:nowrap">{r["article"]}</td>
            <td>{r["requirement"]}</td>
            <td style="color:{sc}">{detail}</td>
        </tr>"""

    iso_rows = ""
    for r in summary["iso27001_controls"]:
        sc = _status_color(r["status"])
        sym = _status_symbol(r["status"])
        detail = f'{r["findings_count"]} found, {r["fixed_count"]} fixed' if r["findings_count"] else "No vulnerabilities"
        iso_rows += f"""<tr>
            <td style="color:{sc};font-weight:700;font-size:16px;text-align:center;width:30px">{sym}</td>
            <td class="mono" style="white-space:nowrap">{r["control"]}</td>
            <td>{r["name"]}</td>
            <td style="color:{sc}">{detail}</td>
        </tr>"""

    rem_rows = ""
    evidence_count = 0
    for t in rem_tasks:
        if t.get("status") not in ("fixed", "verified"):
            continue
        evidence_count += 1
        sev = t.get("finding_severity", "info")
        sc = _sev_color(sev)
        retest_status = t.get("retest_status") or "—"
        retest_badge = ""
        if retest_status == "passed":
            retest_badge = '<span style="color:#3ddc84;font-weight:700">✓ VERIFIED</span>'
        elif retest_status == "failed":
            retest_badge = '<span style="color:#ff4444;font-weight:700">✗ FAILED</span>'
        else:
            retest_badge = f'<span style="color:#4a8fd4">{retest_status}</span>'

        rem_rows += f"""<tr>
            <td><span style="color:{sc};font-weight:600">{(sev or 'info').upper()}</span></td>
            <td>{t.get("finding_name", "")}</td>
            <td class="mono">{(t.get("created_at") or "")[:10]}</td>
            <td class="mono">{(t.get("updated_at") or "")[:10]}</td>
            <td>{t.get("owner") or "—"}</td>
            <td>{_rem_status_label(t.get("status", ""))}</td>
            <td>{retest_badge}</td>
        </tr>"""

    if not rem_rows:
        rem_rows = '<tr><td colspan="7" style="text-align:center;color:#4a8fd4;padding:20px">No fixed vulnerabilities to present as evidence</td></tr>'

    gaps_html = ""
    if summary["gaps"]:
        gaps_html = "<div class='section'><div class='section-title'>// IDENTIFIED GAPS</div>"
        for g in summary["gaps"]:
            gaps_html += f"<div class='gap-item'>⚠ {g}</div>"
        gaps_html += "</div>"

    overall_color = _overall_color(summary["overall_status"])

    # NOTE: This is a very long HTML template — same as the original in main.py lines 460-667
    html_content = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Rajdhani', sans-serif; background:#080c18; color:#b8ccec; padding:0; font-size:13px; }}
  .mono {{ font-family: monospace; font-size:11px; }}
  .page {{ padding:40px; page-break-after:always; min-height:100vh; }}
  .page:last-child {{ page-break-after:auto; }}
  .cover {{ display:flex; flex-direction:column; justify-content:center; align-items:center; text-align:center; min-height:100vh; }}
  .cover-brand {{ font-size:48px; font-weight:700; letter-spacing:0.4em; color:#e8f0fc; margin-bottom:8px; }}
  .cover-sub {{ font-size:10px; color:#4a8fd4; letter-spacing:0.4em; margin-bottom:60px; }}
  .cover-title {{ font-size:22px; font-weight:600; color:#4a8fd4; letter-spacing:0.15em; margin-bottom:40px; border:1px solid rgba(74,143,212,0.3); padding:16px 40px; }}
  .cover-meta {{ font-size:11px; color:#4a8fd4; line-height:2.2; }}
  .cover-meta b {{ color:#e8f0fc; font-weight:600; }}
  .cover-hash {{ margin-top:40px; font-family:monospace; font-size:9px; color:rgba(74,143,212,0.4); word-break:break-all; max-width:500px; }}
  .cover-conf {{ margin-top:24px; font-size:9px; letter-spacing:0.3em; color:rgba(255,68,68,0.5); }}
  .header {{ border-bottom:2px solid #4a8fd4; padding-bottom:16px; margin-bottom:24px; display:flex; justify-content:space-between; align-items:flex-end; }}
  .brand {{ font-size:24px; font-weight:700; letter-spacing:0.3em; color:#e8f0fc; }}
  .brand-sub {{ font-size:8px; color:#4a8fd4; letter-spacing:0.3em; }}
  .page-title {{ font-size:10px; color:#4a8fd4; letter-spacing:0.2em; text-align:right; }}
  .section {{ margin-bottom:24px; }}
  .section-title {{ font-size:10px; color:#4a8fd4; letter-spacing:0.3em; border-bottom:1px solid rgba(74,143,212,0.2); padding-bottom:6px; margin-bottom:14px; }}
  .muted {{ color:#4a8fd4; font-size:11px; }}
  .overall-box {{ background:rgba(74,143,212,0.06); border:2px solid {overall_color}; padding:20px 28px; margin-bottom:24px; display:flex; justify-content:space-between; align-items:center; }}
  .overall-label {{ font-size:11px; color:#4a8fd4; letter-spacing:0.2em; }}
  .overall-value {{ font-size:28px; font-weight:700; color:{overall_color}; letter-spacing:0.15em; }}
  .overall-score {{ font-size:11px; color:#4a8fd4; text-align:right; }}
  .overall-score b {{ font-size:22px; color:{overall_color}; }}
  .stats-grid {{ display:flex; gap:16px; margin-bottom:24px; }}
  .stat-card {{ flex:1; background:rgba(74,143,212,0.04); border:1px solid rgba(74,143,212,0.15); padding:14px; text-align:center; }}
  .stat-value {{ font-size:24px; font-weight:700; color:#e8f0fc; }}
  .stat-label {{ font-size:9px; color:#4a8fd4; letter-spacing:0.15em; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; font-size:11px; margin-top:8px; }}
  th {{ text-align:left; font-size:9px; letter-spacing:0.15em; color:#4a8fd4; padding:8px; border-bottom:1px solid rgba(74,143,212,0.3); }}
  td {{ padding:8px; border-bottom:1px solid rgba(74,143,212,0.08); vertical-align:top; }}
  .gap-item {{ padding:8px 0; border-bottom:1px solid rgba(255,68,68,0.1); font-size:12px; color:#ff8c00; }}
  .methodology {{ font-size:12px; line-height:1.8; color:#b8ccec; }}
  .methodology b {{ color:#e8f0fc; }}
  .sign-box {{ border:1px solid rgba(74,143,212,0.2); padding:24px; margin-top:24px; text-align:center; }}
  .sign-hash {{ font-family:monospace; font-size:10px; color:#4a8fd4; word-break:break-all; margin:12px 0; }}
  .sign-note {{ font-size:10px; color:rgba(74,143,212,0.5); line-height:1.8; }}
  .footer {{ padding-top:16px; border-top:1px solid rgba(74,143,212,0.15); font-size:8px; color:rgba(74,143,212,0.3); text-align:center; letter-spacing:0.2em; margin-top:auto; }}
</style>
</head>
<body>

<div class="page cover">
  <div class="cover-brand">CYRBER</div>
  <div class="cover-sub">AUTONOMOUS SECURITY RECONNAISSANCE PLATFORM</div>
  <div class="cover-title">COMPLIANCE REPORT — NIS2 / ISO 27001</div>
  <div class="cover-meta">
    <b>TARGET:</b> {target}<br>
    <b>TEST DATE:</b> {created_at} — {completed_at}<br>
    <b>SCAN PROFILE:</b> {profile}<br>
    <b>REPORT DATE:</b> {now_str}<br>
    <b>FINDINGS:</b> {findings_count}<br>
  </div>
  <div class="cover-hash">DOCUMENT HASH: {doc_hash}</div>
  <div class="cover-conf">CONFIDENTIAL — AUTHORIZED PERSONNEL ONLY</div>
</div>

<div class="page">
  <div class="header">
    <div><div class="brand">CYRBER</div><div class="brand-sub">COMPLIANCE EVIDENCE</div></div>
    <div class="page-title">EXECUTIVE SUMMARY</div>
  </div>
  <div class="overall-box">
    <div>
      <div class="overall-label">OVERALL COMPLIANCE ASSESSMENT</div>
      <div class="overall-value">{summary["overall_status"]}</div>
    </div>
    <div class="overall-score">
      COMPLIANCE SCORE<br><b>{summary["compliance_score"]}%</b>
    </div>
  </div>
  <div class="section">
    <div class="section-title">// PURPOSE AND SCOPE</div>
    <div class="methodology">
      The purpose of this report is to provide compliance evidence for the requirements of
      <b>NIS2 Directive (2022/2555)</b> and <b>ISO/IEC 27001:2022</b>
      in the scope of information systems security.
      <br><br>
      The scope of testing covered target <b>{target}</b> using scan profile <b>{profile}</b>
      ({findings_count} scanning modules). The methodology is aligned with:
      <b>OWASP Testing Guide v4</b>, <b>PTES (Penetration Testing Execution Standard)</b>,
      <b>NIST SP 800-115</b>.
    </div>
  </div>
  <div class="section">
    <div class="section-title">// RESULTS</div>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-value">{findings_count}</div><div class="stat-label">FOUND</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#3ddc84">{stats["fixed"]}</div><div class="stat-label">FIXED</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#3ddc84">{stats["verified"]}</div><div class="stat-label">VERIFIED</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#ff4444">{stats["open"]}</div><div class="stat-label">OPEN</div></div>
    </div>
  </div>
  <div class="section">
    <div class="section-title">// NIS2 COMPLIANCE — OVERVIEW</div>
    <table>
      <thead><tr><th></th><th>ARTICLE</th><th>REQUIREMENT</th><th>STATUS</th></tr></thead>
      <tbody>{nis2_rows}</tbody>
    </table>
  </div>
  <div class="footer">CYRBER · COMPLIANCE EVIDENCE · CONFIDENTIAL · {now_str}</div>
</div>

<div class="page">
  <div class="header">
    <div><div class="brand">CYRBER</div><div class="brand-sub">COMPLIANCE EVIDENCE</div></div>
    <div class="page-title">ISO/IEC 27001:2022 — CONTROLS</div>
  </div>
  <div class="section">
    <div class="section-title">// ISO 27001 CONTROL DETAILS</div>
    <table>
      <thead><tr><th></th><th>CONTROL</th><th>NAME</th><th>STATUS</th></tr></thead>
      <tbody>{iso_rows}</tbody>
    </table>
  </div>
  {gaps_html}
  <div class="footer">CYRBER · COMPLIANCE EVIDENCE · CONFIDENTIAL · {now_str}</div>
</div>

<div class="page">
  <div class="header">
    <div><div class="brand">CYRBER</div><div class="brand-sub">COMPLIANCE EVIDENCE</div></div>
    <div class="page-title">REMEDIATION EVIDENCE</div>
  </div>
  <div class="section">
    <div class="section-title">// FIXED VULNERABILITIES ({evidence_count})</div>
    <table>
      <thead><tr>
        <th>SEVERITY</th><th>FINDING</th><th>FOUND</th><th>FIXED</th>
        <th>OWNER</th><th>STATUS</th><th>RETEST</th>
      </tr></thead>
      <tbody>{rem_rows}</tbody>
    </table>
  </div>
  <div class="footer">CYRBER · COMPLIANCE EVIDENCE · CONFIDENTIAL · {now_str}</div>
</div>

<div class="page">
  <div class="header">
    <div><div class="brand">CYRBER</div><div class="brand-sub">COMPLIANCE EVIDENCE</div></div>
    <div class="page-title">DIGITAL SIGNATURE</div>
  </div>
  <div class="sign-box">
    <div style="font-size:12px;color:#4a8fd4;letter-spacing:0.2em;margin-bottom:16px">HASH DOKUMENTU (SHA-256)</div>
    <div class="sign-hash">{doc_hash}</div>
    <div style="font-size:11px;color:#b8ccec;margin:16px 0">
      Generated: <b>{now_str}</b><br>
      Target: <b>{target}</b><br>
      Task ID: <b>{safe_task_id}</b>
    </div>
    <div class="sign-note">
      This document was automatically generated by the CYRBER platform.<br>
      Document integrity can be verified by comparing the SHA-256 hash:<br>
      <span style="font-family:monospace">sha256("{safe_task_id}:{now_str}") = {doc_hash}</span><br><br>
      This document serves as evidence of security testing<br>
      and can be presented to NIS2 and ISO 27001 auditors.
    </div>
  </div>
  <div class="footer">CYRBER · COMPLIANCE EVIDENCE · CONFIDENTIAL · {now_str}</div>
</div>

</body></html>"""

    pdf_bytes = HTML(string=html_content, base_url=".").write_pdf()

    safe_t = unicodedata.normalize("NFKD", target).encode("ascii", "ignore").decode("ascii")
    safe_t = _re.sub(r'[^\w\-.]', '_', safe_t).strip('_') or "scan"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cyrber_compliance_{safe_t}_{safe_task_id[:8]}.pdf"}
    )


# ── Multi-target scan ──

@router.post("/scan/multi")
@limiter.limit("5/minute")
async def multi_scan(request: Request, body: MultiTargetScan, user: dict = Depends(require_role("admin", "operator"))):
    if not body.targets:
        raise HTTPException(status_code=400, detail="targets list is empty")

    expanded = []
    for t in body.targets:
        try:
            network = ipaddress.ip_network(t, strict=False)
            if network.num_addresses > 256:
                raise HTTPException(status_code=400, detail=f"CIDR {t} too large, max /24")
            expanded.extend([str(ip) for ip in network.hosts()])
        except ValueError:
            expanded.append(t)

    if len(expanded) > 254:
        raise HTTPException(status_code=400, detail="max 254 targets per request")

    scan_profile = body.profile.upper() if get_profile(body.profile) else "STRAZNIK"
    is_admin = user.get("role") == "admin"
    if not is_admin and not check_profile(scan_profile):
        raise HTTPException(status_code=402, detail=f"Profile {scan_profile} not available in your license tier")
    current_scans = get_scans_this_month()
    if not is_admin and not check_scan_limit(current_scans + len(expanded) - 1):
        raise HTTPException(status_code=402, detail="Monthly scan limit would be exceeded — upgrade your license")
    tasks = []
    for target in expanded:
        task = full_scan_task.delay(target, profile=scan_profile)
        increment_scan_count()
        tasks.append({"task_id": task.id, "target": target, "status": "started", "profile": scan_profile})
    audit(request, user, "multi_scan", f"{len(expanded)} targets")
    return {"count": len(tasks), "tasks": tasks}
