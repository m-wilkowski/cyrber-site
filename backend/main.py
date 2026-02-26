from fastapi import FastAPI, Query, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from sse_starlette.sse import EventSourceResponse

_NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"}
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.hash import sha256_crypt
from datetime import datetime, timedelta, timezone
import sys
import os
import secrets
import ipaddress
import unicodedata
import json
import re as _re
import html as _html
import requests as http_requests
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan
from modules.llm_analyze import analyze_scan_results
from modules.tasks import full_scan_task
from modules.scan_profiles import get_profiles_list, get_profile

# ── Redis config ──
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# ── JWT config ──
_logger = logging.getLogger("cyrber")

def _load_jwt_secret() -> str:
    env_val = os.getenv("JWT_SECRET")
    if env_val:
        return env_val
    secret_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jwt_secret")
    if os.path.exists(secret_path):
        with open(secret_path) as f:
            return f.read().strip()
    _logger.warning("JWT_SECRET not set — generating and persisting to %s", secret_path)
    new_secret = secrets.token_hex(32)
    with open(secret_path, "w") as f:
        f.write(new_secret)
    return new_secret

JWT_SECRET = _load_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 8

bearer_scheme = HTTPBearer(auto_error=False)
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    """Returns dict with username, role, id, is_active from DB."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Account disabled")
    return user

def require_role(*allowed_roles: str):
    """Dependency factory: raises 403 if current user's role not in allowed_roles."""
    def _checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {', '.join(allowed_roles)}")
        return current_user
    return _checker

# ── App ──
app = FastAPI(title="CYRBER API", version="0.3.0")

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'self'"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.mount("/static", StaticFiles(directory="static"), name="static")

# ── Database ──
from modules.database import init_db, get_scan_history, get_scan_by_task_id
from modules.database import add_schedule, get_schedules, delete_schedule
from modules.database import save_audit_log, get_audit_logs
from modules.database import (
    User, get_user_by_username, get_user_by_username_raw, get_user_by_id,
    create_user, update_user, delete_user, list_users, count_admins,
    count_active_users, get_scans_this_month, increment_scan_count,
)
from modules.database import (
    RemediationTask, get_remediation_tasks, create_remediation_task,
    get_remediation_task_by_id, update_remediation_task,
    delete_remediation_task, bulk_create_remediation_tasks,
    get_remediation_stats,
)
from modules.database import (
    get_intel_sync_logs, get_intel_cache_counts,
    search_attack_techniques, get_attack_technique, get_attack_tactics,
    get_mitigations_for_technique, get_techniques_for_cwe, get_euvd_by_cve,
)
from modules.database import (
    get_scans_by_target, get_remediation_counts_for_scan,
    get_unique_targets_with_stats,
)
from modules.license import (
    get_license_info, check_profile, check_scan_limit, check_user_limit,
    check_feature, activate_license,
)
from modules.pdf_report import generate_report
from modules.compliance_map import generate_compliance_summary
from modules.exploit_chains import generate_exploit_chains
from modules.hacker_narrative import generate_hacker_narrative

init_db()

# ── Bootstrap default admin (if no users in DB) ──
if not get_user_by_username("admin"):
    _default_hash = sha256_crypt.hash(os.getenv("CYRBER_PASS", "cyrber2024"))
    create_user(
        username=os.getenv("CYRBER_USER", "admin"),
        password_hash=_default_hash,
        role="admin",
        created_by="system",
        notes="Default admin created at startup",
    )
    print("Bootstrap: created default admin user")
else:
    print("Bootstrap: admin user already exists, skipping")

# ── Audit helper ──
def audit(request: Request, user, action: str, target: str = None):
    username = user["username"] if isinstance(user, dict) else user
    ip = request.client.host if request.client else "unknown"
    save_audit_log(user=username, action=action, target=target, ip_address=ip)

# ── Public routes (no auth) ──

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
@limiter.limit("10/minute")
async def auth_login(request: Request, body: LoginRequest):
    ip = request.client.host if request.client else "unknown"
    user = get_user_by_username_raw(body.username)
    if user and user["is_active"] and sha256_crypt.verify(body.password, user["password_hash"]):
        token = create_token(user["username"], user["role"])
        update_user(user["id"], last_login=datetime.now(timezone.utc))
        save_audit_log(user=user["username"], action="login", ip_address=ip)
        return {
            "token": token, "token_type": "bearer",
            "expires_in": JWT_EXPIRE_HOURS * 3600,
            "role": user["role"], "username": user["username"],
        }
    save_audit_log(user=body.username, action="login_failed", ip_address=ip)
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/auth/me")
async def auth_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.get("/login")
async def login_page():
    return FileResponse("static/login.html")

@app.get("/command-center")
async def command_center():
    return FileResponse("static/command_center.html", headers=_NO_CACHE)

@app.get("/ui")
async def ui():
    return FileResponse("static/index.html", headers=_NO_CACHE)

@app.get("/dashboard")
async def dashboard():
    return FileResponse("static/dashboard.html", headers=_NO_CACHE)

@app.get("/scheduler")
async def scheduler():
    return FileResponse("static/scheduler.html", headers=_NO_CACHE)

@app.get("/phishing")
async def phishing_page():
    return FileResponse("static/phishing.html", headers=_NO_CACHE)

@app.get("/osint")
async def osint_page():
    return FileResponse("static/osint.html", media_type="text/html", headers=_NO_CACHE)

@app.get("/verify")
async def verify_page():
    return FileResponse("static/verify.html", headers=_NO_CACHE)

@app.get("/admin")
async def admin_page():
    return FileResponse("static/admin.html", headers=_NO_CACHE)

def _get_user_or_share_token(
    task_id: str,
    token: str = None,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """Authenticate via JWT header OR HMAC share token query param."""
    if credentials:
        try:
            return get_current_user(credentials)
        except HTTPException:
            pass
    if token:
        import hmac, hashlib
        expected = hmac.new(JWT_SECRET.encode(), task_id.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(token, expected):
            return {"username": "_shared_link", "role": "viewer"}
    raise HTTPException(status_code=401, detail="Not authenticated — provide JWT or valid share token")

@app.get("/report/{task_id}")
async def report_page(task_id: str, token: str = Query(None),
                      credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    _get_user_or_share_token(task_id, token, credentials)
    return FileResponse("static/report.html", headers=_NO_CACHE)

@app.get("/report/{task_id}/compliance")
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

    # Collect findings from scan data (already flattened by get_scan_by_task_id)
    raw = scan

    findings_list = []
    # Nuclei
    for f in (raw.get("nuclei", {}).get("findings", []) if isinstance(raw.get("nuclei"), dict) else []):
        name = (f.get("info", {}).get("name") if isinstance(f, dict) else "") or (f.get("name", "") if isinstance(f, dict) else str(f))
        sev = (f.get("info", {}).get("severity") if isinstance(f, dict) else "") or (f.get("severity", "info") if isinstance(f, dict) else "info")
        findings_list.append({"name": name, "severity": sev, "module": "nuclei"})
    # ZAP
    for a in (raw.get("zap", {}).get("alerts", []) if isinstance(raw.get("zap"), dict) else []):
        if isinstance(a, dict):
            findings_list.append({"name": a.get("name") or a.get("alert", ""), "severity": a.get("risk", "info"), "module": "zap"})
    # SQLMap
    if isinstance(raw.get("sqlmap"), dict) and raw["sqlmap"].get("vulnerable"):
        findings_list.append({"name": "SQL Injection", "severity": "critical", "module": "sqlmap"})
    # TestSSL
    for f in (raw.get("testssl", {}).get("findings", []) if isinstance(raw.get("testssl"), dict) else []):
        if isinstance(f, dict):
            findings_list.append({"name": f.get("name") or f.get("id", ""), "severity": f.get("severity", "info"), "module": "testssl"})
    # Nikto
    for f in (raw.get("nikto", {}).get("findings", []) if isinstance(raw.get("nikto"), dict) else []):
        if isinstance(f, dict):
            findings_list.append({"name": f.get("name") or f.get("msg", ""), "severity": "medium", "module": "nikto"})
    # Generic: iterate modules for findings lists
    for mod_key in raw:
        if mod_key in ("nuclei", "zap", "sqlmap", "testssl", "nikto", "ai_analysis"):
            continue
        mod_data = raw[mod_key]
        if not isinstance(mod_data, dict):
            continue
        for f in mod_data.get("findings", []):
            if isinstance(f, dict) and f.get("name"):
                findings_list.append({"name": f["name"], "severity": f.get("severity", "info"), "module": mod_key})

    # Remediation tasks
    rem_tasks = get_remediation_tasks(task_id)

    # Compliance summary
    summary = generate_compliance_summary(findings_list, rem_tasks)
    stats = summary["stats"]

    # Status colors
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

    # ── Build HTML ──
    # NIS2 table rows
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

    # ISO table rows
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

    # Remediation evidence rows (only fixed/verified)
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

    # Gaps section
    gaps_html = ""
    if summary["gaps"]:
        gaps_html = "<div class='section'><div class='section-title'>// IDENTIFIED GAPS</div>"
        for g in summary["gaps"]:
            gaps_html += f"<div class='gap-item'>⚠ {g}</div>"
        gaps_html += "</div>"

    overall_color = _overall_color(summary["overall_status"])

    html_content = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Rajdhani', sans-serif; background:#080c18; color:#b8ccec; padding:0; font-size:13px; }}
  .mono {{ font-family: monospace; font-size:11px; }}

  .page {{ padding:40px; page-break-after:always; min-height:100vh; }}
  .page:last-child {{ page-break-after:auto; }}

  /* ── Cover ── */
  .cover {{ display:flex; flex-direction:column; justify-content:center; align-items:center; text-align:center; min-height:100vh; }}
  .cover-brand {{ font-size:48px; font-weight:700; letter-spacing:0.4em; color:#e8f0fc; margin-bottom:8px; }}
  .cover-sub {{ font-size:10px; color:#4a8fd4; letter-spacing:0.4em; margin-bottom:60px; }}
  .cover-title {{ font-size:22px; font-weight:600; color:#4a8fd4; letter-spacing:0.15em; margin-bottom:40px; border:1px solid rgba(74,143,212,0.3); padding:16px 40px; }}
  .cover-meta {{ font-size:11px; color:#4a8fd4; line-height:2.2; }}
  .cover-meta b {{ color:#e8f0fc; font-weight:600; }}
  .cover-hash {{ margin-top:40px; font-family:monospace; font-size:9px; color:rgba(74,143,212,0.4); word-break:break-all; max-width:500px; }}
  .cover-conf {{ margin-top:24px; font-size:9px; letter-spacing:0.3em; color:rgba(255,68,68,0.5); }}

  /* ── Common ── */
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

<!-- ═══ PAGE 1: COVER ═══ -->
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

<!-- ═══ PAGE 2: EXECUTIVE SUMMARY ═══ -->
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
      <div class="stat-card">
        <div class="stat-value">{findings_count}</div>
        <div class="stat-label">FOUND</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:#3ddc84">{stats["fixed"]}</div>
        <div class="stat-label">FIXED</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:#3ddc84">{stats["verified"]}</div>
        <div class="stat-label">VERIFIED</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:#ff4444">{stats["open"]}</div>
        <div class="stat-label">OPEN</div>
      </div>
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

<!-- ═══ PAGE 3: ISO 27001 DETAILS ═══ -->
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

<!-- ═══ PAGE 4: REMEDIATION EVIDENCE ═══ -->
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

<!-- ═══ PAGE 5: DIGITAL SIGNATURE ═══ -->
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

@app.get("/scan/{task_id}/detail")
async def scan_detail_page(task_id: str):
    return FileResponse("static/scan_detail.html", headers=_NO_CACHE)

@app.get("/api/health")
async def health():
    return {"status": "ok"}

@app.get("/")
async def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/ui")

# ── Admin routes (admin only) ──

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    email: str = None
    notes: str = None

class UserUpdate(BaseModel):
    role: str = None
    email: str = None
    is_active: bool = None
    notes: str = None

class PasswordReset(BaseModel):
    new_password: str

@app.get("/admin/users")
async def admin_list_users(current_user: dict = Depends(require_role("admin"))):
    return list_users()

@app.post("/admin/users")
async def admin_create_user(request: Request, body: UserCreate, current_user: dict = Depends(require_role("admin"))):
    if not check_user_limit(count_active_users()):
        raise HTTPException(status_code=402, detail="User limit reached — upgrade your license")
    if body.role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be admin, operator, or viewer")
    if get_user_by_username(body.username):
        raise HTTPException(status_code=409, detail="Username already exists")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    hashed = sha256_crypt.hash(body.password)
    user = create_user(
        username=body.username, password_hash=hashed, role=body.role,
        email=body.email, created_by=current_user["username"], notes=body.notes,
    )
    audit(request, current_user, "user_create", body.username)
    return user

@app.get("/admin/users/{user_id}")
async def admin_get_user(user_id: int, current_user: dict = Depends(require_role("admin"))):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.put("/admin/users/{user_id}")
async def admin_update_user(request: Request, user_id: int, body: UserUpdate, current_user: dict = Depends(require_role("admin"))):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    updates = {}
    if body.role is not None:
        if body.role not in ("admin", "operator", "viewer"):
            raise HTTPException(status_code=400, detail="Role must be admin, operator, or viewer")
        # Prevent removing last admin
        if user["role"] == "admin" and body.role != "admin" and count_admins() <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove role from the last admin")
        updates["role"] = body.role
    if body.email is not None:
        updates["email"] = body.email
    if body.is_active is not None:
        # Prevent disabling last admin
        if user["role"] == "admin" and not body.is_active and count_admins() <= 1:
            raise HTTPException(status_code=400, detail="Cannot disable the last admin")
        updates["is_active"] = body.is_active
    if body.notes is not None:
        updates["notes"] = body.notes
    result = update_user(user_id, **updates)
    audit(request, current_user, "user_update", user["username"])
    return result

@app.delete("/admin/users/{user_id}")
async def admin_delete_user(request: Request, user_id: int, current_user: dict = Depends(require_role("admin"))):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user["role"] == "admin" and count_admins() <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin")
    if user["id"] == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    delete_user(user_id)
    audit(request, current_user, "user_delete", user["username"])
    return {"status": "deleted", "id": user_id}

@app.post("/admin/users/{user_id}/reset-password")
async def admin_reset_password(request: Request, user_id: int, body: PasswordReset, current_user: dict = Depends(require_role("admin"))):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    hashed = sha256_crypt.hash(body.new_password)
    update_user(user_id, password_hash=hashed)
    audit(request, current_user, "password_reset", user["username"])
    return {"status": "password_reset", "username": user["username"]}

# ── License endpoints ──

@app.get("/license")
async def license_info(user: dict = Depends(get_current_user)):
    info = get_license_info()
    info["scans_this_month"] = get_scans_this_month()
    info["active_users"] = count_active_users()
    return info

@app.get("/license/usage")
async def license_usage(user: dict = Depends(require_role("admin"))):
    info = get_license_info()
    scans = get_scans_this_month()
    users = count_active_users()
    return {
        "tier": info["tier"],
        "scans_this_month": scans,
        "max_scans_per_month": info["max_scans_per_month"],
        "active_users": users,
        "max_users": info["max_users"],
    }

class LicenseActivateRequest(BaseModel):
    key: str

@app.post("/license/activate")
async def license_activate_endpoint(request: Request, body: LicenseActivateRequest, current_user: dict = Depends(require_role("admin"))):
    result = activate_license(body.key)
    if result["ok"]:
        audit(request, current_user, "license_activate", result["license"]["tier"])
    return result

# ── Protected routes (JWT required) ──

@app.get("/scan/nmap")
def run_nmap(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return nmap_scan(target)

@app.get("/scan/nuclei")
def run_nuclei(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return nuclei_scan(target)

@app.get("/scan/full")
def run_full(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    return {"target": target, "ports": nmap.get("ports", []), "nmap_raw": nmap, "nuclei": nuclei}

@app.get("/scan/analyze")
def run_analyze(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    scan_data = {"target": target, "ports": nmap.get("ports", []), "nuclei": nuclei}
    return analyze_scan_results(scan_data)

@app.get("/scan/profiles")
async def scan_profiles(user: dict = Depends(get_current_user)):
    return get_profiles_list()

class ScanStartRequest(BaseModel):
    target: str
    profile: str = "STRAZNIK"

@app.post("/scan/start")
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

@app.get("/scan/start")
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

@app.get("/scan/status/{task_id}")
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


def _get_user_from_token(token: str) -> dict:
    """Walidacja JWT z query param (SSE nie obsługuje custom headers)."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = get_user_by_username(username)
    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="User inactive or not found")
    return user


@app.get("/scan/stream/{task_id}")
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


@app.get("/scans")
async def scans_history(limit: int = 20, user: dict = Depends(get_current_user)):
    return get_scan_history(limit)

@app.get("/scans/{task_id}")
async def scan_detail(task_id: str, user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/scans/{task_id}/pdf")
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

@app.get("/scans/{task_id}/chains")
async def scan_chains(task_id: str, user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("exploit_chains"):
        return {"target": scan["target"], "exploit_chains": scan["exploit_chains"], "cached": True}
    chains = generate_exploit_chains(scan)
    return chains

@app.get("/scans/{task_id}/narrative")
async def scan_narrative(task_id: str, user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("hacker_narrative"):
        return {"target": scan["target"], **scan["hacker_narrative"], "cached": True}
    narrative = generate_hacker_narrative(scan)
    return narrative

@app.get("/scan/{task_id}/autoflow")
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

    # 1. XSS → BeEF
    if has_xss:
        actions.append({
            "action": "beef", "label": "Launch BeEF Session",
            "reason": "XSS vulnerabilities detected — hook target browsers",
            "url": "/phishing?tab=beef&target=" + target,
            "icon": "hook", "priority": "high",
        })

    # 2. Phishing signals
    if has_phishing_signal:
        actions.append({
            "action": "phishing", "label": "Create Phishing Campaign",
            "reason": "Email/login infrastructure exposed — test user awareness",
            "url": "/phishing?target=" + target,
            "icon": "email", "priority": "high" if risk_norm in ("CRITICAL", "KRYTYCZNE", "HIGH", "WYSOKIE") else "medium",
        })

    # 2b. Login page + HTTPS → Evilginx MITM
    has_login_page = any(kw in all_text for kw in ["login", "sign-in", "signin", "authenticate", "oauth", "sso"])
    has_https = "443" in str(scan.get("nmap", {}).get("ports", []))
    if has_login_page and has_https:
        actions.append({
            "action": "evilginx", "label": "Deploy Evilginx2 MITM Proxy",
            "reason": "Login page on HTTPS detected — intercept credentials with reverse proxy",
            "url": "/phishing?vector=evilginx&target=" + target,
            "icon": "shield", "priority": "high" if risk_norm in ("CRITICAL", "KRYTYCZNE", "HIGH", "WYSOKIE") else "medium",
        })

    # 3. Critical/High → report
    if risk_norm in ("CRITICAL", "KRYTYCZNE", "HIGH", "WYSOKIE"):
        actions.append({
            "action": "report", "label": "Generate Client Report",
            "reason": risk + " risk level — document findings for stakeholders",
            "url": "/scans/" + task_id + "/pdf",
            "icon": "report", "priority": "high",
        })

    # 4. SQLi → deeper exploitation
    if has_sqli:
        actions.append({
            "action": "sqli", "label": "Deep SQL Injection Test",
            "reason": "SQL injection indicators found — run targeted sqlmap",
            "url": "/ui?target=" + target + "&profile=CERBER",
            "icon": "database", "priority": "high",
        })

    # 5. AD attack paths
    if has_ad:
        ad_modules = [m for m in ["bloodhound", "certipy", "netexec", "impacket", "responder"] if scan.get(m)]
        actions.append({
            "action": "ad_paths", "label": "View AD Attack Paths",
            "reason": "Active Directory findings from: " + ", ".join(ad_modules),
            "url": "/ui?task_id=" + task_id + "&section=bloodhound",
            "icon": "ad", "priority": "high",
        })

    # 6. Always → schedule follow-up
    actions.append({
        "action": "schedule", "label": "Schedule Follow-up Scan",
        "reason": "Monitor target for changes and new vulnerabilities",
        "url": "/scheduler?target=" + target,
        "icon": "schedule", "priority": "low",
    })

    return {"task_id": task_id, "target": target, "risk_level": risk, "actions": actions}

# ── Client report API (no auth — shareable link) ──

_FINDING_NAMES = {
    "sql": "SQL Injection Vulnerability",
    "xss": "Cross-Site Scripting (XSS)",
    "rce": "Remote Code Execution",
    "lfi": "Local File Inclusion",
    "rfi": "Remote File Inclusion",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "xxe": "XML External Entity (XXE)",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "open-redirect": "Open Redirect",
    "directory-listing": "Directory Listing Enabled",
    "default-login": "Default Credentials",
    "info-disclosure": "Information Disclosure",
    "misconfig": "Server Misconfiguration",
    "ssl": "SSL/TLS Certificate Issue",
    "cve": "Known Software Vulnerability",
}

_FINDING_DESCS = {
    "sql": "An attacker could read or modify the company database, including customer data and passwords.",
    "xss": "An attacker could hijack user sessions and steal login credentials.",
    "rce": "An attacker could gain full control over the server and company data.",
    "lfi": "An attacker could read sensitive server files, including configuration and passwords.",
    "rfi": "An attacker could execute malicious code on the company server.",
    "ssrf": "An attacker could access internal company systems.",
    "xxe": "An attacker could read server files through crafted XML data.",
    "idor": "An attacker could access other users' data without authorization.",
    "csrf": "An attacker could perform operations on behalf of a logged-in user.",
    "open-redirect": "Users could be redirected to fake login pages.",
    "directory-listing": "Server directory structure is publicly visible, facilitating attacks.",
    "default-login": "System uses factory-default credentials, enabling immediate access.",
    "info-disclosure": "Server exposes technical information useful for attackers.",
    "misconfig": "Improper configuration allows bypassing security controls.",
    "ssl": "Communication could be intercepted by third parties.",
    "cve": "Software contains a known vulnerability with readily available exploit tools.",
}

def _classify_finding(name_lower):
    for key in _FINDING_NAMES:
        if key in name_lower:
            return key
    return "cve"

@app.get("/api/report/{task_id}")
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

    # Build client-safe findings (only critical + high)
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

    # Deduplicate by name
    seen = set()
    deduped = []
    for cf in client_findings:
        if cf["name"] not in seen:
            seen.add(cf["name"])
            deduped.append(cf)
    client_findings = deduped[:10]

    # Build recommendations from scan analysis
    recs_text = scan.get("recommendations") or ""
    top_issues = scan.get("top_issues") or []
    recs_list = []
    for i, issue in enumerate(top_issues[:5]):
        pri = "URGENT" if i == 0 else "IMPORTANT" if i < 3 else "RECOMMENDED"
        time_est = "1-3 days" if i == 0 else "1-2 weeks" if i < 3 else "1 month"
        # Strip technical details — keep only first sentence
        clean = issue.split(".")[0].split(" - ")[0].split(":")[0].strip()
        if len(clean) < 10:
            clean = issue[:120]
        recs_list.append({"priority": pri, "text": clean, "time": time_est})

    if not recs_list and recs_text:
        recs_list.append({"priority": "IMPORTANT", "text": recs_text[:200], "time": "-"})

    # Compliance
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

from modules.gobuster_scan import scan as gobuster_scan
from modules.whatweb_scan import scan as whatweb_scan
from modules.testssl_scan import scan as testssl_scan
from modules.sqlmap_scan import scan as sqlmap_scan
from modules.nikto_scan import scan as nikto_scan
from modules.harvester_scan import scan as harvester_scan
from modules.masscan_scan import scan as masscan_scan
# from modules.censys_scan import scan as censys_scan  # requires paid API plan - module ready
from modules.ipinfo_scan import scan as ipinfo_scan
from modules.enum4linux_scan import enum4linux_scan
from modules.mitre_attack import mitre_map
from modules.abuseipdb_scan import scan as abuseipdb_scan
from modules.otx_scan import scan as otx_scan
from modules.exploitdb_scan import exploitdb_scan
from modules.nvd_scan import nvd_scan
from modules.whois_scan import whois_scan
from modules.dnsrecon_scan import dnsrecon_scan
from modules.amass_scan import amass_scan
from modules.cwe_mapping import cwe_mapping
from modules.owasp_mapping import owasp_mapping

@app.get("/scan/gobuster")
def run_gobuster(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return gobuster_scan(target)

@app.get("/scan/whatweb")
def run_whatweb(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return whatweb_scan(target)

@app.get("/scan/testssl")
def run_testssl(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return testssl_scan(target)

@app.get("/scan/sqlmap")
def run_sqlmap(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return sqlmap_scan(target)

@app.get("/scan/nikto")
def run_nikto(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return nikto_scan(target)

@app.get("/scan/harvester")
def run_harvester(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return harvester_scan(target)

@app.get("/scan/masscan")
def run_masscan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return masscan_scan(target)

# requires paid API plan - module ready
# @app.get("/scan/censys")
# async def run_censys(target: str = Query(...), user: dict = Depends(get_current_user)):
#     return censys_scan(target)

@app.get("/scan/ipinfo")
def run_ipinfo(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return ipinfo_scan(target)

@app.get("/scan/enum4linux")
def run_enum4linux(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return enum4linux_scan(target)

@app.get("/scan/mitre")
def run_mitre(task_id: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return mitre_map(scan)

@app.get("/scan/abuseipdb")
def run_abuseipdb(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return abuseipdb_scan(target)

@app.get("/scan/otx")
def run_otx(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return otx_scan(target)

@app.get("/scan/exploitdb")
def run_exploitdb(task_id: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return exploitdb_scan(scan)

@app.get("/scan/nvd")
def run_nvd(task_id: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return nvd_scan(scan)

@app.get("/scan/whois")
def run_whois(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return whois_scan(target)

@app.get("/scan/dnsrecon")
def run_dnsrecon(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return dnsrecon_scan(target)

@app.get("/scan/amass")
def run_amass(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return amass_scan(target)

@app.get("/scan/cwe")
def run_cwe(task_id: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return cwe_mapping(scan)

@app.get("/scan/owasp")
def run_owasp(task_id: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return owasp_mapping(scan)

from modules.wpscan_scan import wpscan_scan
from modules.zap_scan import zap_scan
from modules.wapiti_scan import wapiti_scan
from modules.joomscan_scan import joomscan_scan
from modules.cmsmap_scan import cmsmap_scan
from modules.droopescan_scan import droopescan_scan
from modules.retirejs_scan import retirejs_scan
from modules.subfinder_scan import subfinder_scan
from modules.httpx_scan import httpx_scan
from modules.naabu_scan import naabu_scan
from modules.katana_scan import katana_scan
from modules.dnsx_scan import dnsx_scan
from modules.netdiscover_scan import netdiscover_scan
from modules.arpscan_scan import arpscan_scan
from modules.fping_scan import fping_scan
from modules.traceroute_scan import traceroute_scan
from modules.nbtscan_scan import nbtscan_scan
from modules.snmpwalk_scan import snmpwalk_scan
from modules.netexec_scan import netexec_scan
from modules.bloodhound_scan import bloodhound_scan
from modules.responder_scan import responder_scan
from modules.fierce_scan import fierce_scan
from modules.smbmap_scan import smbmap_scan
from modules.onesixtyone_scan import onesixtyone_scan
from modules.ikescan_scan import ikescan_scan
from modules.sslyze_scan import sslyze_scan
from modules.searchsploit_scan import searchsploit_scan
from modules.impacket_scan import impacket_scan

@app.get("/scan/wpscan")
def run_wpscan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return wpscan_scan(target)

@app.get("/scan/zap")
def run_zap(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return zap_scan(target)

@app.get("/scan/wapiti")
def run_wapiti(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return wapiti_scan(target)

@app.get("/scan/joomscan")
def run_joomscan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return joomscan_scan(target)

@app.get("/scan/cmsmap")
def run_cmsmap(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return cmsmap_scan(target)

@app.get("/scan/droopescan")
def run_droopescan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return droopescan_scan(target)

@app.get("/scan/retirejs")
def run_retirejs(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return retirejs_scan(target)

@app.get("/scan/subfinder")
def run_subfinder(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return subfinder_scan(target)

@app.get("/scan/httpx")
def run_httpx(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return httpx_scan(target)

@app.get("/scan/naabu")
def run_naabu(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return naabu_scan(target)

@app.get("/scan/katana")
def run_katana(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return katana_scan(target)

@app.get("/scan/dnsx")
def run_dnsx(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return dnsx_scan(target)

@app.get("/scan/netdiscover")
def run_netdiscover(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return netdiscover_scan(target)

@app.get("/scan/arpscan")
def run_arpscan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return arpscan_scan(target)

@app.get("/scan/fping")
def run_fping(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return fping_scan(target)

@app.get("/scan/traceroute")
def run_traceroute(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return traceroute_scan(target)

@app.get("/scan/nbtscan")
def run_nbtscan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return nbtscan_scan(target)

@app.get("/scan/snmpwalk")
def run_snmpwalk(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return snmpwalk_scan(target)

@app.get("/scan/netexec")
def run_netexec(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return netexec_scan(target)

@app.get("/scan/bloodhound")
def run_bloodhound(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return bloodhound_scan(target)

@app.get("/scan/responder")
def run_responder(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return responder_scan(target)

@app.get("/scan/fierce")
def run_fierce(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return fierce_scan(target)

@app.get("/scan/smbmap")
def run_smbmap(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return smbmap_scan(target)

@app.get("/scan/onesixtyone")
def run_onesixtyone(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return onesixtyone_scan(target)

@app.get("/scan/ikescan")
def run_ikescan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return ikescan_scan(target)

@app.get("/scan/sslyze")
def run_sslyze(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return sslyze_scan(target)

@app.get("/scan/searchsploit")
def run_searchsploit(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return searchsploit_scan(target)

@app.get("/scan/impacket")
def run_impacket(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return impacket_scan(target)

from modules.certipy_scan import run_certipy

@app.get("/scan/certipy")
def scan_certipy(
    target: str = Query(...),
    dc_ip: str = Query(""),
    username: str = Query(""),
    password: str = Query(""),
    domain: str = Query(""),
    user: dict = Depends(require_role("admin", "operator")),
):
    return run_certipy(target, username=username or None, password=password or None,
                       domain=domain or None, dc_ip=dc_ip or None)

from modules.tasks import osint_scan_task
from modules.database import get_osint_history, get_osint_by_task_id
from modules.pdf_report import generate_osint_report

class OsintStartRequest(BaseModel):
    target: str
    search_type: str = "domain"

@app.get("/osint/start")
@limiter.limit("5/minute")
async def osint_start_get(request: Request, target: str = Query(...), search_type: str = Query("domain"), user: dict = Depends(require_role("admin", "operator"))):
    task = osint_scan_task.delay(target, search_type=search_type)
    audit(request, user, "osint_start", target)
    return {"task_id": task.id, "status": "started", "target": target, "search_type": search_type}

@app.post("/osint/start")
@limiter.limit("5/minute")
async def osint_start_post(request: Request, body: OsintStartRequest, user: dict = Depends(require_role("admin", "operator"))):
    task = osint_scan_task.delay(body.target, search_type=body.search_type)
    audit(request, user, "osint_start", body.target)
    return {"task_id": task.id, "status": "started", "target": body.target, "search_type": body.search_type}

@app.get("/osint/status/{task_id}")
async def osint_status(task_id: str, user: dict = Depends(get_current_user)):
    task = osint_scan_task.AsyncResult(task_id)
    if task.state == "SUCCESS":
        return {"task_id": task_id, "status": "completed", "result": task.result}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "failed", "error": str(task.info)}
    elif task.state == "PENDING":
        # Celery result may have expired from Redis — check database
        scan = get_osint_by_task_id(task_id)
        if scan:
            return {"task_id": task_id, "status": "completed", "result": scan}
        return {"task_id": task_id, "status": "pending"}
    else:
        return {"task_id": task_id, "status": task.state}

@app.get("/osint/history")
async def osint_history(limit: int = 20, user: dict = Depends(get_current_user)):
    return get_osint_history(limit)

@app.get("/osint/{task_id}/pdf")
async def osint_pdf(request: Request, task_id: str, user: dict = Depends(get_current_user)):
    scan = get_osint_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="OSINT scan not found")
    pdf_bytes = generate_osint_report(scan)
    audit(request, user, "osint_pdf_download", scan.get("target"))
    # Sanitize filename to ASCII-safe (Polish ł→l, ś→s, etc.)
    raw_target = scan.get("target", "unknown")
    safe_target = unicodedata.normalize("NFKD", raw_target).encode("ascii", "ignore").decode("ascii")
    safe_target = _re.sub(r'[^\w\-.]', '_', safe_target).strip('_') or "scan"
    filename = f"cyrber_osint_{safe_target}_{task_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

from modules.webhook import WazuhAlert, extract_target

@app.post("/webhook/wazuh")
@limiter.limit("30/minute")
async def wazuh_webhook(request: Request, alert: WazuhAlert, user: dict = Depends(require_role("admin", "operator"))):
    target = extract_target(alert)
    if not target:
        return {"status": "ignored", "reason": "no valid target extracted"}
    task = full_scan_task.delay(target)
    audit(request, user, "webhook_wazuh", target)
    return {
        "status": "scan_started",
        "target": target,
        "task_id": task.id,
        "trigger": "wazuh_alert",
        "rule_id": alert.rule_id
    }

@app.post("/webhook/generic")
@limiter.limit("30/minute")
async def generic_webhook(request: Request, payload: dict, user: dict = Depends(require_role("admin", "operator"))):
    target = payload.get("target") or payload.get("ip") or payload.get("host")
    if not target:
        return {"status": "ignored", "reason": "no target field in payload"}
    task = full_scan_task.delay(target)
    audit(request, user, "webhook_generic", target)
    return {
        "status": "scan_started",
        "target": target,
        "task_id": task.id,
        "trigger": "webhook"
    }

from modules.tasks import agent_scan_task

@app.get("/agent/start")
@limiter.limit("3/minute")
async def agent_start(request: Request, target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    task = agent_scan_task.delay(target)
    audit(request, user, "agent_start", target)
    return {"task_id": task.id, "status": "started", "target": target, "mode": "agent"}

class ScheduleCreate(BaseModel):
    target: str
    interval_hours: int

@app.post("/schedules")
async def create_schedule(request: Request, schedule: ScheduleCreate, user: dict = Depends(require_role("admin", "operator"))):
    if schedule.interval_hours < 1:
        raise HTTPException(status_code=400, detail="interval_hours must be >= 1")
    result = add_schedule(schedule.target, schedule.interval_hours)
    audit(request, user, "schedule_create", schedule.target)
    return result

@app.get("/schedules")
async def list_schedules(user: dict = Depends(get_current_user)):
    return get_schedules()

@app.delete("/schedules/{schedule_id}")
async def remove_schedule(request: Request, schedule_id: int, user: dict = Depends(require_role("admin", "operator"))):
    ok = delete_schedule(schedule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Schedule not found")
    audit(request, user, "schedule_delete", str(schedule_id))
    return {"status": "deleted", "id": schedule_id}

# ── GoPhish proxy ──
GOPHISH_URL = os.getenv("GOPHISH_URL", "http://gophish:3333")
GOPHISH_API_KEY = os.getenv("GOPHISH_API_KEY", "")

def _gophish_headers():
    return {"Authorization": f"Bearer {GOPHISH_API_KEY}", "Content-Type": "application/json"}

def _gophish_get(path: str):
    r = http_requests.get(f"{GOPHISH_URL}/api/{path}", headers=_gophish_headers(), timeout=15, verify=False)
    r.raise_for_status()
    return r.json()

def _gophish_post(path: str, data: dict):
    r = http_requests.post(f"{GOPHISH_URL}/api/{path}", headers=_gophish_headers(), json=data, timeout=15, verify=False)
    r.raise_for_status()
    return r.json()

def _gophish_delete(path: str):
    r = http_requests.delete(f"{GOPHISH_URL}/api/{path}", headers=_gophish_headers(), timeout=15, verify=False)
    r.raise_for_status()
    return r.json() if r.text else {"status": "deleted"}

@app.get("/phishing/campaigns")
async def phishing_campaigns(user: dict = Depends(get_current_user)):
    try:
        campaigns = _gophish_get("campaigns/")
        result = []
        for c in campaigns:
            stats = c.get("stats", {}) or {}
            result.append({
                "id": c.get("id"),
                "name": c.get("name", ""),
                "status": c.get("status", ""),
                "created_date": c.get("created_date", ""),
                "stats": {
                    "sent": stats.get("sent", 0),
                    "opened": stats.get("opened", 0),
                    "clicked": stats.get("clicked", 0),
                    "submitted_data": stats.get("submitted_data", 0),
                    "error": stats.get("error", 0),
                    "total": stats.get("total", 0),
                }
            })
        return result
    except http_requests.ConnectionError:
        raise HTTPException(status_code=503, detail="GoPhish not available — start with: docker compose --profile phishing up -d")
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

class PhishingCampaignCreate(BaseModel):
    name: str
    domain: str
    subject: str
    email_body: str
    landing_url: str = ""
    targets: list[str]

class PhishingEmailGenerate(BaseModel):
    target: str
    risk_level: str = ""
    risk_score: int = 0
    technologies: list[str] = []
    emails: list[str] = []
    vulnerabilities: list[str] = []
    executive_summary: str = ""
    language: str = "pl"

@app.post("/phishing/generate-email")
@limiter.limit("10/minute")
async def phishing_generate_email(request: Request, data: PhishingEmailGenerate, user: dict = Depends(require_role("admin", "operator"))):
    try:
        from modules.llm_provider import get_provider
        provider = get_provider(task="phishing_email")

        techs_str = ", ".join(data.technologies[:15]) if data.technologies else "brak danych"
        vulns_str = ", ".join(data.vulnerabilities[:10]) if data.vulnerabilities else "brak danych"
        emails_str = ", ".join(data.emails[:10]) if data.emails else "brak danych"

        prompt = f"""Jesteś ekspertem od security awareness testing. Wygeneruj realistyczny email phishingowy (do celów autoryzowanego testu penetracyjnego) na podstawie danych rekonesansu.

DANE REKONESANSU:
- Cel: {data.target}
- Poziom ryzyka: {data.risk_level} (score: {data.risk_score}/100)
- Technologie: {techs_str}
- Znalezione emaile: {emails_str}
- Podatności: {vulns_str}
- Podsumowanie: {data.executive_summary[:500] if data.executive_summary else 'brak'}

WYMAGANIA:
- Język: {"polski" if data.language == "pl" else data.language}
- Email musi być przekonujący i dopasowany do kontekstu technologicznego celu
- Body w HTML, użyj {{{{.URL}}}} jako placeholder na link GoPhish
- Zwróć TYLKO JSON (bez markdown):

{{"subject": "temat emaila", "body": "<p>treść HTML z linkiem <a href=\\"{{{{.URL}}}}\\">kliknij</a></p>", "pretext": "krótki opis pretekstu użytego w emailu"}}"""

        response_text = provider.chat(prompt, max_tokens=1500)

        # Parse JSON from LLM response (pattern from hacker_narrative.py)
        clean = response_text.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        try:
            result = json.loads(clean.strip())
        except json.JSONDecodeError:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            result = json.loads(response_text[start:end])

        audit(request, user, "phishing_generate_email", data.target)
        return {"status": "ok", "provider": provider.name, **result}

    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse LLM response as JSON: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email generation failed: {str(e)}")

@app.post("/phishing/campaigns")
async def phishing_create_campaign(request: Request, campaign: PhishingCampaignCreate, user: dict = Depends(require_role("admin", "operator"))):
    try:
        # 1. Create or reuse sending profile
        smtp_name = f"CYRBER-{campaign.domain}"
        try:
            profiles = _gophish_get("smtp/")
            profile = next((p for p in profiles if p["name"] == smtp_name), None)
        except Exception:
            profile = None

        if not profile:
            profile = _gophish_post("smtp/", {
                "name": smtp_name,
                "host": f"{campaign.domain}:25",
                "from_address": f"security@{campaign.domain}",
                "ignore_cert_errors": True
            })
        smtp_id = profile["id"]

        # 2. Create email template
        tmpl_name = f"CYRBER-{campaign.name}"
        template = _gophish_post("templates/", {
            "name": tmpl_name,
            "subject": campaign.subject,
            "html": campaign.email_body,
        })
        tmpl_id = template["id"]

        # 3. Create landing page (if URL provided)
        page_id = None
        if campaign.landing_url:
            page_name = f"CYRBER-LP-{campaign.name}"
            page = _gophish_post("pages/", {
                "name": page_name,
                "capture_credentials": True,
                "capture_passwords": True,
                "redirect_url": "",
                "html": f'<html><body><script>window.location="{campaign.landing_url}";</script></body></html>',
            })
            page_id = page["id"]

        # 4. Create target group
        group_name = f"CYRBER-{campaign.name}-targets"
        targets_list = [
            {"first_name": "", "last_name": "", "email": email, "position": ""}
            for email in campaign.targets
        ]
        group = _gophish_post("groups/", {
            "name": group_name,
            "targets": targets_list
        })
        group_id = group["id"]

        # 5. Create and launch campaign
        camp_payload = {
            "name": campaign.name,
            "template": {"id": tmpl_id},
            "smtp": {"id": smtp_id},
            "groups": [{"id": group_id}],
            "launch_date": "2000-01-01T00:00:00Z",
        }
        if page_id:
            camp_payload["page"] = {"id": page_id}
        else:
            # GoPhish requires a page — create a minimal one
            fallback_page = _gophish_post("pages/", {
                "name": f"CYRBER-blank-{campaign.name}",
                "html": "<html><body>Thank you.</body></html>",
                "capture_credentials": False,
            })
            camp_payload["page"] = {"id": fallback_page["id"]}

        result = _gophish_post("campaigns/", camp_payload)
        audit(request, user, "phishing_create", campaign.name)
        return {"id": result.get("id"), "name": result.get("name"), "status": result.get("status")}

    except http_requests.ConnectionError:
        raise HTTPException(status_code=503, detail="GoPhish not available")
    except http_requests.HTTPError as e:
        detail = e.response.text if e.response else str(e)
        raise HTTPException(status_code=502, detail=f"GoPhish error: {detail}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/phishing/campaigns/{campaign_id}")
async def phishing_delete_campaign(request: Request, campaign_id: int, user: dict = Depends(require_role("admin", "operator"))):
    try:
        result = _gophish_delete(f"campaigns/{campaign_id}")
        audit(request, user, "phishing_delete", str(campaign_id))
        return result
    except http_requests.ConnectionError:
        raise HTTPException(status_code=503, detail="GoPhish not available")
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

@app.get("/phishing/campaigns/{campaign_id}/results")
async def phishing_campaign_results(campaign_id: int, user: dict = Depends(get_current_user)):
    try:
        campaign = _gophish_get(f"campaigns/{campaign_id}")
        results = campaign.get("results", [])
        timeline = campaign.get("timeline", [])
        stats = campaign.get("stats", {}) or {}

        events = []
        for ev in timeline:
            events.append({
                "email": ev.get("email", ""),
                "message": ev.get("message", ""),
                "time": ev.get("time", ""),
            })

        return {
            "campaign_id": campaign_id,
            "name": campaign.get("name", ""),
            "status": campaign.get("status", ""),
            "stats": {
                "total": stats.get("total", len(results)),
                "sent": stats.get("sent", 0),
                "opened": stats.get("opened", 0),
                "clicked": stats.get("clicked", 0),
                "submitted_data": stats.get("submitted_data", 0),
                "error": stats.get("error", 0),
            },
            "events": events,
        }
    except http_requests.ConnectionError:
        raise HTTPException(status_code=503, detail="GoPhish not available")
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

# ── Garak LLM Security Scanner ──

from modules.garak_scan import (
    is_available as garak_available,
    get_status as garak_status,
    list_probes as garak_probes,
    start_scan as garak_start,
    get_scan as garak_get,
    list_scans as garak_list,
)

def _require_garak():
    if not garak_available():
        raise HTTPException(
            status_code=503,
            detail="Garak not available — start with: docker compose --profile ai-security up -d",
        )

@app.get("/garak/status")
async def garak_get_status(user: dict = Depends(get_current_user)):
    return garak_status()

@app.get("/garak/probes")
async def garak_get_probes(user: dict = Depends(get_current_user)):
    _require_garak()
    return garak_probes()

class GarakScanRequest(BaseModel):
    target_type: str = "openai"
    target_name: str = "gpt-4"
    probes: str = "encoding,dan,promptinject"
    probe_tags: str = ""
    generations: int = 3
    api_key: str = ""
    api_base: str = ""

@app.post("/garak/scan")
async def garak_post_scan(request: Request, body: GarakScanRequest, user: dict = Depends(require_role("admin", "operator"))):
    _require_garak()
    result = garak_start(
        target_type=body.target_type, target_name=body.target_name,
        probes=body.probes, probe_tags=body.probe_tags,
        generations=body.generations, api_key=body.api_key,
        api_base=body.api_base,
    )
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    audit(request, user, "garak_scan_start", f"{body.target_type}/{body.target_name}")
    return result

@app.get("/garak/scan/{scan_id}")
async def garak_get_scan(scan_id: str, user: dict = Depends(get_current_user)):
    _require_garak()
    result = garak_get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result

@app.get("/garak/scans")
async def garak_list_all(user: dict = Depends(get_current_user)):
    _require_garak()
    return garak_list()

# ── BeEF-XSS proxy ──

from modules.beef_xss import (
    is_available as beef_available,
    get_status as beef_status,
    get_hooks as beef_hooks,
    get_hook_detail as beef_hook_detail,
    get_modules as beef_modules,
    get_module_detail as beef_module_detail,
    run_module as beef_run_module,
    get_module_result as beef_module_result,
    get_logs as beef_logs,
)

def _require_beef():
    if not beef_available():
        raise HTTPException(
            status_code=503,
            detail="BeEF not available — start with: docker compose --profile phishing up -d",
        )

@app.get("/beef/status")
async def beef_get_status(user: dict = Depends(get_current_user)):
    return beef_status()

@app.get("/beef/hooks")
async def beef_get_hooks(user: dict = Depends(get_current_user)):
    _require_beef()
    return beef_hooks()

@app.get("/beef/hooks/{session}")
async def beef_get_hook(session: str, user: dict = Depends(get_current_user)):
    _require_beef()
    detail = beef_hook_detail(session)
    if not detail:
        raise HTTPException(status_code=404, detail="Hooked browser not found")
    return detail

@app.get("/beef/modules")
async def beef_get_modules(user: dict = Depends(get_current_user)):
    _require_beef()
    return beef_modules()

@app.get("/beef/modules/{module_id}")
async def beef_get_module(module_id: str, user: dict = Depends(get_current_user)):
    _require_beef()
    detail = beef_module_detail(module_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Module not found")
    return detail

class BeefRunModule(BaseModel):
    session: str
    module_id: str
    options: dict = {}

@app.post("/beef/modules/run")
async def beef_post_run_module(request: Request, body: BeefRunModule, user: dict = Depends(require_role("admin", "operator"))):
    _require_beef()
    result = beef_run_module(body.session, body.module_id, body.options)
    if not result:
        raise HTTPException(status_code=502, detail="Failed to execute module on BeEF")
    audit(request, user, "beef_run_module", f"{body.session}/{body.module_id}")
    return result

@app.get("/beef/modules/{session}/{module_id}/{cmd_id}")
async def beef_get_result(session: str, module_id: str, cmd_id: str, user: dict = Depends(get_current_user)):
    _require_beef()
    result = beef_module_result(session, module_id, cmd_id)
    if not result:
        raise HTTPException(status_code=404, detail="Command result not found")
    return result

@app.get("/beef/logs")
async def beef_get_logs(session: str | None = None, user: dict = Depends(get_current_user)):
    _require_beef()
    return beef_logs(session)

# ── Evilginx2 proxy ──

from modules.evilginx_phishing import (
    is_available as evilginx_available,
    get_sessions as evilginx_sessions,
    get_session as evilginx_session,
    delete_session as evilginx_delete,
    list_phishlets as evilginx_phishlets,
    get_phishlet as evilginx_phishlet,
    get_stats as evilginx_stats,
    get_config as evilginx_config,
    get_credentials as evilginx_credentials,
    get_lures as evilginx_lures,
    create_lure as evilginx_create_lure,
    delete_lure as evilginx_delete_lure,
    get_status as evilginx_status,
)

def _require_evilginx():
    if not evilginx_available():
        raise HTTPException(
            status_code=503,
            detail="Evilginx2 not available — start with: docker compose --profile phishing up -d",
        )

@app.get("/evilginx/stats")
async def evilginx_get_stats(user: dict = Depends(get_current_user)):
    return evilginx_stats()

@app.get("/evilginx/sessions")
async def evilginx_get_sessions(user: dict = Depends(get_current_user)):
    _require_evilginx()
    return evilginx_sessions()

@app.get("/evilginx/sessions/{session_id}")
async def evilginx_get_session(session_id: str, user: dict = Depends(get_current_user)):
    _require_evilginx()
    s = evilginx_session(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return s

@app.delete("/evilginx/sessions/{session_id}")
async def evilginx_delete_session(request: Request, session_id: str, user: dict = Depends(require_role("admin", "operator"))):
    _require_evilginx()
    if not evilginx_delete(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    audit(request, user, "evilginx_session_delete", session_id)
    return {"status": "deleted", "session_id": session_id}

@app.get("/evilginx/phishlets")
async def evilginx_get_phishlets(user: dict = Depends(get_current_user)):
    _require_evilginx()
    return evilginx_phishlets()

@app.get("/evilginx/phishlets/{name}")
async def evilginx_get_phishlet(name: str, user: dict = Depends(get_current_user)):
    _require_evilginx()
    p = evilginx_phishlet(name)
    if not p:
        raise HTTPException(status_code=404, detail="Phishlet not found")
    return p

@app.get("/evilginx/config")
async def evilginx_get_config(user: dict = Depends(get_current_user)):
    _require_evilginx()
    return evilginx_config()

# ── Evilginx2 extended management ──

class EvilginxLureCreate(BaseModel):
    phishlet: str
    redirect_url: str = ""
    path: str = ""

@app.get("/api/evilginx/status")
async def evilginx_get_status_api(user: dict = Depends(get_current_user)):
    return evilginx_status()

@app.get("/api/evilginx/credentials")
async def evilginx_get_credentials(user: dict = Depends(get_current_user)):
    _require_evilginx()
    return evilginx_credentials()

@app.get("/api/evilginx/lures")
async def evilginx_get_lures(user: dict = Depends(get_current_user)):
    _require_evilginx()
    return evilginx_lures()

@app.post("/api/evilginx/lures")
async def evilginx_create_lure_api(request: Request, body: EvilginxLureCreate, user: dict = Depends(require_role("admin", "operator"))):
    _require_evilginx()
    try:
        lure = evilginx_create_lure(body.phishlet, body.redirect_url, body.path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit(request, user, "evilginx_lure_create", f"phishlet={body.phishlet}")
    return lure

@app.delete("/api/evilginx/lures/{lure_id}")
async def evilginx_delete_lure_api(request: Request, lure_id: int, user: dict = Depends(require_role("admin", "operator"))):
    _require_evilginx()
    if not evilginx_delete_lure(lure_id):
        raise HTTPException(status_code=404, detail="Lure not found")
    audit(request, user, "evilginx_lure_delete", str(lure_id))
    return {"status": "deleted", "lure_id": lure_id}

# ── CYRBER VERIFY ──

class VerifyRequest(BaseModel):
    query: str
    type: str = "AUTO"     # url / email / company / AUTO
    country: str = "AUTO"  # PL / UK / AUTO

@app.post("/api/verify")
@limiter.limit("10/minute")
async def api_verify(request: Request, body: VerifyRequest, user: dict = Depends(require_role("admin", "operator"))):
    import redis.asyncio as aioredis

    query = body.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query is required")

    # Auto-detect type
    from modules.verify import CyrberVerify, detect_query_type
    qtype = body.type.lower()
    if qtype == "auto":
        qtype = detect_query_type(query)

    # Auto-detect country
    country = body.country.upper()
    if country == "AUTO":
        country = "PL"

    # Redis cache (1h)
    cache_key = f"verify:{qtype}:{query}".replace(" ", "_").lower()
    try:
        async with aioredis.from_url(REDIS_URL) as r:
            cached = await r.get(cache_key)
            if cached:
                return json.loads(cached)
    except Exception:
        pass

    # Run verification
    v = CyrberVerify()
    try:
        if qtype == "url":
            result = v.verify_url(query)
        elif qtype == "email":
            result = v.verify_email(query)
        elif qtype == "company":
            result = v.verify_company(query, country=country)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown type: {qtype}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Verification failed: {str(exc)}")

    # Save to DB
    try:
        from modules.database import save_verify_result
        result["id"] = save_verify_result(result, created_by=user.get("username", "unknown"))
    except Exception as exc:
        log.warning(f"Failed to save verify result: {exc}")

    # Cache in Redis (1h)
    try:
        async with aioredis.from_url(REDIS_URL) as r:
            await r.setex(cache_key, 3600, json.dumps(result, ensure_ascii=False, default=str))
    except Exception:
        pass

    audit(request, user, "verify", f"{qtype}:{query}")
    return result

@app.get("/api/verify/history")
async def api_verify_history(user: dict = Depends(require_role("admin", "operator"))):
    from modules.database import get_verify_history
    return get_verify_history(limit=50)

# ── Multi-target scan ──

class MultiTargetScan(BaseModel):
    targets: list[str]
    profile: str = "STRAZNIK"

@app.post("/scan/multi")
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

# ── Notifications ──
from modules.notify import (
    send_scan_notification,
    SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_TO,
    SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL,
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
)

@app.get("/notifications/status")
async def notifications_status(user: dict = Depends(get_current_user)):
    return {
        "email": bool(SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_TO),
        "slack": bool(SLACK_WEBHOOK_URL),
        "discord": bool(DISCORD_WEBHOOK_URL),
        "telegram": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID),
    }

@app.post("/notifications/test")
@limiter.limit("3/minute")
async def notifications_test(request: Request, user: dict = Depends(require_role("admin", "operator"))):
    test_result = {
        "target": "test.example.com",
        "findings_count": 42,
        "analysis": {
            "risk_level": "MEDIUM",
            "summary": "This is a test notification from CYRBER to verify your notification channels are configured correctly.",
        }
    }
    ok = send_scan_notification("test.example.com", "test-0000-0000", test_result)
    audit(request, user, "notifications_test")
    return {"sent": ok, "message": "Test notification dispatched to all configured channels"}

# ── Audit logs endpoint ──
@app.get("/audit")
async def audit_logs(limit: int = 100, user: dict = Depends(require_role("admin"))):
    return get_audit_logs(limit)


@app.post("/rag/build-index")
async def build_rag_index(current_user: dict = Depends(require_role("admin"))):
    """Buduje indeks RAG z knowledge_base"""
    from modules.rag_knowledge import get_rag
    result = get_rag().build_index()
    return result


@app.get("/rag/search")
async def rag_search(q: str, top_k: int = 5, current_user: dict = Depends(get_current_user)):
    """Semantic search w knowledge base"""
    from modules.rag_knowledge import get_rag
    results = get_rag().search(q, top_k=top_k)
    return {"query": q, "results": results}


# ── AI Explain Finding ──

class ExplainFindingRequest(BaseModel):
    finding_name: str
    finding_description: str = ""
    target: str = ""
    severity: str = ""

@app.post("/api/explain-finding")
@limiter.limit("20/minute")
async def explain_finding(request: Request, body: ExplainFindingRequest, user: dict = Depends(get_current_user)):
    import redis.asyncio as aioredis

    cache_key = f"explain:{body.finding_name}:{body.severity}".replace(" ", "_")

    # Check Redis cache first
    try:
        async with aioredis.from_url(REDIS_URL) as r:
            cached = await r.get(cache_key)
            if cached:
                return json.loads(cached)
    except Exception:
        pass

    from modules.llm_provider import ClaudeProvider
    prompt = (
        "You are a cybersecurity expert. Explain this finding to a business owner "
        "in plain English, without technical jargon.\n\n"
        f"Finding: {body.finding_name}\n"
        f"Description: {body.finding_description}\n"
        f"Target: {body.target}\n"
        f"Severity: {body.severity}\n\n"
        "Respond EXACTLY in JSON format (no markdown):\n"
        '{"explanation": "What this is - 2-3 sentences", '
        '"risk": "Business impact - 2-3 sentences", '
        '"fix": "How to fix it - 2-3 sentences"}'
    )
    try:
        provider = ClaudeProvider(model="claude-haiku-4-5-20251001")
        response_text = provider.chat(prompt, max_tokens=600)
        clean = response_text.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        try:
            result = json.loads(clean.strip())
        except json.JSONDecodeError:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            result = json.loads(response_text[start:end])

        # Store in Redis cache (TTL 24h)
        try:
            async with aioredis.from_url(REDIS_URL) as r:
                await r.setex(cache_key, 86400, json.dumps(result, ensure_ascii=False))
        except Exception:
            pass

        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI explain failed: {str(e)}")


# ── Scan AI Agent (conversational) ──

class ScanAgentRequest(BaseModel):
    task_id: str
    message: str
    history: list = []

@app.post("/api/scan-agent")
@limiter.limit("30/minute")
async def scan_agent(request: Request, body: ScanAgentRequest, user: dict = Depends(get_current_user)):
    from modules.llm_provider import ClaudeProvider

    scan = get_scan_by_task_id(body.task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build scan context summary (compact)
    target = scan.get("target", "")
    risk = scan.get("risk_level", "N/A")
    findings_count = scan.get("findings_count", 0)
    ai = scan.get("ai_analysis") or {}
    summary = ai.get("executive_summary") or scan.get("summary") or ""
    narrative = (scan.get("hacker_narrative") or {}).get("executive_summary", "")

    # Top findings for context
    top_findings = []
    nuclei = scan.get("nuclei") or {}
    for f in (nuclei.get("findings") or [])[:10]:
        info = f.get("info") or {}
        top_findings.append(f"{info.get('severity', 'info').upper()}: {info.get('name', f.get('template_id', ''))}")

    if scan.get("sqlmap", {}).get("vulnerable"):
        top_findings.insert(0, "CRITICAL: SQL Injection (SQLMap)")

    for a in (scan.get("zap", {}).get("alerts") or [])[:5]:
        top_findings.append(f"{a.get('risk', 'info').upper()}: {a.get('name', '')}")

    # Exploit chains summary
    chains_summary = ""
    chains_raw = scan.get("exploit_chains") or {}
    chains_list = chains_raw.get("chains") if isinstance(chains_raw, dict) else chains_raw
    if isinstance(chains_list, list) and chains_list:
        chain_descs = []
        for c in chains_list[:3]:
            steps = c.get("steps") or c.get("chain") or []
            step_names = [s.get("action") or s.get("technique") or "" for s in steps[:4]]
            chain_descs.append(" -> ".join(step_names))
        chains_summary = "\n".join(chain_descs)

    system_prompt = (
        "You are the CYRBER AI cybersecurity expert. You respond concisely and helpfully "
        "in English. You have full context of the security scan.\n\n"
        f"TARGET: {target}\n"
        f"RISK LEVEL: {risk}\n"
        f"FINDINGS COUNT: {findings_count}\n"
        f"SUMMARY: {summary[:500]}\n"
        f"NARRATIVE: {narrative[:500]}\n"
        f"TOP FINDINGS:\n" + "\n".join(top_findings[:15]) + "\n"
    )
    if chains_summary:
        system_prompt += f"\nEXPLOIT CHAINS:\n{chains_summary}\n"

    system_prompt += (
        "\nRespond concisely (max 3-4 sentences). "
        "If the question is about a CVE, explain what it is and how to fix it. "
        "If the question is about a scan parameter, explain in the context of this target."
    )

    try:
        provider = ClaudeProvider(model="claude-haiku-4-5-20251001")
        # Build conversation from history
        prompt_parts = []
        for msg in (body.history or [])[-8:]:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "user":
                prompt_parts.append(f"User: {content}")
            elif role == "assistant":
                prompt_parts.append(f"AI: {content}")
        prompt_parts.append(f"User: {body.message}")
        prompt = "\n".join(prompt_parts)

        response_text = provider.chat(prompt, system=system_prompt, max_tokens=800)
        return {"response": response_text.strip()}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI agent failed: {str(e)}")

# ── Remediation Tracker ──────────────────────────────────

class RemediationCreate(BaseModel):
    finding_name: str
    finding_severity: str
    finding_module: str | None = None
    owner: str | None = None
    deadline: str | None = None
    notes: str | None = None

class RemediationUpdate(BaseModel):
    status: str | None = None
    owner: str | None = None
    deadline: str | None = None
    notes: str | None = None

class RemediationBulk(BaseModel):
    findings: list[dict]

@app.get("/api/scan/{task_id}/remediation")
async def get_scan_remediation(task_id: str, current_user: dict = Depends(get_current_user)):
    tasks = get_remediation_tasks(task_id)
    stats = get_remediation_stats(task_id)
    return {"tasks": tasks, "stats": stats}

@app.post("/api/scan/{task_id}/remediation")
async def create_scan_remediation(task_id: str, body: RemediationCreate, request: Request,
                                  current_user: dict = Depends(require_role("admin", "operator"))):
    dl = None
    if body.deadline:
        try:
            dl = datetime.fromisoformat(body.deadline)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid deadline format")
    t = create_remediation_task(
        scan_id=task_id, finding_name=body.finding_name,
        finding_severity=body.finding_severity, finding_module=body.finding_module,
        owner=body.owner, deadline=dl, notes=body.notes,
    )
    audit(request, current_user, "remediation_create", f"scan={task_id} finding={body.finding_name}")
    return t

@app.patch("/api/remediation/{rem_id}")
async def patch_remediation(rem_id: int, body: RemediationUpdate, request: Request,
                            current_user: dict = Depends(require_role("admin", "operator"))):
    kwargs = {}
    if body.status is not None:
        if body.status not in ("open", "in_progress", "fixed", "verified", "wontfix"):
            raise HTTPException(status_code=400, detail="Invalid status")
        kwargs["status"] = body.status
    if body.owner is not None:
        kwargs["owner"] = body.owner
    if body.deadline is not None:
        try:
            kwargs["deadline"] = datetime.fromisoformat(body.deadline) if body.deadline else None
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid deadline format")
    if body.notes is not None:
        kwargs["notes"] = body.notes
    t = update_remediation_task(rem_id, **kwargs)
    if not t:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    audit(request, current_user, "remediation_update", f"id={rem_id} {list(kwargs.keys())}")
    return t

@app.delete("/api/remediation/{rem_id}")
async def remove_remediation(rem_id: int, request: Request,
                             current_user: dict = Depends(require_role("admin"))):
    ok = delete_remediation_task(rem_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    audit(request, current_user, "remediation_delete", f"id={rem_id}")
    return {"ok": True}

@app.post("/api/scan/{task_id}/remediation/bulk")
async def bulk_create_remediation(task_id: str, body: RemediationBulk, request: Request,
                                  current_user: dict = Depends(require_role("admin", "operator"))):
    created = bulk_create_remediation_tasks(task_id, body.findings)
    audit(request, current_user, "remediation_bulk_create", f"scan={task_id} count={len(created)}")
    stats = get_remediation_stats(task_id)
    return {"created": len(created), "tasks": created, "stats": stats}

# ── Intelligence Sync ────────────────────────────────────

@app.get("/admin/intel-sync/status")
async def intel_sync_status(current_user: dict = Depends(require_role("admin"))):
    logs = get_intel_sync_logs(limit=10)
    counts = get_intel_cache_counts()
    # Find last sync per source
    last_sync = {}
    for entry in logs:
        src = entry["source"]
        if src not in last_sync:
            last_sync[src] = entry["synced_at"]
    return {"logs": logs, "counts": counts, "last_sync": last_sync}

@app.post("/admin/intel-sync/run")
async def intel_sync_run(request: Request,
                         current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_intel_sync
    result = run_intel_sync.delay()
    audit(request, current_user, "intel_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}

@app.post("/admin/intel-sync/attack")
async def intel_sync_attack(request: Request,
                            current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_attack_sync
    result = run_attack_sync.delay()
    audit(request, current_user, "attack_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}

@app.post("/admin/intel-sync/euvd")
async def intel_sync_euvd(request: Request,
                          current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_euvd_sync
    result = run_euvd_sync.delay()
    audit(request, current_user, "euvd_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}

# ── MISP API ─────────────────────────────────────────────

@app.post("/admin/intel-sync/misp")
async def intel_sync_misp(request: Request,
                          current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_misp_sync
    result = run_misp_sync.delay()
    audit(request, current_user, "misp_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}

@app.post("/api/misp/export/{task_id}")
async def api_misp_export(task_id: str, request: Request,
                          current_user: dict = Depends(require_role("admin", "operator"))):
    from modules.misp_integration import export_scan_to_misp, is_misp_configured
    if not is_misp_configured():
        raise HTTPException(status_code=503, detail="MISP not configured")
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = export_scan_to_misp(scan, task_id)
    audit(request, current_user, "misp_export", f"task_id={task_id} event_id={result.get('event_id')}")
    return result

@app.get("/api/misp/search")
async def api_misp_search(value: str = Query(..., min_length=2),
                          type: str = Query(None),
                          limit: int = Query(20, le=100),
                          current_user: dict = Depends(get_current_user)):
    from modules.misp_integration import lookup_misp_indicator
    results = lookup_misp_indicator(value, attr_type=type)
    return results[:limit]

@app.get("/api/misp/events")
async def api_misp_events(q: str = Query("", min_length=0),
                          limit: int = Query(20, le=100),
                          current_user: dict = Depends(get_current_user)):
    from modules.database import search_misp_events
    return search_misp_events(query=q, limit=limit)

# ── Shodan / URLhaus / GreyNoise API ─────────────────────

@app.get("/api/intel/shodan/lookup")
async def api_shodan_lookup(target: str = Query(..., min_length=4),
                            current_user: dict = Depends(get_current_user)):
    from modules.database import get_shodan_cache
    from modules.intelligence_sync import sync_shodan
    cached = get_shodan_cache(target)
    if cached:
        return cached
    result = sync_shodan(target)
    if not result:
        return {"ip": target, "ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
    return result

@app.get("/api/intel/urlhaus/lookup")
async def api_urlhaus_lookup(target: str = Query(..., min_length=2),
                             current_user: dict = Depends(get_current_user)):
    from modules.database import get_urlhaus_cache
    from modules.intelligence_sync import sync_urlhaus
    cached = get_urlhaus_cache(target)
    if cached:
        return cached
    result = sync_urlhaus(target)
    if not result:
        return {"host": target, "urls_count": 0, "blacklisted": False, "tags": [], "urls": []}
    return result

@app.get("/api/intel/greynoise/lookup")
async def api_greynoise_lookup(target: str = Query(..., min_length=4),
                               current_user: dict = Depends(get_current_user)):
    from modules.database import get_greynoise_cache
    from modules.intelligence_sync import sync_greynoise
    cached = get_greynoise_cache(target)
    if cached:
        return cached
    result = sync_greynoise(target)
    if not result:
        return {"ip": target, "noise": False, "riot": False, "classification": "unknown", "name": "N/A", "link": ""}
    return result

@app.get("/api/intel/target/enrich")
async def api_target_enrich(target: str = Query(..., min_length=2),
                            current_user: dict = Depends(get_current_user)):
    """Combined enrichment for a scan target (Shodan + URLhaus + GreyNoise)."""
    from modules.intelligence_sync import enrich_target
    return enrich_target(target)

# ── ExploitDB API ────────────────────────────────────────

@app.get("/api/intel/exploitdb/lookup")
async def api_exploitdb_lookup(cve_id: str = Query(..., pattern=r"^CVE-\d{4}-\d{4,7}$"),
                               current_user: dict = Depends(get_current_user)):
    from modules.database import get_exploitdb_by_cve
    results = get_exploitdb_by_cve(cve_id)
    return {"cve_id": cve_id, "count": len(results), "exploits": results}

@app.get("/api/intel/exploitdb/search")
async def api_exploitdb_search(q: str = Query(..., min_length=2),
                               limit: int = Query(20, le=100),
                               current_user: dict = Depends(get_current_user)):
    from modules.database import search_exploitdb
    return search_exploitdb(query=q, limit=limit)

@app.post("/admin/intel-sync/exploitdb")
async def intel_sync_exploitdb(request: Request,
                               current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_exploitdb_sync
    result = run_exploitdb_sync.delay()
    audit(request, current_user, "exploitdb_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}

# ── MalwareBazaar API ────────────────────────────────────

@app.get("/api/intel/malwarebazaar/lookup")
async def api_malwarebazaar_lookup(hash: str = Query(..., min_length=32),
                                   current_user: dict = Depends(get_current_user)):
    from modules.database import get_malwarebazaar_by_hash
    from modules.intelligence_sync import lookup_malwarebazaar
    cached = get_malwarebazaar_by_hash(hash)
    if cached:
        return {"hash": hash, "found": True, **cached}
    result = lookup_malwarebazaar(hash)
    if not result:
        return {"hash": hash, "found": False}
    return {"hash": hash, "found": True, **result}

@app.post("/admin/intel-sync/malwarebazaar")
async def intel_sync_malwarebazaar(request: Request,
                                   current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_malwarebazaar_sync
    result = run_malwarebazaar_sync.delay()
    audit(request, current_user, "malwarebazaar_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}

# ── ATT&CK API ───────────────────────────────────────────

@app.get("/api/attack/techniques")
async def api_attack_techniques(q: str = "", tactic: str = "", limit: int = Query(50, le=200),
                                current_user: dict = Depends(get_current_user)):
    return search_attack_techniques(query=q, tactic=tactic, limit=limit)

@app.get("/api/attack/technique/{technique_id}")
async def api_attack_technique_detail(technique_id: str,
                                      current_user: dict = Depends(get_current_user)):
    t = get_attack_technique(technique_id)
    if not t:
        raise HTTPException(status_code=404, detail="Technique not found")
    t["mitigations"] = get_mitigations_for_technique(technique_id)
    return t

@app.get("/api/attack/tactics")
async def api_attack_tactics(current_user: dict = Depends(get_current_user)):
    return get_attack_tactics()

@app.get("/api/attack/cwe/{cwe_id}")
async def api_attack_cwe(cwe_id: str, current_user: dict = Depends(get_current_user)):
    return get_techniques_for_cwe(cwe_id)

@app.get("/api/euvd/lookup")
async def api_euvd_lookup(cve_id: str = Query(..., pattern=r"^CVE-\d{4}-\d{4,7}$"),
                           current_user: dict = Depends(get_current_user)):
    result = get_euvd_by_cve(cve_id)
    if not result:
        return {"cve_id": cve_id, "found": False}
    result["found"] = True
    return result

@app.get("/api/finding/enrich")
async def finding_enrich(cve_id: str = Query(..., pattern=r"^CVE-\d{4}-\d{4,7}$"),
                         current_user: dict = Depends(require_role("admin", "operator"))):
    from modules.intelligence_sync import enrich_finding
    result = enrich_finding(cve_id)
    return result

# ── Retest ───────────────────────────────────────────────

@app.post("/api/remediation/{rem_id}/retest")
async def trigger_retest(rem_id: int, request: Request,
                         current_user: dict = Depends(require_role("admin", "operator"))):
    task = get_remediation_task_by_id(rem_id)
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    if task["status"] != "fixed":
        raise HTTPException(status_code=400, detail="Only tasks with status 'fixed' can be retested")
    if task.get("retest_status") == "running":
        raise HTTPException(status_code=409, detail="Retest already in progress")

    # Get target from the associated scan
    scan = get_scan_by_task_id(task["scan_id"])
    if not scan:
        raise HTTPException(status_code=404, detail="Associated scan not found")

    from modules.tasks import retest_finding
    celery_result = retest_finding.delay(
        rem_id, task["finding_name"], scan["target"], task["finding_module"]
    )
    from modules.database import update_remediation_task as _update_rem
    _update_rem(rem_id,
                retest_task_id=celery_result.id,
                retest_status="pending",
                retest_at=datetime.now(timezone.utc))
    audit(request, current_user, "retest_trigger", f"rem={rem_id} celery={celery_result.id}")
    return {"message": "Retest started", "task_id": celery_result.id}

@app.get("/api/remediation/{rem_id}/retest/status")
async def retest_status(rem_id: int,
                        current_user: dict = Depends(require_role("admin", "operator"))):
    task = get_remediation_task_by_id(rem_id)
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    return {
        "remediation_id": rem_id,
        "status": task["status"],
        "retest_status": task.get("retest_status"),
        "retest_at": task.get("retest_at"),
        "retest_result": task.get("retest_result"),
    }

# ── Security Score Timeline ──────────────────────────────

_RISK_PL_TO_EN = {
    "KRYTYCZNE": "CRITICAL", "WYSOKIE": "HIGH",
    "ŚREDNIE": "MEDIUM", "SREDNIE": "MEDIUM", "NISKIE": "LOW",
}
_RISK_SCORE_MAP = {
    "CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 15,
    # Legacy PL keys for backward compat
    "KRYTYCZNE": 90, "WYSOKIE": 70, "ŚREDNIE": 40, "SREDNIE": 40, "NISKIE": 15,
}

def _normalize_risk(risk: str) -> str:
    """Normalize PL risk level to EN. Pass-through if already EN."""
    if not risk:
        return risk
    return _RISK_PL_TO_EN.get(risk.upper(), risk.upper())

def _extract_severity_counts(raw: dict) -> dict:
    """Extract finding severity counts from raw scan data."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    # Walk through known module keys that contain findings lists
    for key in raw:
        if key in ("nuclei", "sqlmap", "ai_analysis"):
            continue
        val = raw[key]
        if not isinstance(val, dict):
            continue
        findings = val.get("findings", [])
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity", "")).lower()
            if sev in counts:
                counts[sev] += 1
    # Nuclei results
    nuclei = raw.get("nuclei", {})
    if isinstance(nuclei, dict):
        for item in nuclei.get("results", nuclei.get("findings", [])):
            if isinstance(item, dict):
                sev = str(item.get("severity", item.get("info", {}).get("severity", ""))).lower()
                if sev in counts:
                    counts[sev] += 1
    # sqlmap
    sqlmap = raw.get("sqlmap", {})
    if isinstance(sqlmap, dict) and sqlmap.get("vulnerable"):
        counts["critical"] += 1
    return counts

@app.get("/api/target/{target:path}/timeline")
async def target_timeline(target: str,
                          current_user: dict = Depends(require_role("admin", "operator"))):
    scans = get_scans_by_target(target)
    if not scans:
        return {"target": target, "timeline": [], "improvement": "N/A", "fix_rate": "N/A"}

    timeline = []
    for s in scans:
        raw = s["raw"]
        ai = raw.get("ai_analysis", {})

        # Risk score: prefer ai_analysis.risk_score, fallback to risk_level mapping
        risk_score = ai.get("risk_score")
        if risk_score is None:
            risk_score = _RISK_SCORE_MAP.get(s["risk_level"], 50) if s["risk_level"] else 50

        sev_counts = _extract_severity_counts(raw)
        rem = get_remediation_counts_for_scan(s["task_id"])

        timeline.append({
            "date": s["created_at"][:10] if s["created_at"] else None,
            "task_id": s["task_id"],
            "risk_score": risk_score,
            "risk_level": s["risk_level"],
            "profile": s["profile"],
            "findings_total": s["findings_count"],
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "low": sev_counts["low"],
            "remediated": rem["remediated"],
            "verified": rem["verified"],
        })

    # Calculate improvement (first vs last)
    first_score = timeline[0]["risk_score"]
    last_score = timeline[-1]["risk_score"]
    diff = first_score - last_score
    if diff > 0:
        improvement = f"-{diff} point{'s' if diff != 1 else ''} (improved)"
    elif diff < 0:
        improvement = f"+{abs(diff)} point{'s' if abs(diff) != 1 else ''} (degraded)"
    else:
        improvement = "no change"

    # Fix rate: total remediated / total findings across all scans
    total_rem = sum(t["remediated"] for t in timeline)
    total_findings = sum(t["findings_total"] for t in timeline)
    fix_rate = f"{round(total_rem / total_findings * 100)}%" if total_findings > 0 else "N/A"

    return {
        "target": target,
        "timeline": timeline,
        "improvement": improvement,
        "fix_rate": fix_rate,
    }

@app.get("/api/dashboard/security-scores")
async def dashboard_security_scores(
        current_user: dict = Depends(require_role("admin", "operator"))):
    targets = get_unique_targets_with_stats()
    results = []
    for t in targets:
        last_risk = t["last_risk_level"]
        prev_risk = t["prev_risk_level"]
        last_score = _RISK_SCORE_MAP.get(last_risk, 50) if last_risk else 50
        prev_score = _RISK_SCORE_MAP.get(prev_risk, 50) if prev_risk else None

        if prev_score is not None:
            if last_score < prev_score:
                trend = "improving"
            elif last_score > prev_score:
                trend = "degrading"
            else:
                trend = "stable"
        else:
            trend = "new"

        results.append({
            "target": t["target"],
            "scan_count": t["scan_count"],
            "last_scan_at": t["last_scan_at"],
            "last_task_id": t["last_task_id"],
            "risk_score": last_score,
            "risk_level": last_risk,
            "findings_count": t["last_findings_count"],
            "trend": trend,
        })
    return {"targets": results}
