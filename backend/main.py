from fastapi import FastAPI, Query, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.hash import sha256_crypt
from datetime import datetime, timedelta
import sys
import os
import secrets
import ipaddress
import unicodedata
import re as _re
import requests as http_requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan
from modules.llm_analyze import analyze_scan_results
from modules.tasks import full_scan_task

# ── JWT config ──
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 8

CYRBER_USER = os.getenv("CYRBER_USER", "admin")
CYRBER_PASS = os.getenv("CYRBER_PASS", "cyrber2024")
# Hash the password at startup for constant-time comparison
CYRBER_PASS_HASH = sha256_crypt.hash(CYRBER_PASS)

bearer_scheme = HTTPBearer(auto_error=False)
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# ── App ──
app = FastAPI(title="CYRBER API", version="0.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.mount("/static", StaticFiles(directory="static"), name="static")

# ── Database ──
from modules.database import init_db, get_scan_history, get_scan_by_task_id
from modules.database import add_schedule, get_schedules, delete_schedule
from modules.database import save_audit_log, get_audit_logs
from modules.pdf_report import generate_report
from modules.exploit_chains import generate_exploit_chains
from modules.hacker_narrative import generate_hacker_narrative

init_db()

# ── Audit helper ──
def audit(request: Request, user: str, action: str, target: str = None):
    ip = request.client.host if request.client else "unknown"
    save_audit_log(user=user, action=action, target=target, ip_address=ip)

# ── Public routes (no auth) ──

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
@limiter.limit("10/minute")
async def auth_login(request: Request, body: LoginRequest):
    ip = request.client.host if request.client else "unknown"
    if body.username == CYRBER_USER and sha256_crypt.verify(body.password, CYRBER_PASS_HASH):
        token = create_token(body.username)
        save_audit_log(user=body.username, action="login", ip_address=ip)
        return {"token": token, "token_type": "bearer", "expires_in": JWT_EXPIRE_HOURS * 3600}
    save_audit_log(user=body.username, action="login_failed", ip_address=ip)
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/login")
async def login_page():
    return FileResponse("static/login.html")

@app.get("/ui")
async def ui():
    return FileResponse("static/index.html")

@app.get("/dashboard")
async def dashboard():
    return FileResponse("static/dashboard.html")

@app.get("/scheduler")
async def scheduler():
    return FileResponse("static/scheduler.html")

@app.get("/phishing")
async def phishing_page():
    return FileResponse("static/phishing.html")

@app.get("/osint")
async def osint_page():
    return FileResponse("static/osint.html", media_type="text/html")

@app.get("/")
async def root():
    return {"status": "CYRBER online"}

# ── Protected routes (JWT required) ──

@app.get("/scan/nmap")
async def run_nmap(target: str = Query(...), user: str = Depends(get_current_user)):
    return nmap_scan(target)

@app.get("/scan/nuclei")
async def run_nuclei(target: str = Query(...), user: str = Depends(get_current_user)):
    return nuclei_scan(target)

@app.get("/scan/full")
async def run_full(target: str = Query(...), user: str = Depends(get_current_user)):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    return {"target": target, "ports": nmap.get("ports", []), "nmap_raw": nmap, "nuclei": nuclei}

@app.get("/scan/analyze")
async def run_analyze(target: str = Query(...), user: str = Depends(get_current_user)):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    scan_data = {"target": target, "ports": nmap.get("ports", []), "nuclei": nuclei}
    return analyze_scan_results(scan_data)

@app.get("/scan/start")
@limiter.limit("5/minute")
async def scan_start(request: Request, target: str = Query(...), user: str = Depends(get_current_user)):
    task = full_scan_task.delay(target)
    audit(request, user, "scan_start", target)
    return {"task_id": task.id, "status": "started", "target": target}

@app.get("/scan/status/{task_id}")
async def scan_status(task_id: str, user: str = Depends(get_current_user)):
    task = full_scan_task.AsyncResult(task_id)
    if task.state == "PENDING":
        return {"task_id": task_id, "status": "pending"}
    elif task.state == "SUCCESS":
        return {"task_id": task_id, "status": "completed", "result": task.result}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "failed", "error": str(task.info)}
    else:
        return {"task_id": task_id, "status": task.state}

@app.get("/scans")
async def scans_history(limit: int = 20, user: str = Depends(get_current_user)):
    return get_scan_history(limit)

@app.get("/scans/{task_id}")
async def scan_detail(task_id: str, user: str = Depends(get_current_user)):
    return get_scan_by_task_id(task_id)

@app.get("/scans/{task_id}/pdf")
async def scan_pdf(request: Request, task_id: str, user: str = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        return {"error": "Scan not found"}
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
async def scan_chains(task_id: str, user: str = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("exploit_chains"):
        return {"target": scan["target"], "exploit_chains": scan["exploit_chains"], "cached": True}
    chains = generate_exploit_chains(scan)
    return chains

@app.get("/scans/{task_id}/narrative")
async def scan_narrative(task_id: str, user: str = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("hacker_narrative"):
        return {"target": scan["target"], **scan["hacker_narrative"], "cached": True}
    narrative = generate_hacker_narrative(scan)
    return narrative

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
async def run_gobuster(target: str = Query(...), user: str = Depends(get_current_user)):
    return gobuster_scan(target)

@app.get("/scan/whatweb")
async def run_whatweb(target: str = Query(...), user: str = Depends(get_current_user)):
    return whatweb_scan(target)

@app.get("/scan/testssl")
async def run_testssl(target: str = Query(...), user: str = Depends(get_current_user)):
    return testssl_scan(target)

@app.get("/scan/sqlmap")
async def run_sqlmap(target: str = Query(...), user: str = Depends(get_current_user)):
    return sqlmap_scan(target)

@app.get("/scan/nikto")
async def run_nikto(target: str = Query(...), user: str = Depends(get_current_user)):
    return nikto_scan(target)

@app.get("/scan/harvester")
async def run_harvester(target: str = Query(...), user: str = Depends(get_current_user)):
    return harvester_scan(target)

@app.get("/scan/masscan")
async def run_masscan(target: str = Query(...), user: str = Depends(get_current_user)):
    return masscan_scan(target)

# requires paid API plan - module ready
# @app.get("/scan/censys")
# async def run_censys(target: str = Query(...), user: str = Depends(get_current_user)):
#     return censys_scan(target)

@app.get("/scan/ipinfo")
async def run_ipinfo(target: str = Query(...), user: str = Depends(get_current_user)):
    return ipinfo_scan(target)

@app.get("/scan/enum4linux")
async def run_enum4linux(target: str = Query(...), user: str = Depends(get_current_user)):
    return enum4linux_scan(target)

@app.get("/scan/mitre")
async def run_mitre(task_id: str = Query(...), user: str = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return mitre_map(scan)

@app.get("/scan/abuseipdb")
async def run_abuseipdb(target: str = Query(...), user: str = Depends(get_current_user)):
    return abuseipdb_scan(target)

@app.get("/scan/otx")
async def run_otx(target: str = Query(...), user: str = Depends(get_current_user)):
    return otx_scan(target)

@app.get("/scan/exploitdb")
async def run_exploitdb(task_id: str = Query(...), user: str = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return exploitdb_scan(scan)

@app.get("/scan/nvd")
async def run_nvd(task_id: str = Query(...), user: str = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return nvd_scan(scan)

@app.get("/scan/whois")
async def run_whois(target: str = Query(...), user: str = Depends(get_current_user)):
    return whois_scan(target)

@app.get("/scan/dnsrecon")
async def run_dnsrecon(target: str = Query(...), user: str = Depends(get_current_user)):
    return dnsrecon_scan(target)

@app.get("/scan/amass")
async def run_amass(target: str = Query(...), user: str = Depends(get_current_user)):
    return amass_scan(target)

@app.get("/scan/cwe")
async def run_cwe(task_id: str = Query(...), user: str = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return cwe_mapping(scan)

@app.get("/scan/owasp")
async def run_owasp(task_id: str = Query(...), user: str = Depends(get_current_user)):
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
async def run_wpscan(target: str = Query(...), user: str = Depends(get_current_user)):
    return wpscan_scan(target)

@app.get("/scan/zap")
async def run_zap(target: str = Query(...), user: str = Depends(get_current_user)):
    return zap_scan(target)

@app.get("/scan/wapiti")
async def run_wapiti(target: str = Query(...), user: str = Depends(get_current_user)):
    return wapiti_scan(target)

@app.get("/scan/joomscan")
async def run_joomscan(target: str = Query(...), user: str = Depends(get_current_user)):
    return joomscan_scan(target)

@app.get("/scan/cmsmap")
async def run_cmsmap(target: str = Query(...), user: str = Depends(get_current_user)):
    return cmsmap_scan(target)

@app.get("/scan/droopescan")
async def run_droopescan(target: str = Query(...), user: str = Depends(get_current_user)):
    return droopescan_scan(target)

@app.get("/scan/retirejs")
async def run_retirejs(target: str = Query(...), user: str = Depends(get_current_user)):
    return retirejs_scan(target)

@app.get("/scan/subfinder")
async def run_subfinder(target: str = Query(...), user: str = Depends(get_current_user)):
    return subfinder_scan(target)

@app.get("/scan/httpx")
async def run_httpx(target: str = Query(...), user: str = Depends(get_current_user)):
    return httpx_scan(target)

@app.get("/scan/naabu")
async def run_naabu(target: str = Query(...), user: str = Depends(get_current_user)):
    return naabu_scan(target)

@app.get("/scan/katana")
async def run_katana(target: str = Query(...), user: str = Depends(get_current_user)):
    return katana_scan(target)

@app.get("/scan/dnsx")
async def run_dnsx(target: str = Query(...), user: str = Depends(get_current_user)):
    return dnsx_scan(target)

@app.get("/scan/netdiscover")
async def run_netdiscover(target: str = Query(...), user: str = Depends(get_current_user)):
    return netdiscover_scan(target)

@app.get("/scan/arpscan")
async def run_arpscan(target: str = Query(...), user: str = Depends(get_current_user)):
    return arpscan_scan(target)

@app.get("/scan/fping")
async def run_fping(target: str = Query(...), user: str = Depends(get_current_user)):
    return fping_scan(target)

@app.get("/scan/traceroute")
async def run_traceroute(target: str = Query(...), user: str = Depends(get_current_user)):
    return traceroute_scan(target)

@app.get("/scan/nbtscan")
async def run_nbtscan(target: str = Query(...), user: str = Depends(get_current_user)):
    return nbtscan_scan(target)

@app.get("/scan/snmpwalk")
async def run_snmpwalk(target: str = Query(...), user: str = Depends(get_current_user)):
    return snmpwalk_scan(target)

@app.get("/scan/netexec")
async def run_netexec(target: str = Query(...), user: str = Depends(get_current_user)):
    return netexec_scan(target)

@app.get("/scan/bloodhound")
async def run_bloodhound(target: str = Query(...), user: str = Depends(get_current_user)):
    return bloodhound_scan(target)

@app.get("/scan/responder")
async def run_responder(target: str = Query(...), user: str = Depends(get_current_user)):
    return responder_scan(target)

@app.get("/scan/fierce")
async def run_fierce(target: str = Query(...), user: str = Depends(get_current_user)):
    return fierce_scan(target)

@app.get("/scan/smbmap")
async def run_smbmap(target: str = Query(...), user: str = Depends(get_current_user)):
    return smbmap_scan(target)

@app.get("/scan/onesixtyone")
async def run_onesixtyone(target: str = Query(...), user: str = Depends(get_current_user)):
    return onesixtyone_scan(target)

@app.get("/scan/ikescan")
async def run_ikescan(target: str = Query(...), user: str = Depends(get_current_user)):
    return ikescan_scan(target)

@app.get("/scan/sslyze")
async def run_sslyze(target: str = Query(...), user: str = Depends(get_current_user)):
    return sslyze_scan(target)

@app.get("/scan/searchsploit")
async def run_searchsploit(target: str = Query(...), user: str = Depends(get_current_user)):
    return searchsploit_scan(target)

@app.get("/scan/impacket")
async def run_impacket(target: str = Query(...), user: str = Depends(get_current_user)):
    return impacket_scan(target)

from modules.tasks import osint_scan_task
from modules.database import get_osint_history, get_osint_by_task_id
from modules.pdf_report import generate_osint_report

class OsintStartRequest(BaseModel):
    target: str
    search_type: str = "domain"

@app.get("/osint/start")
@limiter.limit("5/minute")
async def osint_start_get(request: Request, target: str = Query(...), search_type: str = Query("domain"), user: str = Depends(get_current_user)):
    task = osint_scan_task.delay(target, search_type=search_type)
    audit(request, user, "osint_start", target)
    return {"task_id": task.id, "status": "started", "target": target, "search_type": search_type}

@app.post("/osint/start")
@limiter.limit("5/minute")
async def osint_start_post(request: Request, body: OsintStartRequest, user: str = Depends(get_current_user)):
    task = osint_scan_task.delay(body.target, search_type=body.search_type)
    audit(request, user, "osint_start", body.target)
    return {"task_id": task.id, "status": "started", "target": body.target, "search_type": body.search_type}

@app.get("/osint/status/{task_id}")
async def osint_status(task_id: str, user: str = Depends(get_current_user)):
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
async def osint_history(limit: int = 20, user: str = Depends(get_current_user)):
    return get_osint_history(limit)

@app.get("/osint/{task_id}/pdf")
async def osint_pdf(request: Request, task_id: str, user: str = Depends(get_current_user)):
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
async def wazuh_webhook(request: Request, alert: WazuhAlert, user: str = Depends(get_current_user)):
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
async def generic_webhook(request: Request, payload: dict, user: str = Depends(get_current_user)):
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
async def agent_start(request: Request, target: str = Query(...), user: str = Depends(get_current_user)):
    task = agent_scan_task.delay(target)
    audit(request, user, "agent_start", target)
    return {"task_id": task.id, "status": "started", "target": target, "mode": "agent"}

class ScheduleCreate(BaseModel):
    target: str
    interval_hours: int

@app.post("/schedules")
async def create_schedule(request: Request, schedule: ScheduleCreate, user: str = Depends(get_current_user)):
    if schedule.interval_hours < 1:
        raise HTTPException(status_code=400, detail="interval_hours must be >= 1")
    result = add_schedule(schedule.target, schedule.interval_hours)
    audit(request, user, "schedule_create", schedule.target)
    return result

@app.get("/schedules")
async def list_schedules(user: str = Depends(get_current_user)):
    return get_schedules()

@app.delete("/schedules/{schedule_id}")
async def remove_schedule(request: Request, schedule_id: int, user: str = Depends(get_current_user)):
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
async def phishing_campaigns(user: str = Depends(get_current_user)):
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

@app.post("/phishing/campaigns")
async def phishing_create_campaign(request: Request, campaign: PhishingCampaignCreate, user: str = Depends(get_current_user)):
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
async def phishing_delete_campaign(request: Request, campaign_id: int, user: str = Depends(get_current_user)):
    try:
        result = _gophish_delete(f"campaigns/{campaign_id}")
        audit(request, user, "phishing_delete", str(campaign_id))
        return result
    except http_requests.ConnectionError:
        raise HTTPException(status_code=503, detail="GoPhish not available")
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

@app.get("/phishing/campaigns/{campaign_id}/results")
async def phishing_campaign_results(campaign_id: int, user: str = Depends(get_current_user)):
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

class MultiTargetScan(BaseModel):
    targets: list[str]

@app.post("/scan/multi")
@limiter.limit("3/minute")
async def multi_scan(request: Request, body: MultiTargetScan, user: str = Depends(get_current_user)):
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

    tasks = []
    for target in expanded:
        task = full_scan_task.delay(target)
        tasks.append({"task_id": task.id, "target": target, "status": "started"})
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
async def notifications_status(user: str = Depends(get_current_user)):
    return {
        "email": bool(SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_TO),
        "slack": bool(SLACK_WEBHOOK_URL),
        "discord": bool(DISCORD_WEBHOOK_URL),
        "telegram": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID),
    }

@app.post("/notifications/test")
@limiter.limit("3/minute")
async def notifications_test(request: Request, user: str = Depends(get_current_user)):
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
async def audit_logs(limit: int = 100, user: str = Depends(get_current_user)):
    return get_audit_logs(limit)
