from fastapi import FastAPI, Query, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response, JSONResponse
from sse_starlette.sse import EventSourceResponse

_NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"}
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
import json
import re as _re
import requests as http_requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan
from modules.llm_analyze import analyze_scan_results
from modules.tasks import full_scan_task
from modules.scan_profiles import get_profiles_list, get_profile

# ── Redis config ──
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# ── JWT config ──
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 8

bearer_scheme = HTTPBearer(auto_error=False)
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.utcnow(),
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
app = FastAPI(title="CYRBER API", version="0.1.0")
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
)
from modules.pdf_report import generate_report
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
        update_user(user["id"], last_login=datetime.utcnow())
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

@app.get("/")
async def root():
    return {"status": "CYRBER online"}

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

# ── Protected routes (JWT required) ──

@app.get("/scan/nmap")
async def run_nmap(target: str = Query(...), user: dict = Depends(get_current_user)):
    return nmap_scan(target)

@app.get("/scan/nuclei")
async def run_nuclei(target: str = Query(...), user: dict = Depends(get_current_user)):
    return nuclei_scan(target)

@app.get("/scan/full")
async def run_full(target: str = Query(...), user: dict = Depends(get_current_user)):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    return {"target": target, "ports": nmap.get("ports", []), "nmap_raw": nmap, "nuclei": nuclei}

@app.get("/scan/analyze")
async def run_analyze(target: str = Query(...), user: dict = Depends(get_current_user)):
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
@limiter.limit("5/minute")
async def scan_start_post(request: Request, body: ScanStartRequest, user: dict = Depends(require_role("admin", "operator"))):
    if not get_profile(body.profile):
        raise HTTPException(status_code=400, detail=f"Invalid profile: {body.profile}")
    task = full_scan_task.delay(body.target, profile=body.profile.upper())
    audit(request, user, "scan_start", body.target)
    return {"task_id": task.id, "status": "started", "target": body.target, "profile": body.profile.upper()}

@app.get("/scan/start")
@limiter.limit("5/minute")
async def scan_start(request: Request, target: str = Query(...), profile: str = Query("STRAZNIK"), user: dict = Depends(require_role("admin", "operator"))):
    if not get_profile(profile):
        profile = "STRAZNIK"
    task = full_scan_task.delay(target, profile=profile.upper())
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
    return get_scan_by_task_id(task_id)

@app.get("/scans/{task_id}/pdf")
async def scan_pdf(request: Request, task_id: str, user: dict = Depends(get_current_user)):
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
async def run_gobuster(target: str = Query(...), user: dict = Depends(get_current_user)):
    return gobuster_scan(target)

@app.get("/scan/whatweb")
async def run_whatweb(target: str = Query(...), user: dict = Depends(get_current_user)):
    return whatweb_scan(target)

@app.get("/scan/testssl")
async def run_testssl(target: str = Query(...), user: dict = Depends(get_current_user)):
    return testssl_scan(target)

@app.get("/scan/sqlmap")
async def run_sqlmap(target: str = Query(...), user: dict = Depends(get_current_user)):
    return sqlmap_scan(target)

@app.get("/scan/nikto")
async def run_nikto(target: str = Query(...), user: dict = Depends(get_current_user)):
    return nikto_scan(target)

@app.get("/scan/harvester")
async def run_harvester(target: str = Query(...), user: dict = Depends(get_current_user)):
    return harvester_scan(target)

@app.get("/scan/masscan")
async def run_masscan(target: str = Query(...), user: dict = Depends(get_current_user)):
    return masscan_scan(target)

# requires paid API plan - module ready
# @app.get("/scan/censys")
# async def run_censys(target: str = Query(...), user: dict = Depends(get_current_user)):
#     return censys_scan(target)

@app.get("/scan/ipinfo")
async def run_ipinfo(target: str = Query(...), user: dict = Depends(get_current_user)):
    return ipinfo_scan(target)

@app.get("/scan/enum4linux")
async def run_enum4linux(target: str = Query(...), user: dict = Depends(get_current_user)):
    return enum4linux_scan(target)

@app.get("/scan/mitre")
async def run_mitre(task_id: str = Query(...), user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return mitre_map(scan)

@app.get("/scan/abuseipdb")
async def run_abuseipdb(target: str = Query(...), user: dict = Depends(get_current_user)):
    return abuseipdb_scan(target)

@app.get("/scan/otx")
async def run_otx(target: str = Query(...), user: dict = Depends(get_current_user)):
    return otx_scan(target)

@app.get("/scan/exploitdb")
async def run_exploitdb(task_id: str = Query(...), user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return exploitdb_scan(scan)

@app.get("/scan/nvd")
async def run_nvd(task_id: str = Query(...), user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return nvd_scan(scan)

@app.get("/scan/whois")
async def run_whois(target: str = Query(...), user: dict = Depends(get_current_user)):
    return whois_scan(target)

@app.get("/scan/dnsrecon")
async def run_dnsrecon(target: str = Query(...), user: dict = Depends(get_current_user)):
    return dnsrecon_scan(target)

@app.get("/scan/amass")
async def run_amass(target: str = Query(...), user: dict = Depends(get_current_user)):
    return amass_scan(target)

@app.get("/scan/cwe")
async def run_cwe(task_id: str = Query(...), user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return cwe_mapping(scan)

@app.get("/scan/owasp")
async def run_owasp(task_id: str = Query(...), user: dict = Depends(get_current_user)):
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
async def run_wpscan(target: str = Query(...), user: dict = Depends(get_current_user)):
    return wpscan_scan(target)

@app.get("/scan/zap")
async def run_zap(target: str = Query(...), user: dict = Depends(get_current_user)):
    return zap_scan(target)

@app.get("/scan/wapiti")
async def run_wapiti(target: str = Query(...), user: dict = Depends(get_current_user)):
    return wapiti_scan(target)

@app.get("/scan/joomscan")
async def run_joomscan(target: str = Query(...), user: dict = Depends(get_current_user)):
    return joomscan_scan(target)

@app.get("/scan/cmsmap")
async def run_cmsmap(target: str = Query(...), user: dict = Depends(get_current_user)):
    return cmsmap_scan(target)

@app.get("/scan/droopescan")
async def run_droopescan(target: str = Query(...), user: dict = Depends(get_current_user)):
    return droopescan_scan(target)

@app.get("/scan/retirejs")
async def run_retirejs(target: str = Query(...), user: dict = Depends(get_current_user)):
    return retirejs_scan(target)

@app.get("/scan/subfinder")
async def run_subfinder(target: str = Query(...), user: dict = Depends(get_current_user)):
    return subfinder_scan(target)

@app.get("/scan/httpx")
async def run_httpx(target: str = Query(...), user: dict = Depends(get_current_user)):
    return httpx_scan(target)

@app.get("/scan/naabu")
async def run_naabu(target: str = Query(...), user: dict = Depends(get_current_user)):
    return naabu_scan(target)

@app.get("/scan/katana")
async def run_katana(target: str = Query(...), user: dict = Depends(get_current_user)):
    return katana_scan(target)

@app.get("/scan/dnsx")
async def run_dnsx(target: str = Query(...), user: dict = Depends(get_current_user)):
    return dnsx_scan(target)

@app.get("/scan/netdiscover")
async def run_netdiscover(target: str = Query(...), user: dict = Depends(get_current_user)):
    return netdiscover_scan(target)

@app.get("/scan/arpscan")
async def run_arpscan(target: str = Query(...), user: dict = Depends(get_current_user)):
    return arpscan_scan(target)

@app.get("/scan/fping")
async def run_fping(target: str = Query(...), user: dict = Depends(get_current_user)):
    return fping_scan(target)

@app.get("/scan/traceroute")
async def run_traceroute(target: str = Query(...), user: dict = Depends(get_current_user)):
    return traceroute_scan(target)

@app.get("/scan/nbtscan")
async def run_nbtscan(target: str = Query(...), user: dict = Depends(get_current_user)):
    return nbtscan_scan(target)

@app.get("/scan/snmpwalk")
async def run_snmpwalk(target: str = Query(...), user: dict = Depends(get_current_user)):
    return snmpwalk_scan(target)

@app.get("/scan/netexec")
async def run_netexec(target: str = Query(...), user: dict = Depends(get_current_user)):
    return netexec_scan(target)

@app.get("/scan/bloodhound")
async def run_bloodhound(target: str = Query(...), user: dict = Depends(get_current_user)):
    return bloodhound_scan(target)

@app.get("/scan/responder")
async def run_responder(target: str = Query(...), user: dict = Depends(get_current_user)):
    return responder_scan(target)

@app.get("/scan/fierce")
async def run_fierce(target: str = Query(...), user: dict = Depends(get_current_user)):
    return fierce_scan(target)

@app.get("/scan/smbmap")
async def run_smbmap(target: str = Query(...), user: dict = Depends(get_current_user)):
    return smbmap_scan(target)

@app.get("/scan/onesixtyone")
async def run_onesixtyone(target: str = Query(...), user: dict = Depends(get_current_user)):
    return onesixtyone_scan(target)

@app.get("/scan/ikescan")
async def run_ikescan(target: str = Query(...), user: dict = Depends(get_current_user)):
    return ikescan_scan(target)

@app.get("/scan/sslyze")
async def run_sslyze(target: str = Query(...), user: dict = Depends(get_current_user)):
    return sslyze_scan(target)

@app.get("/scan/searchsploit")
async def run_searchsploit(target: str = Query(...), user: dict = Depends(get_current_user)):
    return searchsploit_scan(target)

@app.get("/scan/impacket")
async def run_impacket(target: str = Query(...), user: dict = Depends(get_current_user)):
    return impacket_scan(target)

from modules.certipy_scan import run_certipy

@app.get("/scan/certipy")
async def scan_certipy(
    target: str = Query(...),
    dc_ip: str = Query(""),
    username: str = Query(""),
    password: str = Query(""),
    domain: str = Query(""),
    user: dict = Depends(get_current_user),
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

# ── Multi-target scan ──

class MultiTargetScan(BaseModel):
    targets: list[str]
    profile: str = "STRAZNIK"

@app.post("/scan/multi")
@limiter.limit("3/minute")
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
    tasks = []
    for target in expanded:
        task = full_scan_task.delay(target, profile=scan_profile)
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
