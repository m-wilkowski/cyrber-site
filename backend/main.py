from fastapi import FastAPI, Query, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
import sys
import os
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan
from modules.llm_analyze import analyze_scan_results
from modules.tasks import full_scan_task

security = HTTPBasic()
limiter = Limiter(key_func=get_remote_address)

CYRBER_USER = os.getenv("CYRBER_USER", "admin")
CYRBER_PASS = os.getenv("CYRBER_PASS", "cyrber2024")

def require_auth(credentials: HTTPBasicCredentials = Depends(security)):
    ok_user = secrets.compare_digest(credentials.username.encode(), CYRBER_USER.encode())
    ok_pass = secrets.compare_digest(credentials.password.encode(), CYRBER_PASS.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

app = FastAPI(title="CYRBER API", version="0.1.0", dependencies=[Depends(require_auth)])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/ui")
async def ui():
    return FileResponse("static/index.html")

@app.get("/")
async def root():
    return {"status": "CYRBER online"}

@app.get("/scan/nmap")
async def run_nmap(target: str = Query(...)):
    return nmap_scan(target)

@app.get("/scan/nuclei")
async def run_nuclei(target: str = Query(...)):
    return nuclei_scan(target)

@app.get("/scan/full")
async def run_full(target: str = Query(...)):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    return {"target": target, "ports": nmap.get("ports", []), "nmap_raw": nmap, "nuclei": nuclei}

@app.get("/scan/analyze")
async def run_analyze(target: str = Query(...)):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    scan_data = {"target": target, "ports": nmap.get("ports", []), "nuclei": nuclei}
    return analyze_scan_results(scan_data)

@app.get("/scan/start")
@limiter.limit("5/minute")
async def scan_start(request: Request, target: str = Query(...)):
    task = full_scan_task.delay(target)
    return {"task_id": task.id, "status": "started", "target": target}

@app.get("/scan/status/{task_id}")
async def scan_status(task_id: str):
    task = full_scan_task.AsyncResult(task_id)
    if task.state == "PENDING":
        return {"task_id": task_id, "status": "pending"}
    elif task.state == "SUCCESS":
        return {"task_id": task_id, "status": "completed", "result": task.result}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "failed", "error": str(task.info)}
    else:
        return {"task_id": task_id, "status": task.state}

from modules.database import init_db, get_scan_history, get_scan_by_task_id
from modules.database import add_schedule, get_schedules, delete_schedule
from modules.pdf_report import generate_report

init_db()

@app.get("/scans")
async def scans_history(limit: int = 20):
    return get_scan_history(limit)

@app.get("/scans/{task_id}")
async def scan_detail(task_id: str):
    return get_scan_by_task_id(task_id)

@app.get("/scans/{task_id}/pdf")
async def scan_pdf(task_id: str):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        return {"error": "Scan not found"}
    pdf_bytes = generate_report(scan)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cyrber_{scan['target']}_{task_id[:8]}.pdf"}
    )

from modules.gobuster_scan import scan as gobuster_scan
from modules.whatweb_scan import scan as whatweb_scan
from modules.testssl_scan import scan as testssl_scan
from modules.sqlmap_scan import scan as sqlmap_scan

@app.get("/scan/gobuster")
async def run_gobuster(target: str = Query(...)):
    return gobuster_scan(target)

@app.get("/scan/whatweb")
async def run_whatweb(target: str = Query(...)):
    return whatweb_scan(target)

@app.get("/scan/testssl")
async def run_testssl(target: str = Query(...)):
    return testssl_scan(target)

@app.get("/scan/sqlmap")
async def run_sqlmap(target: str = Query(...)):
    return sqlmap_scan(target)

from modules.webhook import WazuhAlert, extract_target

@app.post("/webhook/wazuh")
@limiter.limit("30/minute")
async def wazuh_webhook(request: Request, alert: WazuhAlert):
    target = extract_target(alert)
    if not target:
        return {"status": "ignored", "reason": "no valid target extracted"}
    task = full_scan_task.delay(target)
    return {
        "status": "scan_started",
        "target": target,
        "task_id": task.id,
        "trigger": "wazuh_alert",
        "rule_id": alert.rule_id
    }

@app.post("/webhook/generic")
@limiter.limit("30/minute")
async def generic_webhook(request: Request, payload: dict):
    target = payload.get("target") or payload.get("ip") or payload.get("host")
    if not target:
        return {"status": "ignored", "reason": "no target field in payload"}
    task = full_scan_task.delay(target)
    return {
        "status": "scan_started",
        "target": target,
        "task_id": task.id,
        "trigger": "webhook"
    }

from modules.tasks import agent_scan_task

@app.get("/agent/start")
@limiter.limit("3/minute")
async def agent_start(request: Request, target: str = Query(...)):
    task = agent_scan_task.delay(target)
    return {"task_id": task.id, "status": "started", "target": target, "mode": "agent"}

@app.get("/dashboard")
async def dashboard():
    return FileResponse("static/dashboard.html")

class ScheduleCreate(BaseModel):
    target: str
    interval_hours: int

@app.post("/schedules")
async def create_schedule(schedule: ScheduleCreate):
    if schedule.interval_hours < 1:
        raise HTTPException(status_code=400, detail="interval_hours must be >= 1")
    return add_schedule(schedule.target, schedule.interval_hours)

@app.get("/schedules")
async def list_schedules():
    return get_schedules()

@app.delete("/schedules/{schedule_id}")
async def remove_schedule(schedule_id: int):
    ok = delete_schedule(schedule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "deleted", "id": schedule_id}

class MultiTargetScan(BaseModel):
    targets: list[str]

@app.post("/scan/multi")
@limiter.limit("3/minute")
async def multi_scan(request: Request, body: MultiTargetScan):
    if not body.targets:
        raise HTTPException(status_code=400, detail="targets list is empty")
    if len(body.targets) > 20:
        raise HTTPException(status_code=400, detail="max 20 targets per request")
    tasks = []
    for target in body.targets:
        task = full_scan_task.delay(target)
        tasks.append({"task_id": task.id, "target": target, "status": "started"})
    return {"count": len(tasks), "tasks": tasks}
