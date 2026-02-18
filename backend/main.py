from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan
from modules.llm_analyze import analyze_scan_results
from modules.tasks import full_scan_task

app = FastAPI(title="CYRBER API", version="0.1.0")

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
async def scan_start(target: str = Query(...)):
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
