"""OSINT scan routes: start, status, history, PDF."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
import unicodedata
import re as _re

from backend.deps import limiter, get_current_user, require_role, audit
from backend.schemas import OsintStartRequest
from modules.tasks import osint_scan_task
from modules.database import get_osint_history, get_osint_by_task_id
from modules.pdf_report import generate_osint_report

router = APIRouter(tags=["osint"])


@router.get("/osint/start")
@limiter.limit("5/minute")
async def osint_start_get(
    request: Request,
    target: str = Query(...),
    search_type: str = Query("domain"),
    user: dict = Depends(require_role("admin", "operator")),
):
    task = osint_scan_task.delay(target, search_type=search_type)
    audit(request, user, "osint_start", target)
    return {"task_id": task.id, "status": "started", "target": target, "search_type": search_type}


@router.post("/osint/start")
@limiter.limit("5/minute")
async def osint_start_post(
    request: Request,
    body: OsintStartRequest,
    user: dict = Depends(require_role("admin", "operator")),
):
    task = osint_scan_task.delay(body.target, search_type=body.search_type)
    audit(request, user, "osint_start", body.target)
    return {"task_id": task.id, "status": "started", "target": body.target, "search_type": body.search_type}


@router.get("/osint/status/{task_id}")
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


@router.get("/osint/history")
async def osint_history(limit: int = 20, user: dict = Depends(get_current_user)):
    return get_osint_history(limit)


@router.get("/osint/{task_id}/pdf")
async def osint_pdf(request: Request, task_id: str, user: dict = Depends(get_current_user)):
    scan = get_osint_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="OSINT scan not found")
    pdf_bytes = generate_osint_report(scan)
    audit(request, user, "osint_pdf_download", scan.get("target"))
    raw_target = scan.get("target", "unknown")
    safe_target = unicodedata.normalize("NFKD", raw_target).encode("ascii", "ignore").decode("ascii")
    safe_target = _re.sub(r'[^\w\-.]', '_', safe_target).strip('_') or "scan"
    filename = f"cyrber_osint_{safe_target}_{task_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
