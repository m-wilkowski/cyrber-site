"""Remediation tracker: CRUD, bulk, retest, security score timeline."""

from fastapi import APIRouter, Depends, HTTPException, Request
from datetime import datetime, timezone

from backend.deps import (
    get_current_user, require_role, audit,
    _RISK_SCORE_MAP, _extract_severity_counts,
)
from backend.schemas import RemediationCreate, RemediationUpdate, RemediationBulk
from modules.database import (
    get_scan_by_task_id, get_remediation_tasks, create_remediation_task,
    get_remediation_task_by_id, update_remediation_task,
    delete_remediation_task, bulk_create_remediation_tasks,
    get_remediation_stats, get_scans_by_target, get_remediation_counts_for_scan,
)

router = APIRouter(tags=["remediation"])


@router.get("/api/scan/{task_id}/remediation")
async def get_scan_remediation(task_id: str, current_user: dict = Depends(get_current_user)):
    tasks = get_remediation_tasks(task_id)
    stats = get_remediation_stats(task_id)
    return {"tasks": tasks, "stats": stats}


@router.post("/api/scan/{task_id}/remediation")
async def create_scan_remediation(
    task_id: str,
    body: RemediationCreate,
    request: Request,
    current_user: dict = Depends(require_role("admin", "operator")),
):
    dl = None
    if body.deadline:
        try:
            dl = datetime.fromisoformat(body.deadline)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid deadline format")
    t = create_remediation_task(
        scan_id=task_id,
        finding_name=body.finding_name,
        finding_severity=body.finding_severity,
        finding_module=body.finding_module,
        owner=body.owner,
        deadline=dl,
        notes=body.notes,
    )
    audit(request, current_user, "remediation_create", f"scan={task_id} finding={body.finding_name}")
    return t


@router.patch("/api/remediation/{rem_id}")
async def patch_remediation(
    rem_id: int,
    body: RemediationUpdate,
    request: Request,
    current_user: dict = Depends(require_role("admin", "operator")),
):
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


@router.delete("/api/remediation/{rem_id}")
async def remove_remediation(
    rem_id: int,
    request: Request,
    current_user: dict = Depends(require_role("admin")),
):
    ok = delete_remediation_task(rem_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    audit(request, current_user, "remediation_delete", f"id={rem_id}")
    return {"ok": True}


@router.post("/api/scan/{task_id}/remediation/bulk")
async def bulk_create_remediation(
    task_id: str,
    body: RemediationBulk,
    request: Request,
    current_user: dict = Depends(require_role("admin", "operator")),
):
    created = bulk_create_remediation_tasks(task_id, body.findings)
    audit(request, current_user, "remediation_bulk_create", f"scan={task_id} count={len(created)}")
    stats = get_remediation_stats(task_id)
    return {"created": len(created), "tasks": created, "stats": stats}


# ── Retest ──

@router.post("/api/remediation/{rem_id}/retest")
async def trigger_retest(
    rem_id: int,
    request: Request,
    current_user: dict = Depends(require_role("admin", "operator")),
):
    task = get_remediation_task_by_id(rem_id)
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    if task["status"] != "fixed":
        raise HTTPException(status_code=400, detail="Only tasks with status 'fixed' can be retested")
    if task.get("retest_status") == "running":
        raise HTTPException(status_code=409, detail="Retest already in progress")

    scan = get_scan_by_task_id(task["scan_id"])
    if not scan:
        raise HTTPException(status_code=404, detail="Associated scan not found")

    from modules.tasks import retest_finding
    celery_result = retest_finding.delay(
        rem_id, task["finding_name"], scan["target"], task["finding_module"]
    )
    update_remediation_task(
        rem_id,
        retest_task_id=celery_result.id,
        retest_status="pending",
        retest_at=datetime.now(timezone.utc),
    )
    audit(request, current_user, "retest_trigger", f"rem={rem_id} celery={celery_result.id}")
    return {"message": "Retest started", "task_id": celery_result.id}


@router.get("/api/remediation/{rem_id}/retest/status")
async def retest_status(
    rem_id: int,
    current_user: dict = Depends(require_role("admin", "operator")),
):
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


# ── Security Score Timeline ──

@router.get("/api/target/{target:path}/timeline")
async def target_timeline(
    target: str,
    current_user: dict = Depends(require_role("admin", "operator")),
):
    scans = get_scans_by_target(target)
    if not scans:
        return {"target": target, "timeline": [], "improvement": "N/A", "fix_rate": "N/A"}

    timeline = []
    for s in scans:
        raw = s["raw"]
        ai = raw.get("ai_analysis", {})

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

    first_score = timeline[0]["risk_score"]
    last_score = timeline[-1]["risk_score"]
    diff = first_score - last_score
    if diff > 0:
        improvement = f"-{diff} point{'s' if diff != 1 else ''} (improved)"
    elif diff < 0:
        improvement = f"+{abs(diff)} point{'s' if abs(diff) != 1 else ''} (degraded)"
    else:
        improvement = "no change"

    total_rem = sum(t["remediated"] for t in timeline)
    total_findings = sum(t["findings_total"] for t in timeline)
    fix_rate = f"{round(total_rem / total_findings * 100)}%" if total_findings > 0 else "N/A"

    return {
        "target": target,
        "timeline": timeline,
        "improvement": improvement,
        "fix_rate": fix_rate,
    }
