"""MENS autonomous agent — missions, iterations, LEX rules, COGITATIO stream."""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.deps import get_current_user, require_role, audit, _get_user_from_token
from backend.lex import LexRuleModel
from backend.validators import require_valid_target
from backend.mind_agent import (
    MensMissionModel,
    MensIterationModel,
)
from modules.database import SessionLocal

router = APIRouter(prefix="/api/mind", tags=["mind"])


# ── DB session dependency ────────────────────────────────────────


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Request / response schemas ───────────────────────────────────


class CreateMissionRequest(BaseModel):
    target: str
    objective: str
    lex_rule_id: str
    mode: str = "comes"


class CreateLexRuleRequest(BaseModel):
    name: str
    mission_id: Optional[str] = None
    scope_cidrs: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)
    allowed_hours: Optional[list[int]] = None
    max_cvss_without_approval: float = 7.0
    max_duration_minutes: int = 480
    allowed_modules: Optional[list[str]] = None
    require_comes_mode: bool = False


class RejectRequest(BaseModel):
    reason: Optional[str] = None


# ── Helpers ──────────────────────────────────────────────────────


def _mission_to_dict(row: MensMissionModel) -> dict:
    return {
        "id": row.id,
        "target": row.target,
        "objective": row.objective,
        "lex_rule_id": row.lex_rule_id,
        "mode": row.mode,
        "status": row.status,
        "fiducia": row.fiducia,
        "started_at": str(row.started_at) if row.started_at else None,
        "completed_at": str(row.completed_at) if row.completed_at else None,
        "created_by": row.created_by,
    }


def _iteration_to_dict(row: MensIterationModel) -> dict:
    return {
        "id": row.id,
        "mission_id": row.mission_id,
        "iteration_number": row.iteration_number,
        "phase": row.phase,
        "module_selected": row.module_selected,
        "module_args": row.module_args,
        "cogitatio": row.cogitatio,
        "result_summary": row.result_summary,
        "findings_count": row.findings_count,
        "head": row.head or "RATIO",
        "approved": row.approved,
        "created_at": str(row.created_at) if row.created_at else None,
    }


def _lex_rule_to_dict(row: LexRuleModel) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "mission_id": row.mission_id,
        "scope_cidrs": row.scope_cidrs,
        "excluded_hosts": row.excluded_hosts,
        "allowed_hours": row.allowed_hours,
        "max_cvss_without_approval": row.max_cvss_without_approval,
        "max_duration_minutes": row.max_duration_minutes,
        "allowed_modules": row.allowed_modules,
        "require_comes_mode": row.require_comes_mode,
        "active": row.active,
        "created_at": str(row.created_at) if row.created_at else None,
        "created_by": row.created_by,
    }


def _get_mission_or_404(db, mission_id: str) -> MensMissionModel:
    row = db.query(MensMissionModel).filter(
        MensMissionModel.id == mission_id
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Mission not found")
    return row


# ═════════════════════════════════════════════════════════════════
# Missions
# ═════════════════════════════════════════════════════════════════


@router.post("/missions")
async def create_mission(
    body: CreateMissionRequest,
    user: dict = Depends(require_role("admin", "operator")),
    db=Depends(_get_db),
):
    """Create a new MENS mission."""
    body.target = require_valid_target(body.target)
    # Validate LEX rule exists
    rule = db.query(LexRuleModel).filter(
        LexRuleModel.id == body.lex_rule_id,
        LexRuleModel.active == True,  # noqa: E712
    ).first()
    if not rule:
        raise HTTPException(status_code=400, detail="LEX rule not found or inactive")

    if body.mode not in ("comes", "liber", "iterum"):
        raise HTTPException(status_code=400, detail="Invalid mode; must be comes, liber, or iterum")

    mission = MensMissionModel(
        id=str(uuid.uuid4()),
        target=body.target,
        objective=body.objective,
        lex_rule_id=body.lex_rule_id,
        mode=body.mode,
        status="pending",
        started_at=datetime.now(timezone.utc),
        created_by=user["username"],
        fiducia=0.0,
    )
    db.add(mission)
    db.commit()
    db.refresh(mission)
    return _mission_to_dict(mission)


@router.get("/missions")
async def list_missions(
    user: dict = Depends(get_current_user),
    db=Depends(_get_db),
):
    """List recent MENS missions (max 20)."""
    rows = (
        db.query(MensMissionModel)
        .order_by(MensMissionModel.started_at.desc())
        .limit(20)
        .all()
    )
    return [_mission_to_dict(r) for r in rows]


@router.get("/missions/{mission_id}")
async def get_mission(
    mission_id: str,
    user: dict = Depends(get_current_user),
    db=Depends(_get_db),
):
    """Get mission details with iterations."""
    mission = _get_mission_or_404(db, mission_id)
    iterations = (
        db.query(MensIterationModel)
        .filter(MensIterationModel.mission_id == mission_id)
        .order_by(MensIterationModel.iteration_number)
        .all()
    )
    result = _mission_to_dict(mission)
    result["iterations"] = [_iteration_to_dict(it) for it in iterations]
    return result


@router.post("/missions/{mission_id}/start")
async def start_mission(
    mission_id: str,
    user: dict = Depends(require_role("admin", "operator")),
    db=Depends(_get_db),
):
    """Set mission to running and dispatch Celery task."""
    mission = _get_mission_or_404(db, mission_id)
    if mission.status not in ("pending", "paused"):
        raise HTTPException(status_code=400, detail=f"Cannot start mission in status '{mission.status}'")

    mission.status = "running"
    mission.started_at = datetime.now(timezone.utc)
    db.commit()

    from modules.mens_task import mens_run_task
    mens_run_task.delay(mission_id)

    return {"status": "started", "mission_id": mission_id}


@router.post("/missions/{mission_id}/abort")
async def abort_mission(
    mission_id: str,
    user: dict = Depends(require_role("admin", "operator")),
    db=Depends(_get_db),
):
    """Abort a running mission."""
    mission = _get_mission_or_404(db, mission_id)
    mission.status = "aborted"
    mission.completed_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "aborted", "mission_id": mission_id}


# ═════════════════════════════════════════════════════════════════
# COGITATIO live stream (SSE)
# ═════════════════════════════════════════════════════════════════


@router.get("/missions/{mission_id}/stream")
async def mission_stream(mission_id: str, token: str = Query(...)):
    """SSE stream of COGITATIO thoughts and mission status."""
    _get_user_from_token(token)

    last_iteration_count = 0

    async def event_generator():
        nonlocal last_iteration_count

        while True:
            db = SessionLocal()
            try:
                mission = db.query(MensMissionModel).filter(
                    MensMissionModel.id == mission_id
                ).first()
                if not mission:
                    yield f"data: {json.dumps({'type': 'error', 'message': 'Mission not found'})}\n\n"
                    return

                # Status event
                yield f"data: {json.dumps({'type': 'status', 'status': mission.status, 'fiducia': mission.fiducia})}\n\n"

                # Check for new iterations
                iterations = (
                    db.query(MensIterationModel)
                    .filter(MensIterationModel.mission_id == mission_id)
                    .order_by(MensIterationModel.iteration_number)
                    .all()
                )

                if len(iterations) > last_iteration_count:
                    for it in iterations[last_iteration_count:]:
                        # Cogitatio event
                        if it.cogitatio:
                            yield f"data: {json.dumps({'type': 'cogitatio', 'iteration_number': it.iteration_number, 'module': it.module_selected, 'head': it.head or 'RATIO', 'cogitatio': it.cogitatio})}\n\n"

                        # Full iteration event when phase == learn
                        if it.phase == "learn":
                            yield f"data: {json.dumps({'type': 'iteration', **_iteration_to_dict(it)})}\n\n"

                    last_iteration_count = len(iterations)

                # End stream on terminal status
                if mission.status in ("completed", "aborted"):
                    yield f"data: {json.dumps({'type': 'done', 'status': mission.status, 'fiducia': mission.fiducia})}\n\n"
                    return
            finally:
                db.close()

            await asyncio.sleep(2)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ═════════════════════════════════════════════════════════════════
# Iteration approval (COMES mode)
# ═════════════════════════════════════════════════════════════════


@router.post("/missions/{mission_id}/iterations/{iteration_id}/approve")
async def approve_iteration(
    mission_id: str,
    iteration_id: str,
    user: dict = Depends(require_role("admin", "operator")),
    db=Depends(_get_db),
):
    """Approve a pending iteration in COMES mode."""
    mission = _get_mission_or_404(db, mission_id)
    if mission.mode != "comes":
        raise HTTPException(status_code=400, detail="Approval only available in COMES mode")

    iteration = db.query(MensIterationModel).filter(
        MensIterationModel.id == iteration_id,
        MensIterationModel.mission_id == mission_id,
    ).first()
    if not iteration:
        raise HTTPException(status_code=404, detail="Iteration not found")

    iteration.approved = True
    db.commit()
    return {"status": "approved", "iteration_id": iteration_id}


@router.post("/missions/{mission_id}/iterations/{iteration_id}/reject")
async def reject_iteration(
    mission_id: str,
    iteration_id: str,
    body: RejectRequest = RejectRequest(),
    user: dict = Depends(require_role("admin", "operator")),
    db=Depends(_get_db),
):
    """Reject a pending iteration."""
    mission = _get_mission_or_404(db, mission_id)

    iteration = db.query(MensIterationModel).filter(
        MensIterationModel.id == iteration_id,
        MensIterationModel.mission_id == mission_id,
    ).first()
    if not iteration:
        raise HTTPException(status_code=404, detail="Iteration not found")

    iteration.approved = False
    if body.reason:
        iteration.cogitatio = (iteration.cogitatio or "") + f"\n\n[REJECTED: {body.reason}]"
    db.commit()
    return {"status": "rejected", "iteration_id": iteration_id}


# ═════════════════════════════════════════════════════════════════
# LEX rules
# ═════════════════════════════════════════════════════════════════


@router.get("/lex/rules")
async def list_lex_rules(
    user: dict = Depends(get_current_user),
    db=Depends(_get_db),
):
    """List active LEX rules."""
    rows = db.query(LexRuleModel).filter(
        LexRuleModel.active == True,  # noqa: E712
    ).all()
    return [_lex_rule_to_dict(r) for r in rows]


@router.post("/lex/rules")
async def create_lex_rule(
    body: CreateLexRuleRequest,
    user: dict = Depends(require_role("admin")),
    db=Depends(_get_db),
):
    """Create a new LEX rule (admin only)."""
    rule = LexRuleModel(
        id=str(uuid.uuid4()),
        name=body.name,
        mission_id=body.mission_id,
        scope_cidrs=body.scope_cidrs,
        excluded_hosts=body.excluded_hosts,
        allowed_hours=body.allowed_hours,
        max_cvss_without_approval=body.max_cvss_without_approval,
        max_duration_minutes=body.max_duration_minutes,
        allowed_modules=body.allowed_modules,
        require_comes_mode=body.require_comes_mode,
        active=True,
        created_at=datetime.now(timezone.utc),
        created_by=user["username"],
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _lex_rule_to_dict(rule)
