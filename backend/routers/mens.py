"""MENS v2 — missions API (observe/think/act/learn)."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from backend.deps import get_current_user, require_role
from backend.validators import require_valid_target
from modules.database import SessionLocal
from modules.lex import LexPolicyModel, LexPolicy
from modules.mind_agent import MensMissionModel, MensIterationModel

router = APIRouter(prefix="/api/mens", tags=["mens"])


# ── DB session dependency ────────────────────────────────────────


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Request schemas ──────────────────────────────────────────────


class CreateMissionRequest(BaseModel):
    target: str
    policy_id: int
    mode: str = "COMES"
    organization_id: Optional[int] = None


# ── Helpers ──────────────────────────────────────────────────────


def _mission_to_dict(row: MensMissionModel) -> dict:
    return {
        "id": row.id,
        "organization_id": row.organization_id,
        "mission_id": row.mission_id,
        "target": row.target,
        "policy_id": row.policy_id,
        "mode": row.mode,
        "status": row.status,
        "started_at": str(row.started_at) if row.started_at else None,
        "completed_at": str(row.completed_at) if row.completed_at else None,
        "iterations_count": row.iterations_count,
        "findings_count": row.findings_count,
        "summary": row.summary,
        "created_by": row.created_by,
    }


def _iteration_to_dict(row: MensIterationModel) -> dict:
    return {
        "id": row.id,
        "mission_id": row.mission_id,
        "iteration_number": row.iteration_number,
        "module_used": row.module_used,
        "target": row.target,
        "reason": row.reason,
        "confidence": row.confidence,
        "result_summary": row.result_summary,
        "created_at": str(row.created_at) if row.created_at else None,
    }


def _row_to_policy(row: LexPolicyModel) -> LexPolicy:
    return LexPolicy(
        mission_id=row.mission_id or "",
        organization_id=row.organization_id,
        scope_cidrs=row.scope_cidrs or [],
        excluded_hosts=row.excluded_hosts or [],
        allowed_modules=row.allowed_modules or [],
        excluded_modules=row.excluded_modules or [],
        time_windows=row.time_windows or [],
        require_approval_cvss=row.require_approval_cvss,
        max_duration_seconds=row.max_duration_seconds,
        max_targets=row.max_targets,
        mode=row.mode or "COMES",
    )


def _policy_to_dict(policy: LexPolicy) -> dict:
    """Serialize LexPolicy to JSON-safe dict for Celery task."""
    return {
        "mission_id": policy.mission_id,
        "organization_id": policy.organization_id,
        "scope_cidrs": policy.scope_cidrs,
        "excluded_hosts": policy.excluded_hosts,
        "allowed_modules": policy.allowed_modules,
        "excluded_modules": policy.excluded_modules,
        "time_windows": policy.time_windows,
        "require_approval_cvss": policy.require_approval_cvss,
        "max_duration_seconds": policy.max_duration_seconds,
        "max_targets": policy.max_targets,
        "mode": policy.mode,
    }


def _get_mission_or_404(db, mission_id: str) -> MensMissionModel:
    """Lookup by UUID mission_id string."""
    row = db.query(MensMissionModel).filter(
        MensMissionModel.mission_id == mission_id
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
    """Create and start a new MENS v2 mission."""
    body.target = require_valid_target(body.target)

    # Validate mode
    if body.mode not in ("COMES", "LIBER", "ITERUM"):
        raise HTTPException(status_code=400, detail="Invalid mode; must be COMES, LIBER, or ITERUM")

    # Load policy
    policy_row = db.query(LexPolicyModel).filter(
        LexPolicyModel.id == body.policy_id,
        LexPolicyModel.is_active == True,  # noqa: E712
    ).first()
    if not policy_row:
        raise HTTPException(status_code=400, detail="LEX policy not found or inactive")

    org_id = body.organization_id or policy_row.organization_id

    mission_uuid = str(uuid.uuid4())
    mission = MensMissionModel(
        organization_id=org_id,
        mission_id=mission_uuid,
        target=body.target,
        policy_id=body.policy_id,
        mode=body.mode,
        status="pending",
        started_at=datetime.now(timezone.utc),
        created_by=user["username"],
    )
    db.add(mission)
    db.commit()
    db.refresh(mission)

    # Dispatch Celery task
    policy = _row_to_policy(policy_row)
    from modules.mens_task import run_mens_mission
    run_mens_mission.delay(mission.id, body.target, _policy_to_dict(policy), org_id)

    return _mission_to_dict(mission)


@router.get("/missions")
async def list_missions(
    org_id: Optional[int] = None,
    user: dict = Depends(get_current_user),
    db=Depends(_get_db),
):
    """List recent MENS missions, optionally filtered by org."""
    query = db.query(MensMissionModel)
    if org_id is not None:
        query = query.filter(MensMissionModel.organization_id == org_id)
    rows = query.order_by(MensMissionModel.started_at.desc()).limit(20).all()
    return [_mission_to_dict(r) for r in rows]


@router.get("/missions/{mission_id}")
async def get_mission(
    mission_id: str,
    user: dict = Depends(get_current_user),
    db=Depends(_get_db),
):
    """Get mission details with iterations (lookup by UUID string)."""
    mission = _get_mission_or_404(db, mission_id)
    iterations = (
        db.query(MensIterationModel)
        .filter(MensIterationModel.mission_id == mission.id)
        .order_by(MensIterationModel.iteration_number)
        .all()
    )
    result = _mission_to_dict(mission)
    result["iterations"] = [_iteration_to_dict(it) for it in iterations]
    return result


@router.post("/missions/{mission_id}/approve")
async def approve_mission(
    mission_id: str,
    user: dict = Depends(require_role("admin", "operator")),
    db=Depends(_get_db),
):
    """Approve a paused COMES mission — resume execution."""
    mission = _get_mission_or_404(db, mission_id)

    if mission.status != "paused":
        raise HTTPException(status_code=400, detail=f"Cannot approve mission in status '{mission.status}'")

    mission.status = "running"
    db.commit()

    # Re-dispatch Celery task to continue
    policy_row = db.query(LexPolicyModel).filter(LexPolicyModel.id == mission.policy_id).first()
    if policy_row:
        policy = _row_to_policy(policy_row)
        from modules.mens_task import run_mens_mission
        run_mens_mission.delay(mission.id, mission.target, _policy_to_dict(policy), mission.organization_id)

    return {"status": "approved", "mission_id": mission.mission_id}


@router.post("/missions/{mission_id}/abort")
async def abort_mission(
    mission_id: str,
    user: dict = Depends(require_role("admin", "operator")),
    db=Depends(_get_db),
):
    """Abort a running or paused mission."""
    mission = _get_mission_or_404(db, mission_id)
    mission.status = "aborted"
    mission.completed_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "aborted", "mission_id": mission.mission_id}
