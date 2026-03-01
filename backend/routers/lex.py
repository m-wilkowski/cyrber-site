"""LEX Policy CRUD and ad-hoc validation API."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timezone

from backend.deps import get_current_user, require_role
from modules.database import SessionLocal
from modules.lex import LexPolicyModel, LexPolicy, LexEngine

router = APIRouter(prefix="/api/lex", tags=["lex"])


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Schemas ──────────────────────────────────────────────────────


class PolicyCreate(BaseModel):
    organization_id: int
    mission_id: Optional[str] = None
    name: str
    scope_cidrs: List[str] = []
    excluded_hosts: List[str] = []
    allowed_modules: List[str] = []
    excluded_modules: List[str] = []
    time_windows: List[dict] = []
    require_approval_cvss: float = 9.0
    max_duration_seconds: int = 28800
    max_targets: int = 50
    mode: str = "COMES"


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    scope_cidrs: Optional[List[str]] = None
    excluded_hosts: Optional[List[str]] = None
    allowed_modules: Optional[List[str]] = None
    excluded_modules: Optional[List[str]] = None
    time_windows: Optional[List[dict]] = None
    require_approval_cvss: Optional[float] = None
    max_duration_seconds: Optional[int] = None
    max_targets: Optional[int] = None
    mode: Optional[str] = None
    is_active: Optional[bool] = None


class ValidateRequest(BaseModel):
    policy_id: int
    target: str
    module: str = ""
    cvss: float = 0.0


# ── Helpers ──────────────────────────────────────────────────────


def _row_to_dict(row: LexPolicyModel) -> dict:
    return {
        "id": row.id,
        "organization_id": row.organization_id,
        "mission_id": row.mission_id,
        "name": row.name,
        "scope_cidrs": row.scope_cidrs or [],
        "excluded_hosts": row.excluded_hosts or [],
        "allowed_modules": row.allowed_modules or [],
        "excluded_modules": row.excluded_modules or [],
        "time_windows": row.time_windows or [],
        "require_approval_cvss": row.require_approval_cvss,
        "max_duration_seconds": row.max_duration_seconds,
        "max_targets": row.max_targets,
        "mode": row.mode,
        "is_active": row.is_active,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "created_by": row.created_by,
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


# ── Endpoints ────────────────────────────────────────────────────


@router.get("/policies")
async def list_policies(
    org_id: Optional[int] = None,
    user=Depends(get_current_user),
    db=Depends(_get_db),
):
    """List LEX policies, optionally filtered by organization."""
    query = db.query(LexPolicyModel)
    if org_id is not None:
        query = query.filter(LexPolicyModel.organization_id == org_id)
    rows = query.order_by(LexPolicyModel.id.desc()).all()
    return [_row_to_dict(r) for r in rows]


@router.post("/policies", status_code=201)
async def create_policy(
    body: PolicyCreate,
    user=Depends(require_role("admin")),
    db=Depends(_get_db),
):
    """Create a new LEX policy."""
    row = LexPolicyModel(
        organization_id=body.organization_id,
        mission_id=body.mission_id,
        name=body.name,
        scope_cidrs=body.scope_cidrs,
        excluded_hosts=body.excluded_hosts,
        allowed_modules=body.allowed_modules,
        excluded_modules=body.excluded_modules,
        time_windows=body.time_windows,
        require_approval_cvss=body.require_approval_cvss,
        max_duration_seconds=body.max_duration_seconds,
        max_targets=body.max_targets,
        mode=body.mode,
        is_active=True,
        created_by=user.get("sub", "system"),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _row_to_dict(row)


@router.get("/policies/{policy_id}")
async def get_policy(
    policy_id: int,
    user=Depends(get_current_user),
    db=Depends(_get_db),
):
    """Get a single LEX policy by ID."""
    row = db.query(LexPolicyModel).filter(LexPolicyModel.id == policy_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _row_to_dict(row)


@router.put("/policies/{policy_id}")
async def update_policy(
    policy_id: int,
    body: PolicyUpdate,
    user=Depends(require_role("admin")),
    db=Depends(_get_db),
):
    """Update a LEX policy."""
    row = db.query(LexPolicyModel).filter(LexPolicyModel.id == policy_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")

    for field_name in (
        "name", "scope_cidrs", "excluded_hosts", "allowed_modules",
        "excluded_modules", "time_windows", "require_approval_cvss",
        "max_duration_seconds", "max_targets", "mode", "is_active",
    ):
        val = getattr(body, field_name, None)
        if val is not None:
            setattr(row, field_name, val)

    db.commit()
    db.refresh(row)
    return _row_to_dict(row)


@router.post("/validate")
async def validate_adhoc(
    body: ValidateRequest,
    user=Depends(get_current_user),
    db=Depends(_get_db),
):
    """Ad-hoc validation against a specific policy."""
    row = db.query(LexPolicyModel).filter(
        LexPolicyModel.id == body.policy_id,
        LexPolicyModel.is_active == True,  # noqa: E712
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Active policy not found")

    policy = _row_to_policy(row)
    engine = LexEngine()

    started_at = datetime.now(timezone.utc)
    decision = engine.validate_all(
        target=body.target,
        module=body.module,
        cvss=body.cvss,
        started_at=started_at,
        policy=policy,
    )

    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "requires_approval": decision.requires_approval,
        "warnings": decision.warnings,
    }
