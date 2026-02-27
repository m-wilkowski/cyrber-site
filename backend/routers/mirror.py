"""CYRBER MIRROR — Organization profile API endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from backend.deps import get_current_user, require_role
from backend.mirror import (
    MirrorEngine,
    OrganizationProfileModel,
    _row_to_profile,
)
from modules.database import SessionLocal

router = APIRouter(prefix="/api/mirror", tags=["mirror"])


# ── DB session dependency ────────────────────────────────────────


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Helpers ──────────────────────────────────────────────────────


def _profile_to_dict(row: OrganizationProfileModel) -> dict:
    return {
        "id": row.id,
        "target": row.target,
        "last_updated": str(row.last_updated) if row.last_updated else None,
        "missions_count": row.missions_count or 0,
        "patch_cycle_days": row.patch_cycle_days,
        "phishing_click_rate": row.phishing_click_rate,
        "credential_reuse_incidents": row.credential_reuse_incidents or 0,
        "unreviewed_services": row.unreviewed_services or 0,
        "predispositions": row.predispositions or {},
        "patterns": row.patterns or [],
        "genome_report": row.genome_report,
        "genome_generated_at": str(row.genome_generated_at) if row.genome_generated_at else None,
    }


def _get_profile_or_404(db, target: str) -> OrganizationProfileModel:
    row = db.query(OrganizationProfileModel).filter(
        OrganizationProfileModel.target == target,
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Organization profile not found")
    return row


# ═════════════════════════════════════════════════════════════════
# Endpoints
# ═════════════════════════════════════════════════════════════════


@router.get("/profiles")
async def list_profiles(
    user: dict = Depends(get_current_user),
    db=Depends(_get_db),
):
    """List all organization profiles."""
    rows = (
        db.query(OrganizationProfileModel)
        .order_by(OrganizationProfileModel.last_updated.desc())
        .limit(50)
        .all()
    )
    return [_profile_to_dict(r) for r in rows]


@router.get("/profiles/{target}")
async def get_profile(
    target: str,
    user: dict = Depends(get_current_user),
    db=Depends(_get_db),
):
    """Get organization profile for a specific target."""
    row = _get_profile_or_404(db, target)
    return _profile_to_dict(row)


@router.post("/profiles/{target}/genome")
async def generate_genome(
    target: str,
    user: dict = Depends(require_role("admin", "operator")),
    db=Depends(_get_db),
):
    """Generate or regenerate Security Genome Report."""
    row = _get_profile_or_404(db, target)
    profile = _row_to_profile(row)

    engine = MirrorEngine()
    report = engine.generate_genome(profile, db)

    return {
        "genome": report,
        "generated_at": str(datetime.now(timezone.utc)),
    }


@router.get("/profiles/{target}/genome")
async def get_genome(
    target: str,
    user: dict = Depends(get_current_user),
    db=Depends(_get_db),
):
    """Get the latest Security Genome Report."""
    row = _get_profile_or_404(db, target)
    if not row.genome_report:
        raise HTTPException(status_code=404, detail="Genome report not yet generated")
    return {
        "genome": row.genome_report,
        "generated_at": str(row.genome_generated_at) if row.genome_generated_at else None,
    }
