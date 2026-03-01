"""CYRBER Integrations API — CRUD, test, toggle for external connectors."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from backend.deps import get_current_user, require_role
from modules.database import SessionLocal
from modules.integrations.models import IntegrationConfig
from modules.integrations import create_integration

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


# ── Pydantic schemas ──


class IntegrationCreate(BaseModel):
    organization_id: int
    integration_type: str
    name: str
    config: dict = {}
    is_active: bool = False


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    config: Optional[dict] = None
    is_active: Optional[bool] = None


# ── Helpers ──


def _row_to_dict(row: IntegrationConfig) -> dict:
    return {
        "id": row.id,
        "organization_id": row.organization_id,
        "integration_type": row.integration_type,
        "name": row.name,
        "config": row.config or {},
        "is_active": row.is_active,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


# ── Endpoints ──


@router.get("")
async def list_integrations(
    organization_id: int = None,
    user=Depends(get_current_user),
):
    """List integrations, optionally filtered by org."""
    require_role(user, "operator")
    db = SessionLocal()
    try:
        q = db.query(IntegrationConfig)
        if organization_id:
            q = q.filter(IntegrationConfig.organization_id == organization_id)
        rows = q.order_by(IntegrationConfig.id).all()
        return {"integrations": [_row_to_dict(r) for r in rows]}
    finally:
        db.close()


@router.post("")
async def create_integration_config(
    body: IntegrationCreate,
    user=Depends(get_current_user),
):
    """Create a new integration config."""
    require_role(user, "operator")
    db = SessionLocal()
    try:
        row = IntegrationConfig(
            organization_id=body.organization_id,
            integration_type=body.integration_type,
            name=body.name,
            config=body.config,
            is_active=body.is_active,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return _row_to_dict(row)
    finally:
        db.close()


@router.get("/{integration_id}")
async def get_integration(
    integration_id: int,
    user=Depends(get_current_user),
):
    """Get integration details."""
    require_role(user, "operator")
    db = SessionLocal()
    try:
        row = db.query(IntegrationConfig).filter(IntegrationConfig.id == integration_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Integration not found")
        return _row_to_dict(row)
    finally:
        db.close()


@router.patch("/{integration_id}")
async def update_integration(
    integration_id: int,
    body: IntegrationUpdate,
    user=Depends(get_current_user),
):
    """Update integration config."""
    require_role(user, "operator")
    db = SessionLocal()
    try:
        row = db.query(IntegrationConfig).filter(IntegrationConfig.id == integration_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Integration not found")

        if body.name is not None:
            row.name = body.name
        if body.config is not None:
            row.config = body.config
        if body.is_active is not None:
            row.is_active = body.is_active
        row.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(row)
        return _row_to_dict(row)
    finally:
        db.close()


@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: int,
    user=Depends(get_current_user),
):
    """Delete an integration config."""
    require_role(user, "admin")
    db = SessionLocal()
    try:
        row = db.query(IntegrationConfig).filter(IntegrationConfig.id == integration_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Integration not found")
        db.delete(row)
        db.commit()
        return {"status": "deleted", "id": integration_id}
    finally:
        db.close()


@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: int,
    user=Depends(get_current_user),
):
    """Test connectivity for an integration."""
    require_role(user, "operator")
    db = SessionLocal()
    try:
        row = db.query(IntegrationConfig).filter(IntegrationConfig.id == integration_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Integration not found")

        cfg = row.config or {}
        cfg["enabled"] = "true"
        inst = create_integration(row.integration_type, cfg)
        if not inst:
            raise HTTPException(status_code=400, detail=f"Unknown type: {row.integration_type}")

        result = inst.test_connection()
        return {"integration_id": integration_id, "type": row.integration_type, "result": result}
    finally:
        db.close()


@router.post("/{integration_id}/toggle")
async def toggle_integration(
    integration_id: int,
    user=Depends(get_current_user),
):
    """Toggle integration active/inactive."""
    require_role(user, "operator")
    db = SessionLocal()
    try:
        row = db.query(IntegrationConfig).filter(IntegrationConfig.id == integration_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Integration not found")

        row.is_active = not row.is_active
        row.updated_at = datetime.now(timezone.utc)
        db.commit()
        return {"id": integration_id, "is_active": row.is_active}
    finally:
        db.close()
