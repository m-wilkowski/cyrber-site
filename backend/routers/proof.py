"""CYRBER PROOF — Cryptographic audit trail API endpoints."""

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException

from backend.deps import get_current_user, require_role
from backend.proof import (
    MerkleTreeModel,
    ProofEngine,
    ProofLeafModel,
)
from modules.database import SessionLocal

router = APIRouter(prefix="/api/proof", tags=["proof"])

PROOF_API_KEY = os.getenv("PROOF_API_KEY", "proof_demo_key")


# ── DB session dependency ────────────────────────────────────────


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── X-Proof-Key auth ────────────────────────────────────────────


def _verify_proof_key(x_proof_key: str = Header(...)):
    if x_proof_key != PROOF_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid proof API key")
    return x_proof_key


# ── Helpers ──────────────────────────────────────────────────────


def _tree_to_dict(row: MerkleTreeModel) -> dict:
    return {
        "id": row.id,
        "root_hash": row.root_hash,
        "leaves_count": row.leaves_count,
        "created_at": str(row.created_at) if row.created_at else None,
        "scan_id": row.scan_id,
        "target": row.target,
    }


def _leaf_to_dict(row: ProofLeafModel) -> dict:
    return {
        "id": row.id,
        "finding_id": row.finding_id,
        "scan_id": row.scan_id,
        "target": row.target,
        "finding_hash": row.finding_hash,
        "timestamp": str(row.timestamp) if row.timestamp else None,
        "signature": row.signature,
        "leaf_index": row.leaf_index,
        "merkle_path": row.merkle_path or [],
    }


# ═════════════════════════════════════════════════════════════════
# Endpoints
# ═════════════════════════════════════════════════════════════════


@router.post("/seal/{scan_id}")
async def seal_scan(
    scan_id: str,
    user: dict = Depends(require_role("admin", "operator")),
    db=Depends(_get_db),
):
    """Seal a completed scan into a Merkle tree."""
    engine = ProofEngine()
    try:
        tree = engine.seal_scan(scan_id, db)
    except ValueError as e:
        msg = str(e)
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=msg)
        if "already sealed" in msg:
            raise HTTPException(status_code=409, detail=msg)
        raise HTTPException(status_code=400, detail=msg)

    return {
        "root_hash": tree.root_hash,
        "leaves_count": tree.leaves_count,
        "scan_id": tree.scan_id,
        "target": tree.target,
        "created_at": str(tree.created_at),
    }


@router.get("/trees")
async def list_trees(
    user: dict = Depends(get_current_user),
    db=Depends(_get_db),
):
    """List all sealed scans (Merkle trees)."""
    rows = (
        db.query(MerkleTreeModel)
        .order_by(MerkleTreeModel.created_at.desc())
        .limit(100)
        .all()
    )
    return [_tree_to_dict(r) for r in rows]


@router.get("/trees/{scan_id}")
async def get_tree(
    scan_id: str,
    user: dict = Depends(get_current_user),
    db=Depends(_get_db),
):
    """Get Merkle tree details with all leaves."""
    tree = db.query(MerkleTreeModel).filter(
        MerkleTreeModel.scan_id == scan_id,
    ).first()
    if not tree:
        raise HTTPException(status_code=404, detail="Scan not sealed")

    leaves = (
        db.query(ProofLeafModel)
        .filter(ProofLeafModel.scan_id == scan_id)
        .order_by(ProofLeafModel.leaf_index)
        .all()
    )

    result = _tree_to_dict(tree)
    result["leaves"] = [_leaf_to_dict(l) for l in leaves]
    return result


@router.get("/verify/{scan_id}/{finding_id}")
async def verify_finding(
    scan_id: str,
    finding_id: str,
    _key: str = Depends(_verify_proof_key),
    db=Depends(_get_db),
):
    """Verify a single finding via its Merkle path. Auth: X-Proof-Key header."""
    tree = db.query(MerkleTreeModel).filter(
        MerkleTreeModel.scan_id == scan_id,
    ).first()
    if not tree:
        raise HTTPException(status_code=404, detail="Scan not sealed")

    leaf = db.query(ProofLeafModel).filter(
        ProofLeafModel.scan_id == scan_id,
        ProofLeafModel.finding_id == finding_id,
    ).first()
    if not leaf:
        raise HTTPException(status_code=404, detail="Finding not found in sealed scan")

    valid = ProofEngine.verify_leaf(
        leaf.finding_hash,
        leaf.merkle_path or [],
        tree.root_hash,
    )

    return {
        "valid": valid,
        "root_hash": tree.root_hash,
        "finding_hash": leaf.finding_hash,
        "verified_at": str(datetime.now(timezone.utc)),
    }


@router.get("/feed")
async def proof_feed(
    _key: str = Depends(_verify_proof_key),
    db=Depends(_get_db),
):
    """Continuous feed of sealed scans for insurers. Auth: X-Proof-Key header."""
    rows = (
        db.query(MerkleTreeModel)
        .order_by(MerkleTreeModel.created_at.desc())
        .limit(100)
        .all()
    )

    total = db.query(MerkleTreeModel).count()

    return {
        "scans": [_tree_to_dict(r) for r in rows],
        "generated_at": str(datetime.now(timezone.utc)),
        "total_sealed": total,
    }
