"""CYRBER PROOF — Cryptographic Audit Trail.

Builds a Merkle tree over scan findings so that every finding can be
independently verified without exposing the full dataset.  Intended
for insurers, auditors and compliance officers.
"""

import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, DateTime, Text, UniqueConstraint
from sqlalchemy.types import JSON

from modules.database import Base

_log = logging.getLogger("cyrber.proof")


# ── Pydantic models ─────────────────────────────────────────────


class ProofLeaf(BaseModel):
    """One sealed finding."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    finding_id: str
    scan_id: str
    target: str
    finding_hash: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str
    leaf_index: int = 0
    merkle_path: List[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class MerkleTree(BaseModel):
    """Sealed scan — Merkle root over all findings."""

    root_hash: str
    leaves_count: int
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: str
    target: str

    model_config = {"from_attributes": True}


# ── SQLAlchemy models ────────────────────────────────────────────


class ProofLeafModel(Base):
    __tablename__ = "proof_leaves"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(255), nullable=False)
    scan_id = Column(String(255), nullable=False, index=True)
    target = Column(String(255), nullable=False)
    finding_hash = Column(String(64), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    signature = Column(String(64), nullable=False)
    leaf_index = Column(Integer, default=0)
    merkle_path = Column(JSON, default=list)


class MerkleTreeModel(Base):
    __tablename__ = "proof_trees"
    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_proof_trees_scan_id"),
    )

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    root_hash = Column(String(64), nullable=False, unique=True)
    leaves_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    scan_id = Column(String(255), nullable=False)
    target = Column(String(255), nullable=False)


# ── Crypto helpers ───────────────────────────────────────────────


def _get_proof_secret() -> str:
    from backend.deps import JWT_SECRET
    return JWT_SECRET


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _hash_pair(a: str, b: str) -> str:
    combined = min(a, b) + max(a, b)
    return _sha256(combined)


# ── Engine ───────────────────────────────────────────────────────


class ProofEngine:
    """Builds and verifies cryptographic audit trails for scans."""

    @staticmethod
    def hash_finding(finding: dict) -> str:
        canonical = json.dumps(finding, sort_keys=True, ensure_ascii=False, default=str)
        return _sha256(canonical)

    @staticmethod
    def sign_leaf(finding_hash: str, timestamp: datetime) -> str:
        secret = _get_proof_secret()
        message = finding_hash + timestamp.isoformat()
        return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def build_merkle_tree(leaves: List[str]) -> tuple:
        """Build a Merkle tree. Returns (root_hash, levels)."""
        if not leaves:
            return (_sha256("empty"), [[]])

        current_level = list(leaves)
        levels = [current_level[:]]

        while len(current_level) > 1:
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])

            next_level = []
            for i in range(0, len(current_level), 2):
                next_level.append(_hash_pair(current_level[i], current_level[i + 1]))
            current_level = next_level
            levels.append(current_level[:])

        return (current_level[0], levels)

    @staticmethod
    def get_merkle_path(leaf_index: int, levels: List[List[str]]) -> List[str]:
        """Return sibling hashes needed to recompute root from a leaf."""
        path = []
        idx = leaf_index

        for level in levels[:-1]:
            if len(level) % 2 == 1:
                level = level + [level[-1]]

            sibling_idx = idx ^ 1
            if sibling_idx < len(level):
                path.append(level[sibling_idx])
            idx //= 2

        return path

    @staticmethod
    def verify_leaf(leaf_hash: str, merkle_path: List[str], root_hash: str) -> bool:
        """Verify that a leaf belongs to the tree with the given root."""
        current = leaf_hash

        for sibling in merkle_path:
            current = _hash_pair(current, sibling)

        return current == root_hash

    def seal_scan(self, scan_id: str, db_session) -> MerkleTree:
        """Seal all findings from a scan into a Merkle tree."""
        from modules.database import Scan

        scan = db_session.query(Scan).filter(Scan.task_id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Check if already sealed
        existing = db_session.query(MerkleTreeModel).filter(
            MerkleTreeModel.scan_id == scan_id,
        ).first()
        if existing:
            raise ValueError(f"Scan {scan_id} already sealed")

        # Extract findings from raw_data
        findings = _extract_findings(scan)
        if not findings:
            findings = [{"module": "scan", "target": scan.target, "summary": scan.summary or "no findings"}]

        now = datetime.now(timezone.utc)
        leaf_hashes = []
        leaf_rows = []

        for i, finding in enumerate(findings):
            finding_id = finding.get("id") or finding.get("name") or f"finding-{i}"
            fhash = self.hash_finding(finding)
            sig = self.sign_leaf(fhash, now)
            leaf_hashes.append(fhash)

            leaf_rows.append({
                "finding_id": str(finding_id),
                "finding_hash": fhash,
                "signature": sig,
                "index": i,
                "finding": finding,
            })

        # Build Merkle tree
        root_hash, levels = self.build_merkle_tree(leaf_hashes)

        # Persist leaves with merkle paths
        for row_data in leaf_rows:
            mpath = self.get_merkle_path(row_data["index"], levels)
            leaf = ProofLeafModel(
                id=str(uuid.uuid4()),
                finding_id=row_data["finding_id"],
                scan_id=scan_id,
                target=scan.target,
                finding_hash=row_data["finding_hash"],
                timestamp=now,
                signature=row_data["signature"],
                leaf_index=row_data["index"],
                merkle_path=mpath,
            )
            db_session.add(leaf)

        # Persist tree
        tree = MerkleTreeModel(
            id=str(uuid.uuid4()),
            root_hash=root_hash,
            leaves_count=len(leaf_hashes),
            created_at=now,
            scan_id=scan_id,
            target=scan.target,
        )
        db_session.add(tree)
        db_session.commit()

        _log.info("[PROOF] sealed scan %s: %d leaves, root=%s",
                  scan_id, len(leaf_hashes), root_hash[:16])

        return MerkleTree(
            root_hash=root_hash,
            leaves_count=len(leaf_hashes),
            created_at=now,
            scan_id=scan_id,
            target=scan.target,
        )


# ── Helpers ──────────────────────────────────────────────────────


def _extract_findings(scan) -> list:
    """Pull findings from scan raw_data across all modules."""
    if not scan.raw_data:
        return []

    try:
        raw = json.loads(scan.raw_data) if isinstance(scan.raw_data, str) else scan.raw_data
    except (json.JSONDecodeError, TypeError):
        return []

    findings = []

    # Nuclei findings
    nuclei = raw.get("nuclei", {})
    if isinstance(nuclei, dict):
        for f in nuclei.get("findings", []):
            f["_module"] = "nuclei"
            findings.append(f)

    # ZAP alerts
    zap = raw.get("zap", {})
    if isinstance(zap, dict):
        for a in zap.get("alerts", []):
            a["_module"] = "zap"
            findings.append(a)

    # TestSSL findings
    testssl = raw.get("testssl", {})
    if isinstance(testssl, dict):
        for f in testssl.get("findings", []):
            f["_module"] = "testssl"
            findings.append(f)

    # Nikto findings
    nikto = raw.get("nikto", {})
    if isinstance(nikto, dict):
        for f in nikto.get("findings", []):
            f["_module"] = "nikto"
            findings.append(f)

    # Generic module findings
    for mod_key, mod_data in raw.items():
        if mod_key in ("nuclei", "zap", "testssl", "nikto"):
            continue
        if isinstance(mod_data, dict) and "findings" in mod_data:
            for f in mod_data["findings"]:
                if isinstance(f, dict):
                    f["_module"] = mod_key
                    findings.append(f)

    return findings
