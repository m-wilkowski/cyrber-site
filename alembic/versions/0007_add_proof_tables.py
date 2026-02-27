"""add proof_leaves and proof_trees tables

Revision ID: 0007
Revises: 0006
Create Date: 2026-02-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "proof_trees",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("root_hash", sa.String(64), nullable=False),
        sa.Column("leaves_count", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime),
        sa.Column("scan_id", sa.String(255), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.UniqueConstraint("root_hash", name="uq_proof_trees_root_hash"),
        sa.UniqueConstraint("scan_id", name="uq_proof_trees_scan_id"),
    )

    op.create_table(
        "proof_leaves",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("finding_id", sa.String(255), nullable=False),
        sa.Column("scan_id", sa.String(255), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("finding_hash", sa.String(64), nullable=False),
        sa.Column("timestamp", sa.DateTime),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.Column("leaf_index", sa.Integer, server_default="0"),
        sa.Column("merkle_path", sa.JSON),
    )
    op.create_index("ix_proof_leaves_scan_id", "proof_leaves", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_proof_leaves_scan_id")
    op.drop_table("proof_leaves")
    op.drop_table("proof_trees")
