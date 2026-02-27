"""add lex_rules table

Revision ID: 0003
Revises: 0002
Create Date: 2026-02-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "lex_rules",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("mission_id", sa.String, nullable=True),
        sa.Column("scope_cidrs", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("excluded_hosts", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("allowed_hours", sa.JSON, nullable=True),
        sa.Column("max_cvss_without_approval", sa.Float, server_default="7.0"),
        sa.Column("max_duration_minutes", sa.Integer, server_default="480"),
        sa.Column("allowed_modules", sa.JSON, nullable=True),
        sa.Column("require_comes_mode", sa.Boolean, server_default="false"),
        sa.Column("active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime),
        sa.Column("created_by", sa.String, server_default="system"),
    )
    op.create_index("ix_lex_rules_mission_id", "lex_rules", ["mission_id"])


def downgrade() -> None:
    op.drop_index("ix_lex_rules_mission_id")
    op.drop_table("lex_rules")
