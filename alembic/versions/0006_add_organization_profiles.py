"""add organization_profiles table

Revision ID: 0006
Revises: 0005
Create Date: 2026-02-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "organization_profiles",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("last_updated", sa.DateTime),
        sa.Column("missions_count", sa.Integer, server_default="0"),
        sa.Column("patch_cycle_days", sa.Float, nullable=True),
        sa.Column("phishing_click_rate", sa.Float, nullable=True),
        sa.Column("credential_reuse_incidents", sa.Integer, server_default="0"),
        sa.Column("unreviewed_services", sa.Integer, server_default="0"),
        sa.Column("predispositions", sa.JSON),
        sa.Column("patterns", sa.JSON),
        sa.Column("genome_report", sa.Text, nullable=True),
        sa.Column("genome_generated_at", sa.DateTime, nullable=True),
        sa.UniqueConstraint("target", name="uq_organization_profiles_target"),
    )


def downgrade() -> None:
    op.drop_table("organization_profiles")
