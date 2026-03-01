"""0013 - Add integration_configs table

Revision ID: 0013
Revises: 0012
Create Date: 2026-03-01

External integration configuration per organization:
- ELS (Energy Logserver / Elasticsearch SIEM)
- Webhook (Slack, Teams, Discord, custom)
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def _table_exists(name):
    from sqlalchemy import inspect as sa_inspect
    conn = op.get_bind()
    inspector = sa_inspect(conn)
    return name in inspector.get_table_names()


def upgrade():
    if _table_exists("integration_configs"):
        return

    op.create_table(
        "integration_configs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("integration_type", sa.String(50), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("config", JSONB, nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade():
    op.drop_table("integration_configs")
