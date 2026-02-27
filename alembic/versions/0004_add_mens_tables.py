"""add mens_missions and mens_iterations tables

Revision ID: 0004
Revises: 0003
Create Date: 2026-02-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mens_missions",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("target", sa.String, nullable=False),
        sa.Column("objective", sa.Text, nullable=False),
        sa.Column("lex_rule_id", sa.String, nullable=False),
        sa.Column("mode", sa.String, server_default="comes"),
        sa.Column("status", sa.String, server_default="pending"),
        sa.Column("started_at", sa.DateTime),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("created_by", sa.String, server_default="system"),
        sa.Column("fiducia", sa.Float, server_default="0.0"),
    )
    op.create_index("ix_mens_missions_lex_rule_id", "mens_missions", ["lex_rule_id"])
    op.create_index("ix_mens_missions_status", "mens_missions", ["status"])

    op.create_table(
        "mens_iterations",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("mission_id", sa.String, nullable=False),
        sa.Column("iteration_number", sa.Integer, server_default="0"),
        sa.Column("phase", sa.String, server_default="observe"),
        sa.Column("module_selected", sa.String, nullable=True),
        sa.Column("module_args", sa.JSON, nullable=True),
        sa.Column("cogitatio", sa.Text, nullable=True),
        sa.Column("result_summary", sa.Text, nullable=True),
        sa.Column("findings_count", sa.Integer, server_default="0"),
        sa.Column("approved", sa.Boolean, nullable=True),
        sa.Column("created_at", sa.DateTime),
    )
    op.create_index("ix_mens_iterations_mission_id", "mens_iterations", ["mission_id"])

    # FK: mens_missions.lex_rule_id → lex_rules.id
    op.create_foreign_key(
        "fk_mens_missions_lex_rule_id",
        "mens_missions", "lex_rules",
        ["lex_rule_id"], ["id"],
    )
    # FK: mens_iterations.mission_id → mens_missions.id
    op.create_foreign_key(
        "fk_mens_iterations_mission_id",
        "mens_iterations", "mens_missions",
        ["mission_id"], ["id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_mens_iterations_mission_id", "mens_iterations", type_="foreignkey")
    op.drop_constraint("fk_mens_missions_lex_rule_id", "mens_missions", type_="foreignkey")
    op.drop_index("ix_mens_iterations_mission_id")
    op.drop_table("mens_iterations")
    op.drop_index("ix_mens_missions_status")
    op.drop_index("ix_mens_missions_lex_rule_id")
    op.drop_table("mens_missions")
