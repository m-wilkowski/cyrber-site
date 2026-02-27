"""add head column to mens_iterations

Revision ID: 0005
Revises: 0004
Create Date: 2026-02-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "mens_iterations",
        sa.Column("head", sa.String(10), server_default="RATIO"),
    )


def downgrade() -> None:
    op.drop_column("mens_iterations", "head")
