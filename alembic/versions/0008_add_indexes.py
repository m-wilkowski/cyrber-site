"""add performance indexes to key tables

Revision ID: 0008
Revises: 0007
Create Date: 2026-02-27
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, column: str) -> bool:
    """Check if a column exists in a table."""
    result = conn.execute(text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = :t AND column_name = :c"
    ), {"t": table, "c": column})
    return result.fetchone() is not None


def _table_exists(conn, table: str) -> bool:
    """Check if a table exists."""
    result = conn.execute(text(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_name = :t"
    ), {"t": table})
    return result.fetchone() is not None


def _index_exists(conn, index_name: str) -> bool:
    """Check if an index already exists."""
    result = conn.execute(text(
        "SELECT 1 FROM pg_indexes "
        "WHERE schemaname = 'public' AND indexname = :idx"
    ), {"idx": index_name})
    return result.fetchone() is not None


def _safe_index(conn, index_name: str, table: str, columns: list[str], **kw):
    """Create an index only if table, all columns, and no duplicate index exist."""
    if _index_exists(conn, index_name):
        return
    if not _table_exists(conn, table):
        return
    for col in columns:
        if not _col_exists(conn, table, col):
            return
    op.create_index(index_name, table, columns, **kw)


def upgrade() -> None:
    conn = op.get_bind()

    # ── scans ──
    _safe_index(conn, "idx_scans_target", "scans", ["target"])
    _safe_index(conn, "idx_scans_status", "scans", ["status"])
    _safe_index(conn, "idx_scans_created_at", "scans", ["created_at"],
                postgresql_using="btree",
                postgresql_ops={"created_at": "DESC"})
    _safe_index(conn, "idx_scans_target_status", "scans", ["target", "status"])

    # ── remediation_tasks ──
    _safe_index(conn, "idx_remediation_scan_id", "remediation_tasks", ["scan_id"])
    _safe_index(conn, "idx_remediation_status", "remediation_tasks", ["status"])

    # ── schedules (user asked 'scheduled_scans' — actual table is 'schedules') ──
    _safe_index(conn, "idx_scheduled_enabled", "schedules", ["enabled"])
    _safe_index(conn, "idx_scheduled_next_run", "schedules", ["next_run"])

    # ── mens_missions ──
    _safe_index(conn, "idx_mens_target", "mens_missions", ["target"])
    # idx for status already exists as ix_mens_missions_status — skip

    # ── mens_iterations ──
    # idx for mission_id already exists as ix_mens_iterations_mission_id — skip
    _safe_index(conn, "idx_mens_iter_head", "mens_iterations", ["head"])

    # ── proof_leaves ──
    # idx for scan_id already exists as ix_proof_leaves_scan_id — skip


def downgrade() -> None:
    indexes = [
        "idx_scans_target",
        "idx_scans_status",
        "idx_scans_created_at",
        "idx_scans_target_status",
        "idx_remediation_scan_id",
        "idx_remediation_status",
        "idx_scheduled_enabled",
        "idx_scheduled_next_run",
        "idx_mens_target",
        "idx_mens_iter_head",
    ]
    conn = op.get_bind()
    for idx in indexes:
        if _index_exists(conn, idx):
            op.drop_index(idx)
