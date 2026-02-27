"""add foreign keys

Revision ID: 0002
Revises: 0001
Create Date: 2026-02-27

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Clean orphan rows that would violate FK constraints
    op.execute("DELETE FROM remediation_tasks WHERE scan_id NOT IN (SELECT task_id FROM scans)")
    op.execute("DELETE FROM attack_mitigation_links WHERE technique_id NOT IN (SELECT technique_id FROM attack_techniques)")
    op.execute("DELETE FROM attack_mitigation_links WHERE mitigation_id NOT IN (SELECT mitigation_id FROM attack_mitigations)")
    op.execute("DELETE FROM cwe_attack_map WHERE technique_id NOT IN (SELECT technique_id FROM attack_techniques)")
    op.execute("DELETE FROM misp_attributes WHERE event_id NOT IN (SELECT event_id FROM misp_events)")
    op.execute("UPDATE attack_techniques SET parent_id = NULL WHERE parent_id IS NOT NULL AND parent_id NOT IN (SELECT technique_id FROM attack_techniques)")

    # Add FK constraints
    op.create_foreign_key("fk_rem_scan", "remediation_tasks", "scans", ["scan_id"], ["task_id"], ondelete="CASCADE")
    op.create_foreign_key("fk_link_technique", "attack_mitigation_links", "attack_techniques", ["technique_id"], ["technique_id"], ondelete="CASCADE")
    op.create_foreign_key("fk_link_mitigation", "attack_mitigation_links", "attack_mitigations", ["mitigation_id"], ["mitigation_id"], ondelete="CASCADE")
    op.create_foreign_key("fk_cwe_technique", "cwe_attack_map", "attack_techniques", ["technique_id"], ["technique_id"], ondelete="CASCADE")
    op.create_foreign_key("fk_misp_event", "misp_attributes", "misp_events", ["event_id"], ["event_id"], ondelete="CASCADE")
    op.create_foreign_key("fk_technique_parent", "attack_techniques", "attack_techniques", ["parent_id"], ["technique_id"], ondelete="SET NULL")


def downgrade() -> None:
    op.drop_constraint("fk_technique_parent", "attack_techniques", type_="foreignkey")
    op.drop_constraint("fk_misp_event", "misp_attributes", type_="foreignkey")
    op.drop_constraint("fk_cwe_technique", "cwe_attack_map", type_="foreignkey")
    op.drop_constraint("fk_link_mitigation", "attack_mitigation_links", type_="foreignkey")
    op.drop_constraint("fk_link_technique", "attack_mitigation_links", type_="foreignkey")
    op.drop_constraint("fk_rem_scan", "remediation_tasks", type_="foreignkey")
