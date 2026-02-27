"""initial schema - 24 tables

Revision ID: 0001
Revises:
Create Date: 2026-02-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── scans ──
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("task_id", sa.String, unique=True),
        sa.Column("target", sa.String, nullable=False),
        sa.Column("status", sa.String, server_default="pending"),
        sa.Column("risk_level", sa.String),
        sa.Column("findings_count", sa.Integer, server_default="0"),
        sa.Column("summary", sa.Text),
        sa.Column("recommendations", sa.Text),
        sa.Column("top_issues", sa.Text),
        sa.Column("ports", sa.Text),
        sa.Column("raw_data", sa.Text),
        sa.Column("scan_type", sa.String, server_default="full"),
        sa.Column("profile", sa.String, server_default="STRAZNIK"),
        sa.Column("created_at", sa.DateTime),
        sa.Column("completed_at", sa.DateTime),
    )
    op.create_index("ix_scans_id", "scans", ["id"])
    op.create_index("ix_scans_task_id", "scans", ["task_id"], unique=True)

    # ── users ──
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String, unique=True, nullable=False),
        sa.Column("email", sa.String, unique=True, nullable=True),
        sa.Column("password_hash", sa.String, nullable=False),
        sa.Column("role", sa.String, server_default="viewer"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("created_at", sa.DateTime),
        sa.Column("last_login", sa.DateTime, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    # ── audit_logs ──
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("timestamp", sa.DateTime),
        sa.Column("user", sa.String, nullable=False),
        sa.Column("action", sa.String, nullable=False),
        sa.Column("target", sa.String),
        sa.Column("ip_address", sa.String),
    )
    op.create_index("ix_audit_logs_id", "audit_logs", ["id"])
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])

    # ── license_usage ──
    op.create_table(
        "license_usage",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("month", sa.String, unique=True, nullable=False),
        sa.Column("scans_count", sa.Integer, server_default="0"),
        sa.Column("updated_at", sa.DateTime),
    )
    op.create_index("ix_license_usage_month", "license_usage", ["month"], unique=True)

    # ── remediation_tasks ──
    op.create_table(
        "remediation_tasks",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("scan_id", sa.String, nullable=False),
        sa.Column("finding_name", sa.String, nullable=False),
        sa.Column("finding_severity", sa.String, nullable=False),
        sa.Column("finding_module", sa.String, nullable=True),
        sa.Column("owner", sa.String, nullable=True),
        sa.Column("deadline", sa.DateTime, nullable=True),
        sa.Column("status", sa.String, server_default="open"),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("verified_at", sa.DateTime, nullable=True),
        sa.Column("retest_task_id", sa.String, nullable=True),
        sa.Column("retest_status", sa.String, nullable=True),
        sa.Column("retest_at", sa.DateTime, nullable=True),
        sa.Column("retest_result", sa.JSON, nullable=True),
    )
    op.create_index("ix_remediation_tasks_id", "remediation_tasks", ["id"])
    op.create_index("ix_remediation_tasks_scan_id", "remediation_tasks", ["scan_id"])

    # ── schedules ──
    op.create_table(
        "schedules",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("target", sa.String, nullable=False),
        sa.Column("interval_hours", sa.Integer, nullable=False),
        sa.Column("enabled", sa.Boolean, server_default="true"),
        sa.Column("last_run", sa.DateTime),
        sa.Column("next_run", sa.DateTime),
        sa.Column("created_at", sa.DateTime),
    )
    op.create_index("ix_schedules_id", "schedules", ["id"])

    # ── cve_cache ──
    op.create_table(
        "cve_cache",
        sa.Column("cve_id", sa.String, primary_key=True),
        sa.Column("cvss_score", sa.Float),
        sa.Column("cvss_vector", sa.String),
        sa.Column("description", sa.Text),
        sa.Column("published", sa.String),
        sa.Column("last_modified", sa.String),
        sa.Column("cwe_id", sa.String),
        sa.Column("references", sa.JSON),
        sa.Column("updated_at", sa.DateTime),
    )

    # ── kev_cache ──
    op.create_table(
        "kev_cache",
        sa.Column("cve_id", sa.String, primary_key=True),
        sa.Column("vendor_project", sa.String),
        sa.Column("product", sa.String),
        sa.Column("vulnerability_name", sa.String),
        sa.Column("date_added", sa.String),
        sa.Column("short_description", sa.Text),
        sa.Column("required_action", sa.Text),
        sa.Column("due_date", sa.String),
        sa.Column("updated_at", sa.DateTime),
    )

    # ── epss_cache ──
    op.create_table(
        "epss_cache",
        sa.Column("cve_id", sa.String, primary_key=True),
        sa.Column("epss_score", sa.Float),
        sa.Column("percentile", sa.Float),
        sa.Column("updated_at", sa.DateTime),
    )

    # ── intel_sync_log ──
    op.create_table(
        "intel_sync_log",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("source", sa.String),
        sa.Column("status", sa.String),
        sa.Column("records_updated", sa.Integer),
        sa.Column("duration_seconds", sa.Float),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("synced_at", sa.DateTime),
    )

    # ── attack_techniques ──
    op.create_table(
        "attack_techniques",
        sa.Column("technique_id", sa.String, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("url", sa.String),
        sa.Column("platforms", sa.JSON),
        sa.Column("tactics", sa.JSON),
        sa.Column("data_sources", sa.JSON),
        sa.Column("detection", sa.Text),
        sa.Column("is_subtechnique", sa.Boolean, server_default="false"),
        sa.Column("parent_id", sa.String, nullable=True),
        sa.Column("deprecated", sa.Boolean, server_default="false"),
        sa.Column("updated_at", sa.DateTime),
    )

    # ── attack_tactics ──
    op.create_table(
        "attack_tactics",
        sa.Column("tactic_id", sa.String, primary_key=True),
        sa.Column("short_name", sa.String),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("url", sa.String),
        sa.Column("updated_at", sa.DateTime),
    )

    # ── attack_mitigations ──
    op.create_table(
        "attack_mitigations",
        sa.Column("mitigation_id", sa.String, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("url", sa.String),
        sa.Column("updated_at", sa.DateTime),
    )

    # ── attack_mitigation_links ──
    op.create_table(
        "attack_mitigation_links",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("technique_id", sa.String),
        sa.Column("mitigation_id", sa.String),
        sa.Column("description", sa.Text),
    )
    op.create_index("ix_attack_mitigation_links_technique_id", "attack_mitigation_links", ["technique_id"])
    op.create_index("ix_attack_mitigation_links_mitigation_id", "attack_mitigation_links", ["mitigation_id"])

    # ── cwe_attack_map ──
    op.create_table(
        "cwe_attack_map",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("cwe_id", sa.String),
        sa.Column("capec_id", sa.String),
        sa.Column("technique_id", sa.String),
        sa.Column("updated_at", sa.DateTime),
    )
    op.create_index("ix_cwe_attack_map_cwe_id", "cwe_attack_map", ["cwe_id"])
    op.create_index("ix_cwe_attack_map_technique_id", "cwe_attack_map", ["technique_id"])

    # ── euvd_cache ──
    op.create_table(
        "euvd_cache",
        sa.Column("euvd_id", sa.String, primary_key=True),
        sa.Column("description", sa.Text),
        sa.Column("date_published", sa.String),
        sa.Column("date_updated", sa.String),
        sa.Column("base_score", sa.Float),
        sa.Column("base_score_version", sa.String),
        sa.Column("base_score_vector", sa.String),
        sa.Column("aliases", sa.JSON),
        sa.Column("epss", sa.Float),
        sa.Column("vendor", sa.String),
        sa.Column("product", sa.String),
        sa.Column("references", sa.JSON),
        sa.Column("updated_at", sa.DateTime),
    )

    # ── misp_events ──
    op.create_table(
        "misp_events",
        sa.Column("event_id", sa.Integer, primary_key=True),
        sa.Column("uuid", sa.String, unique=True),
        sa.Column("info", sa.Text),
        sa.Column("threat_level_id", sa.Integer),
        sa.Column("analysis", sa.Integer),
        sa.Column("date", sa.String),
        sa.Column("org", sa.String),
        sa.Column("tags", sa.JSON),
        sa.Column("attribute_count", sa.Integer, server_default="0"),
        sa.Column("updated_at", sa.DateTime),
    )
    op.create_index("ix_misp_events_uuid", "misp_events", ["uuid"], unique=True)

    # ── misp_attributes ──
    op.create_table(
        "misp_attributes",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("attribute_id", sa.Integer, unique=True),
        sa.Column("event_id", sa.Integer),
        sa.Column("type", sa.String),
        sa.Column("value", sa.String),
        sa.Column("category", sa.String),
        sa.Column("to_ids", sa.Boolean, server_default="false"),
        sa.Column("tags", sa.JSON),
        sa.Column("updated_at", sa.DateTime),
    )
    op.create_index("ix_misp_attributes_attribute_id", "misp_attributes", ["attribute_id"], unique=True)
    op.create_index("ix_misp_attributes_event_id", "misp_attributes", ["event_id"])
    op.create_index("ix_misp_attributes_value", "misp_attributes", ["value"])

    # ── shodan_cache ──
    op.create_table(
        "shodan_cache",
        sa.Column("ip", sa.String, primary_key=True),
        sa.Column("ports", sa.JSON),
        sa.Column("cpes", sa.JSON),
        sa.Column("hostnames", sa.JSON),
        sa.Column("tags", sa.JSON),
        sa.Column("vulns", sa.JSON),
        sa.Column("fetched_at", sa.DateTime),
    )

    # ── urlhaus_cache ──
    op.create_table(
        "urlhaus_cache",
        sa.Column("host", sa.String, primary_key=True),
        sa.Column("urls_count", sa.Integer, server_default="0"),
        sa.Column("blacklisted", sa.Boolean, server_default="false"),
        sa.Column("tags", sa.JSON),
        sa.Column("urls", sa.JSON),
        sa.Column("fetched_at", sa.DateTime),
    )

    # ── greynoise_cache ──
    op.create_table(
        "greynoise_cache",
        sa.Column("ip", sa.String, primary_key=True),
        sa.Column("noise", sa.Boolean, server_default="false"),
        sa.Column("riot", sa.Boolean, server_default="false"),
        sa.Column("classification", sa.String),
        sa.Column("name", sa.String),
        sa.Column("link", sa.String),
        sa.Column("fetched_at", sa.DateTime),
    )

    # ── exploitdb_cache ──
    op.create_table(
        "exploitdb_cache",
        sa.Column("exploit_id", sa.Integer, primary_key=True),
        sa.Column("description", sa.Text),
        sa.Column("cve", sa.String),
        sa.Column("type", sa.String),
        sa.Column("platform", sa.String),
        sa.Column("port", sa.Integer),
        sa.Column("date", sa.String),
        sa.Column("author", sa.String),
        sa.Column("url", sa.String),
        sa.Column("updated_at", sa.DateTime),
    )
    op.create_index("ix_exploitdb_cache_cve", "exploitdb_cache", ["cve"])

    # ── malwarebazaar_cache ──
    op.create_table(
        "malwarebazaar_cache",
        sa.Column("sha256_hash", sa.String, primary_key=True),
        sa.Column("md5_hash", sa.String),
        sa.Column("sha1_hash", sa.String),
        sa.Column("file_name", sa.String),
        sa.Column("file_type", sa.String),
        sa.Column("tags", sa.JSON),
        sa.Column("signature", sa.String),
        sa.Column("first_seen", sa.String),
        sa.Column("reporter", sa.String),
        sa.Column("fetched_at", sa.DateTime),
    )
    op.create_index("ix_malwarebazaar_cache_md5_hash", "malwarebazaar_cache", ["md5_hash"])
    op.create_index("ix_malwarebazaar_cache_sha1_hash", "malwarebazaar_cache", ["sha1_hash"])

    # ── verify_results ──
    op.create_table(
        "verify_results",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("query", sa.String),
        sa.Column("query_type", sa.String),
        sa.Column("risk_score", sa.Integer, server_default="0"),
        sa.Column("verdict", sa.String),
        sa.Column("signals", sa.JSON),
        sa.Column("red_flags", sa.JSON),
        sa.Column("summary", sa.Text),
        sa.Column("recommendation", sa.Text),
        sa.Column("narrative", sa.Text),
        sa.Column("trust_factors", sa.JSON),
        sa.Column("signal_explanations", sa.JSON),
        sa.Column("educational_tips", sa.JSON),
        sa.Column("problems", sa.JSON),
        sa.Column("positives", sa.JSON),
        sa.Column("action", sa.Text),
        sa.Column("immediate_actions", sa.JSON),
        sa.Column("if_paid_already", sa.JSON),
        sa.Column("report_to", sa.JSON),
        sa.Column("created_at", sa.DateTime),
        sa.Column("created_by", sa.String),
    )
    op.create_index("ix_verify_results_query", "verify_results", ["query"])


def downgrade() -> None:
    op.drop_table("verify_results")
    op.drop_table("malwarebazaar_cache")
    op.drop_table("exploitdb_cache")
    op.drop_table("greynoise_cache")
    op.drop_table("urlhaus_cache")
    op.drop_table("shodan_cache")
    op.drop_table("misp_attributes")
    op.drop_table("misp_events")
    op.drop_table("euvd_cache")
    op.drop_table("cwe_attack_map")
    op.drop_table("attack_mitigation_links")
    op.drop_table("attack_mitigations")
    op.drop_table("attack_tactics")
    op.drop_table("attack_techniques")
    op.drop_table("intel_sync_log")
    op.drop_table("epss_cache")
    op.drop_table("kev_cache")
    op.drop_table("cve_cache")
    op.drop_table("schedules")
    op.drop_table("remediation_tasks")
    op.drop_table("license_usage")
    op.drop_table("audit_logs")
    op.drop_table("users")
    op.drop_table("scans")
