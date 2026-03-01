"""Tests for modules/lex.py — LEX Decision Guard v2.

Covers: target scope, excluded hosts, modules, time windows,
CVSS threshold (COMES vs LIBER), duration, validate_all.
"""

import pytest
from datetime import datetime, timezone, timedelta

from modules.lex import LexPolicy, LexEngine, LexDecision


@pytest.fixture
def engine():
    return LexEngine()


@pytest.fixture
def base_policy():
    return LexPolicy(
        mission_id="test-mission",
        organization_id=1,
        scope_cidrs=["10.0.0.0/24", "192.168.1.0/24", "example.com"],
        excluded_hosts=["10.0.0.99", "evil.com"],
        allowed_modules=[],
        excluded_modules=["sqlmap"],
        time_windows=[],
        require_approval_cvss=9.0,
        max_duration_seconds=28800,
        max_targets=50,
        mode="COMES",
    )


# ── Target validation ────────────────────────────────────────────


class TestValidateTarget:

    def test_target_in_scope_cidr(self, engine, base_policy):
        ok, reason = engine.validate_target("10.0.0.5", base_policy)
        assert ok is True

    def test_target_out_of_scope(self, engine, base_policy):
        ok, reason = engine.validate_target("172.16.0.1", base_policy)
        assert ok is False
        assert "not in any scope CIDR" in reason

    def test_target_in_excluded_hosts(self, engine, base_policy):
        ok, reason = engine.validate_target("10.0.0.99", base_policy)
        assert ok is False
        assert "excluded_hosts" in reason

    def test_target_hostname_in_excluded(self, engine, base_policy):
        ok, reason = engine.validate_target("evil.com", base_policy)
        assert ok is False
        assert "excluded_hosts" in reason

    def test_target_hostname_in_scope(self, engine, base_policy):
        ok, reason = engine.validate_target("example.com", base_policy)
        assert ok is True

    def test_target_hostname_not_in_scope(self, engine, base_policy):
        ok, reason = engine.validate_target("unknown.org", base_policy)
        assert ok is False
        assert "not found in scope_cidrs" in reason

    def test_target_url_format(self, engine, base_policy):
        ok, reason = engine.validate_target("http://10.0.0.5/path", base_policy)
        assert ok is True

    def test_target_host_port_format(self, engine, base_policy):
        ok, reason = engine.validate_target("10.0.0.5:8080", base_policy)
        assert ok is True

    def test_empty_scope_allows_all(self, engine):
        policy = LexPolicy(scope_cidrs=[], excluded_hosts=[])
        ok, reason = engine.validate_target("anything.anywhere.com", policy)
        assert ok is True

    def test_excluded_cidr_range(self, engine):
        policy = LexPolicy(
            scope_cidrs=["10.0.0.0/16"],
            excluded_hosts=["10.0.1.0/24"],
        )
        ok, reason = engine.validate_target("10.0.1.50", policy)
        assert ok is False
        assert "excluded" in reason


# ── Module validation ────────────────────────────────────────────


class TestValidateModule:

    def test_module_not_excluded(self, engine, base_policy):
        ok, reason = engine.validate_module("nmap", base_policy)
        assert ok is True

    def test_module_excluded(self, engine, base_policy):
        ok, reason = engine.validate_module("sqlmap", base_policy)
        assert ok is False
        assert "excluded_modules" in reason

    def test_allowed_modules_whitelist(self, engine):
        policy = LexPolicy(
            allowed_modules=["nmap", "nuclei"],
            excluded_modules=[],
        )
        ok, reason = engine.validate_module("nmap", policy)
        assert ok is True

        ok, reason = engine.validate_module("gobuster", policy)
        assert ok is False
        assert "not in allowed_modules" in reason

    def test_empty_allowed_and_excluded(self, engine):
        policy = LexPolicy(allowed_modules=[], excluded_modules=[])
        ok, reason = engine.validate_module("anything", policy)
        assert ok is True


# ── Time window validation ───────────────────────────────────────


class TestValidateTimeWindow:

    def test_no_time_windows_allows_all(self, engine):
        policy = LexPolicy(time_windows=[])
        ok, reason = engine.validate_time_window(policy)
        assert ok is True

    def test_within_simple_time_window(self, engine):
        policy = LexPolicy(time_windows=[
            {"start": "09:00", "end": "17:00", "days": []}
        ])
        now = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)  # Saturday 12:00
        ok, reason = engine.validate_time_window(policy, now=now)
        assert ok is True

    def test_outside_simple_time_window(self, engine):
        policy = LexPolicy(time_windows=[
            {"start": "09:00", "end": "17:00", "days": []}
        ])
        now = datetime(2026, 3, 1, 20, 0, tzinfo=timezone.utc)  # 20:00
        ok, reason = engine.validate_time_window(policy, now=now)
        assert ok is False
        assert "outside" in reason

    def test_overnight_time_window(self, engine):
        policy = LexPolicy(time_windows=[
            {"start": "22:00", "end": "06:00", "days": []}
        ])
        # 23:00 should be within overnight window
        now = datetime(2026, 3, 1, 23, 0, tzinfo=timezone.utc)
        ok, reason = engine.validate_time_window(policy, now=now)
        assert ok is True

        # 03:00 should also be within overnight window
        now = datetime(2026, 3, 2, 3, 0, tzinfo=timezone.utc)
        ok, reason = engine.validate_time_window(policy, now=now)
        assert ok is True

        # 12:00 should be outside
        now = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)
        ok, reason = engine.validate_time_window(policy, now=now)
        assert ok is False

    def test_day_constraint(self, engine):
        policy = LexPolicy(time_windows=[
            {"start": "00:00", "end": "23:59", "days": ["mon", "tue"]}
        ])
        # 2026-03-02 is Monday
        now = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)
        ok, reason = engine.validate_time_window(policy, now=now)
        assert ok is True

        # 2026-03-04 is Wednesday
        now = datetime(2026, 3, 4, 12, 0, tzinfo=timezone.utc)
        ok, reason = engine.validate_time_window(policy, now=now)
        assert ok is False


# ── CVSS validation ──────────────────────────────────────────────


class TestValidateCvss:

    def test_cvss_below_threshold(self, engine, base_policy):
        ok, reason = engine.validate_cvss_action(7.5, base_policy)
        assert ok is True

    def test_cvss_above_threshold_comes(self, engine, base_policy):
        ok, reason = engine.validate_cvss_action(9.5, base_policy)
        assert ok is False
        assert "requires operator approval" in reason

    def test_cvss_above_threshold_liber(self, engine):
        policy = LexPolicy(mode="LIBER", require_approval_cvss=9.0)
        ok, reason = engine.validate_cvss_action(10.0, policy)
        assert ok is True  # LIBER ignores CVSS threshold

    def test_cvss_at_threshold(self, engine, base_policy):
        ok, reason = engine.validate_cvss_action(9.0, base_policy)
        assert ok is True  # <= threshold is OK


# ── Duration validation ──────────────────────────────────────────


class TestCheckDuration:

    def test_duration_within_limit(self, engine, base_policy):
        started = datetime.now(timezone.utc) - timedelta(hours=1)
        ok, reason, warnings = engine.check_duration(started, base_policy)
        assert ok is True

    def test_duration_exceeded(self, engine, base_policy):
        started = datetime.now(timezone.utc) - timedelta(hours=10)
        ok, reason, warnings = engine.check_duration(started, base_policy)
        assert ok is False
        assert "exceeds limit" in reason

    def test_duration_warning_near_end(self, engine):
        policy = LexPolicy(max_duration_seconds=3600)
        started = datetime.now(timezone.utc) - timedelta(minutes=55)
        ok, reason, warnings = engine.check_duration(started, policy)
        assert ok is True
        assert len(warnings) > 0
        assert "ends in" in warnings[0]

    def test_duration_naive_datetime(self, engine, base_policy):
        """Ensure naive datetime is handled (treated as UTC)."""
        started = datetime.utcnow() - timedelta(hours=1)
        ok, reason, warnings = engine.check_duration(started, base_policy)
        assert ok is True


# ── validate_all ─────────────────────────────────────────────────


class TestValidateAll:

    def test_all_pass(self, engine, base_policy):
        started = datetime.now(timezone.utc) - timedelta(hours=1)
        decision = engine.validate_all(
            target="10.0.0.5",
            module="nmap",
            cvss=5.0,
            started_at=started,
            policy=base_policy,
        )
        assert decision.allowed is True
        assert decision.reason == ""
        assert decision.requires_approval is False

    def test_target_blocked(self, engine, base_policy):
        started = datetime.now(timezone.utc)
        decision = engine.validate_all(
            target="172.16.0.1",
            module="nmap",
            cvss=5.0,
            started_at=started,
            policy=base_policy,
        )
        assert decision.allowed is False
        assert "not in any scope CIDR" in decision.reason

    def test_module_blocked(self, engine, base_policy):
        started = datetime.now(timezone.utc)
        decision = engine.validate_all(
            target="10.0.0.5",
            module="sqlmap",
            cvss=5.0,
            started_at=started,
            policy=base_policy,
        )
        assert decision.allowed is False
        assert "excluded_modules" in decision.reason

    def test_cvss_requires_approval_comes(self, engine, base_policy):
        started = datetime.now(timezone.utc)
        decision = engine.validate_all(
            target="10.0.0.5",
            module="nmap",
            cvss=9.8,
            started_at=started,
            policy=base_policy,
        )
        assert decision.allowed is True
        assert decision.requires_approval is True

    def test_cvss_blocked_iterum(self, engine):
        policy = LexPolicy(
            scope_cidrs=[],
            excluded_hosts=[],
            excluded_modules=[],
            mode="ITERUM",
            require_approval_cvss=9.0,
        )
        started = datetime.now(timezone.utc)
        decision = engine.validate_all(
            target="10.0.0.5",
            module="nmap",
            cvss=9.8,
            started_at=started,
            policy=policy,
        )
        assert decision.allowed is False

    def test_duration_exceeded_blocks(self, engine, base_policy):
        started = datetime.now(timezone.utc) - timedelta(hours=10)
        decision = engine.validate_all(
            target="10.0.0.5",
            module="nmap",
            cvss=5.0,
            started_at=started,
            policy=base_policy,
        )
        assert decision.allowed is False
        assert "exceeds limit" in decision.reason

    def test_time_window_blocked(self, engine):
        policy = LexPolicy(
            scope_cidrs=[],
            excluded_hosts=[],
            excluded_modules=[],
            time_windows=[{"start": "09:00", "end": "10:00", "days": []}],
        )
        started = datetime.now(timezone.utc)
        now = datetime(2026, 3, 1, 20, 0, tzinfo=timezone.utc)
        decision = engine.validate_all(
            target="example.com",
            module="nmap",
            cvss=0.0,
            started_at=started,
            policy=policy,
            now=now,
        )
        assert decision.allowed is False
        assert "outside" in decision.reason
