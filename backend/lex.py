"""LEX — Decision Guard engine for CYRBER MENS.

Every MENS action must pass through LEX validation before execution.
Without an active LexRule, MENS cannot start a mission.
"""

import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, Text
from sqlalchemy.types import JSON

from modules.database import Base, SessionLocal


# ── Pydantic models ──────────────────────────────────────────────


class LexRule(BaseModel):
    """Policy rule that governs what MENS is allowed to do."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: str
    mission_id: Optional[uuid.UUID] = None
    scope_cidrs: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)
    allowed_hours: Optional[tuple[int, int]] = None
    max_cvss_without_approval: float = 7.0
    max_duration_minutes: int = 480
    allowed_modules: Optional[list[str]] = None
    require_comes_mode: bool = False
    active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"

    model_config = {"from_attributes": True}


class LexDecision(BaseModel):
    """Result of a full LEX validation pass."""

    allowed: bool
    reason: str = "ok"
    requires_approval: bool = False
    checks: dict = Field(default_factory=dict)


# ── SQLAlchemy model ─────────────────────────────────────────────


class LexRuleModel(Base):
    """Persistent storage for LEX rules."""

    __tablename__ = "lex_rules"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    mission_id = Column(String, nullable=True, index=True)
    scope_cidrs = Column(JSON, nullable=False, default=list)
    excluded_hosts = Column(JSON, nullable=False, default=list)
    allowed_hours = Column(JSON, nullable=True)          # null = no restriction
    max_cvss_without_approval = Column(Float, default=7.0)
    max_duration_minutes = Column(Integer, default=480)
    allowed_modules = Column(JSON, nullable=True)        # null = all
    require_comes_mode = Column(Boolean, default=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = Column(String, default="system")


# ── Helpers ──────────────────────────────────────────────────────


def is_ip_in_cidr(ip: str, cidr: str) -> bool:
    """Check if an IP address falls within a CIDR range.

    Also handles single-host entries (e.g. '10.0.0.1' without prefix).
    """
    try:
        addr = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(cidr, strict=False)
        return addr in network
    except ValueError:
        return False


def _resolve_target_ip(target: str) -> Optional[str]:
    """Extract IP from target string. Returns None for hostnames."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return None


# ── Engine ───────────────────────────────────────────────────────


class LexEngine:
    """Core LEX policy engine — validates every MENS action."""

    def load_rule(self, rule_id: str) -> Optional[LexRule]:
        """Load a LEX rule from the database by ID."""
        session = SessionLocal()
        try:
            row = session.query(LexRuleModel).filter(
                LexRuleModel.id == str(rule_id),
                LexRuleModel.active == True,  # noqa: E712
            ).first()
            if not row:
                return None
            return LexRule(
                id=uuid.UUID(row.id),
                name=row.name,
                mission_id=uuid.UUID(row.mission_id) if row.mission_id else None,
                scope_cidrs=row.scope_cidrs or [],
                excluded_hosts=row.excluded_hosts or [],
                allowed_hours=tuple(row.allowed_hours) if row.allowed_hours else None,
                max_cvss_without_approval=row.max_cvss_without_approval,
                max_duration_minutes=row.max_duration_minutes,
                allowed_modules=row.allowed_modules,
                require_comes_mode=row.require_comes_mode,
                active=row.active,
                created_at=row.created_at or datetime.now(timezone.utc),
                created_by=row.created_by or "system",
            )
        finally:
            session.close()

    def validate_target(self, target: str, rule: LexRule) -> tuple[bool, str]:
        """Check if target is within scope_cidrs and not in excluded_hosts."""
        if target in rule.excluded_hosts:
            return False, f"target '{target}' is in excluded_hosts"

        ip = _resolve_target_ip(target)

        # Check excluded_hosts for IP match
        if ip:
            for excl in rule.excluded_hosts:
                if is_ip_in_cidr(ip, excl):
                    return False, f"target IP {ip} matches excluded entry '{excl}'"

        # If no scope_cidrs defined, allow all non-excluded targets
        if not rule.scope_cidrs:
            return True, "ok"

        # Hostname targets: check literal match in scope_cidrs
        if not ip:
            if target in rule.scope_cidrs:
                return True, "ok"
            return False, f"hostname '{target}' not found in scope_cidrs"

        # IP targets: check CIDR membership
        for cidr in rule.scope_cidrs:
            if is_ip_in_cidr(ip, cidr):
                return True, "ok"

        return False, f"target {ip} not in any scope CIDR"

    def validate_module(self, module_name: str, rule: LexRule) -> tuple[bool, str]:
        """Check if the module is allowed by the rule."""
        if rule.allowed_modules is None:
            return True, "ok"
        if module_name in rule.allowed_modules:
            return True, "ok"
        return False, f"module '{module_name}' not in allowed_modules"

    def validate_time(self, rule: LexRule) -> tuple[bool, str]:
        """Check if current time falls within allowed_hours window."""
        if rule.allowed_hours is None:
            return True, "ok"

        start_h, end_h = rule.allowed_hours
        now_h = datetime.now(timezone.utc).hour

        if start_h <= end_h:
            # Simple range: e.g. (9, 17)
            allowed = start_h <= now_h < end_h
        else:
            # Overnight range: e.g. (22, 6) = 22:00 → 06:00
            allowed = now_h >= start_h or now_h < end_h

        if allowed:
            return True, "ok"
        return False, f"current hour {now_h} UTC outside allowed window ({start_h}:00-{end_h}:00)"

    def validate_cvss(self, cvss_score: float, rule: LexRule) -> tuple[bool, str]:
        """Check CVSS score against approval threshold."""
        if cvss_score < rule.max_cvss_without_approval:
            return True, "ok"
        return False, "requires_approval"

    def validate_duration(self, start_time: datetime, rule: LexRule) -> tuple[bool, str]:
        """Check if mission has exceeded max_duration_minutes."""
        now = datetime.now(timezone.utc)
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        elapsed = (now - start_time).total_seconds() / 60
        if elapsed <= rule.max_duration_minutes:
            return True, "ok"
        return False, f"mission duration {int(elapsed)}m exceeds limit {rule.max_duration_minutes}m"

    def check_all(
        self,
        target: str,
        module_name: str,
        cvss: float,
        start_time: datetime,
        rule: LexRule,
    ) -> LexDecision:
        """Run all validations and return a combined decision."""
        checks = {}
        blocked_reason = None
        requires_approval = False

        target_ok, target_msg = self.validate_target(target, rule)
        checks["target"] = {"allowed": target_ok, "reason": target_msg}
        if not target_ok:
            blocked_reason = blocked_reason or target_msg

        module_ok, module_msg = self.validate_module(module_name, rule)
        checks["module"] = {"allowed": module_ok, "reason": module_msg}
        if not module_ok:
            blocked_reason = blocked_reason or module_msg

        time_ok, time_msg = self.validate_time(rule)
        checks["time"] = {"allowed": time_ok, "reason": time_msg}
        if not time_ok:
            blocked_reason = blocked_reason or time_msg

        cvss_ok, cvss_msg = self.validate_cvss(cvss, rule)
        checks["cvss"] = {"allowed": cvss_ok, "reason": cvss_msg}
        if not cvss_ok:
            if cvss_msg == "requires_approval":
                requires_approval = True
            else:
                blocked_reason = blocked_reason or cvss_msg

        duration_ok, duration_msg = self.validate_duration(start_time, rule)
        checks["duration"] = {"allowed": duration_ok, "reason": duration_msg}
        if not duration_ok:
            blocked_reason = blocked_reason or duration_msg

        if blocked_reason:
            return LexDecision(
                allowed=False,
                reason=blocked_reason,
                requires_approval=requires_approval,
                checks=checks,
            )

        return LexDecision(
            allowed=True,
            reason="ok",
            requires_approval=requires_approval,
            checks=checks,
        )
