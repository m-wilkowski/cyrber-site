"""LEX Decision Guard — policy engine for CYRBER MENS (v2).

Extended policy model with multi-tenant support, time windows with day-of-week,
excluded modules, per-org scoping, and COMES/LIBER/ITERUM mode awareness.

Without an active LexPolicy, MENS cannot start a mission.
"""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from sqlalchemy import (
    Column, String, Float, Integer, Boolean, DateTime, Text,
    ForeignKey,
)
from sqlalchemy.types import JSON

from modules.database import Base


# ── Data classes ─────────────────────────────────────────────────


@dataclass
class LexPolicy:
    """Policy that governs what MENS is allowed to do within a mission."""

    mission_id: str = ""
    organization_id: int = 0
    scope_cidrs: List[str] = field(default_factory=list)
    excluded_hosts: List[str] = field(default_factory=list)
    allowed_modules: List[str] = field(default_factory=list)
    excluded_modules: List[str] = field(default_factory=list)
    time_windows: List[dict] = field(default_factory=list)
    require_approval_cvss: float = 9.0
    max_duration_seconds: int = 28800  # 8h
    max_targets: int = 50
    mode: str = "COMES"


@dataclass
class LexDecision:
    """Result of a full LEX validation pass."""

    allowed: bool = True
    reason: str = ""
    requires_approval: bool = False
    warnings: List[str] = field(default_factory=list)


# ── SQLAlchemy model ─────────────────────────────────────────────


class LexPolicyModel(Base):
    """Persistent storage for LEX policies (v2)."""

    __tablename__ = "lex_policies"

    id = Column(Integer, primary_key=True)
    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    mission_id = Column(String, nullable=True, index=True)
    name = Column(String(255), nullable=False)
    scope_cidrs = Column(JSON, nullable=False, server_default="[]")
    excluded_hosts = Column(JSON, nullable=False, server_default="[]")
    allowed_modules = Column(JSON, nullable=False, server_default="[]")
    excluded_modules = Column(JSON, nullable=False, server_default="[]")
    time_windows = Column(JSON, nullable=False, server_default="[]")
    require_approval_cvss = Column(Float, nullable=False, server_default="9.0")
    max_duration_seconds = Column(Integer, nullable=False, server_default="28800")
    max_targets = Column(Integer, nullable=False, server_default="50")
    mode = Column(String(20), nullable=False, server_default="COMES")
    is_active = Column(Boolean, nullable=False, server_default="true")
    created_at = Column(DateTime, server_default="now()")
    created_by = Column(String(100), server_default="system")


# ── Helpers ──────────────────────────────────────────────────────


def _is_ip_in_cidr(ip_str: str, cidr: str) -> bool:
    """Check if an IP address falls within a CIDR range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr, strict=False)
        return addr in network
    except ValueError:
        return False


def _extract_host(target: str) -> str:
    """Extract hostname/IP from a target (URL, host:port, or bare IP)."""
    t = target.strip()
    if "://" in t:
        parsed = urlparse(t)
        return parsed.hostname or t
    if ":" in t and not t.startswith("["):
        host, _, port = t.rpartition(":")
        if port.isdigit():
            return host
    return t


def _resolve_ip(target: str) -> Optional[str]:
    """Return IP string if target contains a valid IP, else None."""
    host = _extract_host(target)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return None


# ── Engine ───────────────────────────────────────────────────────


class LexEngine:
    """Core LEX policy engine (v2) — validates every MENS action."""

    def validate_target(self, target: str, policy: LexPolicy) -> tuple:
        """Check if target is within scope_cidrs and not in excluded_hosts."""
        host = _extract_host(target)

        # Check excluded_hosts — hostname and literal match
        for excl in policy.excluded_hosts:
            if host == excl or target.strip() == excl:
                return (False, f"target '{host}' is in excluded_hosts")

        ip = _resolve_ip(target)

        # Check excluded_hosts for CIDR match
        if ip:
            for excl in policy.excluded_hosts:
                if _is_ip_in_cidr(ip, excl):
                    return (False, f"target IP {ip} matches excluded entry '{excl}'")

        # If no scope_cidrs defined, allow all non-excluded targets
        if not policy.scope_cidrs:
            return (True, "")

        # IP targets: check CIDR membership
        if ip:
            for cidr in policy.scope_cidrs:
                if _is_ip_in_cidr(ip, cidr):
                    return (True, "")
            return (False, f"target {ip} not in any scope CIDR")

        # Hostname targets: check literal match in scope_cidrs
        if host in policy.scope_cidrs:
            return (True, "")
        return (False, f"hostname '{host}' not found in scope_cidrs")

    def validate_module(self, module_name: str, policy: LexPolicy) -> tuple:
        """Check if the module is allowed by the policy."""
        if module_name in policy.excluded_modules:
            return (False, f"module '{module_name}' is in excluded_modules")
        if policy.allowed_modules and module_name not in policy.allowed_modules:
            return (False, f"module '{module_name}' not in allowed_modules")
        return (True, "")

    def validate_time_window(self, policy: LexPolicy, now: Optional[datetime] = None) -> tuple:
        """Check if current time and day falls within any time_window."""
        if not policy.time_windows:
            return (True, "")

        if now is None:
            now = datetime.now(timezone.utc)

        current_time = now.strftime("%H:%M")
        day_names = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
        current_day = day_names[now.weekday()]

        for window in policy.time_windows:
            start = window.get("start", "00:00")
            end = window.get("end", "23:59")
            days = window.get("days", [])

            # Check day constraint
            if days and current_day not in days:
                continue

            # Check time constraint
            if start <= end:
                # Simple range: e.g. 09:00 - 17:00
                if start <= current_time <= end:
                    return (True, "")
            else:
                # Overnight range: e.g. 22:00 - 06:00
                if current_time >= start or current_time <= end:
                    return (True, "")

        return (False, f"current time {current_time} ({current_day}) outside all time windows")

    def validate_cvss_action(self, cvss_score: float, policy: LexPolicy) -> tuple:
        """Check CVSS score against approval threshold.

        LIBER mode ignores this rule (autonomous).
        """
        if policy.mode == "LIBER":
            return (True, "")
        if cvss_score <= policy.require_approval_cvss:
            return (True, "")
        return (False, f"CVSS {cvss_score} exceeds threshold {policy.require_approval_cvss} — requires operator approval")

    def check_duration(self, started_at: datetime, policy: LexPolicy, now: Optional[datetime] = None) -> tuple:
        """Check if mission has exceeded max_duration_seconds."""
        if now is None:
            now = datetime.now(timezone.utc)
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        elapsed = (now - started_at).total_seconds()
        if elapsed <= policy.max_duration_seconds:
            remaining = policy.max_duration_seconds - elapsed
            warnings = []
            if remaining < 600:
                warnings.append(f"mission ends in {int(remaining)}s")
            return (True, "", warnings)
        return (False, f"mission duration {int(elapsed)}s exceeds limit {policy.max_duration_seconds}s", [])

    def validate_all(
        self,
        target: str,
        module: str,
        cvss: float,
        started_at: datetime,
        policy: LexPolicy,
        now: Optional[datetime] = None,
    ) -> LexDecision:
        """Run all validations and return a combined decision."""
        decision = LexDecision()
        all_warnings = []

        # Target
        ok, reason = self.validate_target(target, policy)
        if not ok:
            return LexDecision(allowed=False, reason=reason)

        # Module
        ok, reason = self.validate_module(module, policy)
        if not ok:
            return LexDecision(allowed=False, reason=reason)

        # Time window
        ok, reason = self.validate_time_window(policy, now=now)
        if not ok:
            return LexDecision(allowed=False, reason=reason)

        # CVSS
        ok, reason = self.validate_cvss_action(cvss, policy)
        if not ok:
            decision.requires_approval = True
            decision.reason = reason
            # In COMES mode this doesn't block — it requires approval
            if policy.mode == "COMES":
                decision.allowed = True
                decision.requires_approval = True
                decision.reason = reason
            else:
                # ITERUM or other — block
                return LexDecision(allowed=False, reason=reason)

        # Duration
        result = self.check_duration(started_at, policy, now=now)
        ok, reason = result[0], result[1]
        if len(result) > 2:
            all_warnings.extend(result[2])
        if not ok:
            return LexDecision(allowed=False, reason=reason, warnings=all_warnings)

        decision.warnings = all_warnings
        return decision
