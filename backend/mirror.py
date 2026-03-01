"""CYRBER MIRROR — Organization Model Builder.

Builds a behavioural profile of the target organization based on MENS
mission data.  Generates a Security Genome Report that describes the
organisation as a living organism — its predispositions, historical
patterns and 30-day forecast.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Float, Integer, DateTime, Text, UniqueConstraint
from sqlalchemy.types import JSON

from modules.database import Base, SessionLocal

_log = logging.getLogger("cyrber.mirror")


# ── Pydantic models ─────────────────────────────────────────────


class OrganizationProfile(BaseModel):
    """Behavioural profile of a target organization."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    target: str
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    missions_count: int = 0
    patch_cycle_days: Optional[float] = None
    phishing_click_rate: Optional[float] = None
    credential_reuse_incidents: int = 0
    unreviewed_services: int = 0
    predispositions: dict = Field(default_factory=lambda: {
        "ransomware": 0.0, "supply_chain": 0.0, "phishing": 0.0,
    })
    patterns: List[str] = Field(default_factory=list)
    genome_report: Optional[str] = None
    genome_generated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class SecurityGenomeInput(BaseModel):
    """Input bundle for genome generation."""

    target: str
    missions: List[dict] = Field(default_factory=list)
    profile: OrganizationProfile


# ── SQLAlchemy model ─────────────────────────────────────────────


class OrganizationProfileModel(Base):
    """Persistent storage for organization profiles."""

    __tablename__ = "organization_profiles"
    __table_args__ = (
        UniqueConstraint("target", name="uq_organization_profiles_target"),
    )

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String(255), nullable=False)
    last_updated = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    missions_count = Column(Integer, default=0)
    patch_cycle_days = Column(Float, nullable=True)
    phishing_click_rate = Column(Float, nullable=True)
    credential_reuse_incidents = Column(Integer, default=0)
    unreviewed_services = Column(Integer, default=0)
    predispositions = Column(JSON, default=lambda: {
        "ransomware": 0.0, "supply_chain": 0.0, "phishing": 0.0,
    })
    patterns = Column(JSON, default=list)
    genome_report = Column(Text, nullable=True)
    genome_generated_at = Column(DateTime, nullable=True)


# ── Genome generation prompt ─────────────────────────────────────


_GENOME_SYSTEM = """\
You are MIRROR, the organizational profiling engine of the CYRBER \
penetration testing platform.  You produce a Security Genome Report — \
a characterization of the target organization as a living organism \
with predispositions, patterns and a forecast.

Write in the second person ("your organization…").  Be direct, \
concrete and actionable.  Do NOT list CVEs — focus on systemic traits.\
"""


def _build_genome_prompt(profile: OrganizationProfile) -> str:
    pred = profile.predispositions or {}
    patterns_str = "\n".join(f"  - {p}" for p in (profile.patterns or [])) or "  (none observed yet)"

    return f"""\
TARGET: {profile.target}
MISSIONS COMPLETED: {profile.missions_count}
PATCH CYCLE: {profile.patch_cycle_days or 'unknown'} days (avg CVE → patch)
PHISHING CLICK RATE: {profile.phishing_click_rate or 'untested'}
CREDENTIAL REUSE INCIDENTS: {profile.credential_reuse_incidents}
UNREVIEWED SERVICES: {profile.unreviewed_services}

PREDISPOSITION SCORES (0.0 – 1.0):
  Ransomware: {pred.get('ransomware', 0.0):.2f}
  Supply-chain: {pred.get('supply_chain', 0.0):.2f}
  Phishing: {pred.get('phishing', 0.0):.2f}

OBSERVED PATTERNS:
{patterns_str}

Generate a Security Genome Report with exactly four sections:

## PREDYSPOZYCJE
For each predisposition (ransomware, supply-chain, phishing) — explain \
WHY the score is what it is.  Reference concrete observations from missions.

## WZORCE HISTORYCZNE
What recurring behaviours or gaps appear across multiple missions?

## FENOTYP ORGANIZACJI
One-paragraph personality sketch: how does this organization approach \
security?  Is it reactive, proactive, under-resourced, compliant-on-paper?

## PROGNOZA 30 DNI
Most likely incident type and attack vector in the next 30 days.  \
Concrete, actionable prediction — not vague warnings."""


# ── ANIMUS module names (for phishing detection) ─────────────────

_ANIMUS_MODULES = {
    "harvester", "sherlock", "maigret", "gophish",
    "evilginx", "beef", "gitleaks", "holehe",
}


# ── Engine ───────────────────────────────────────────────────────


class MirrorEngine:
    """Builds and maintains organization profiles from MENS data."""

    def update_profile(
        self,
        target: str,
        mission_data: dict,
        db_session,
    ) -> OrganizationProfile:
        """Update (or create) the organization profile from a completed mission."""

        row = db_session.query(OrganizationProfileModel).filter(
            OrganizationProfileModel.target == target,
        ).first()

        if not row:
            row = OrganizationProfileModel(
                id=str(uuid.uuid4()),
                target=target,
            )
            db_session.add(row)

        # ── Increment mission counter ────────────────────────────
        row.missions_count = (row.missions_count or 0) + 1
        row.last_updated = datetime.now(timezone.utc)

        iterations = mission_data.get("iterations", [])
        modules_used = [it.get("module") for it in iterations if it.get("module")]
        total_findings = sum(it.get("findings_count", 0) for it in iterations)

        # ── Patch cycle estimation ───────────────────────────────
        # Use mission data to estimate how fast this org patches
        cve_age_days = mission_data.get("cve_age_days")
        if cve_age_days is not None:
            if row.patch_cycle_days is not None:
                # Exponential moving average
                row.patch_cycle_days = row.patch_cycle_days * 0.7 + cve_age_days * 0.3
            else:
                row.patch_cycle_days = cve_age_days

        # ── Phishing click rate ──────────────────────────────────
        animus_used = [m for m in modules_used if m in _ANIMUS_MODULES]
        if animus_used:
            phishing_findings = sum(
                it.get("findings_count", 0) for it in iterations
                if it.get("module") in _ANIMUS_MODULES
            )
            # Heuristic: more findings = worse click rate
            rate = min(1.0, phishing_findings * 0.1)
            if row.phishing_click_rate is not None:
                row.phishing_click_rate = row.phishing_click_rate * 0.7 + rate * 0.3
            else:
                row.phishing_click_rate = rate

        # ── Credential reuse detection ───────────────────────────
        for it in iterations:
            summary = (it.get("result_summary") or "").lower()
            if "credential" in summary and "reuse" in summary:
                row.credential_reuse_incidents = (row.credential_reuse_incidents or 0) + 1

        # ── Unreviewed services ──────────────────────────────────
        # Count from nmap-like findings: new open ports
        if "nmap" in modules_used:
            nmap_findings = sum(
                it.get("findings_count", 0) for it in iterations
                if it.get("module") == "nmap"
            )
            row.unreviewed_services = nmap_findings

        # ── Recalculate predispositions ──────────────────────────
        pred = dict(row.predispositions or {})

        # Ransomware: high if RDP/SMB open or many findings
        rdp_smb_found = any(
            m in modules_used for m in ("netexec", "enum4linux", "bloodhound")
        )
        ransomware_score = 0.0
        if rdp_smb_found:
            ransomware_score += 0.4
        if total_findings > 10:
            ransomware_score += 0.3
        if (row.patch_cycle_days or 0) > 90:
            ransomware_score += 0.3
        pred["ransomware"] = min(1.0, ransomware_score)

        # Supply chain: high if many old unpatched CVEs
        supply_score = 0.0
        if (row.patch_cycle_days or 0) > 180:
            supply_score += 0.6
        elif (row.patch_cycle_days or 0) > 90:
            supply_score += 0.3
        if total_findings > 20:
            supply_score += 0.2
        if (row.unreviewed_services or 0) > 5:
            supply_score += 0.2
        pred["supply_chain"] = min(1.0, supply_score)

        # Phishing: inverse of resistance
        if row.phishing_click_rate is not None:
            pred["phishing"] = min(1.0, row.phishing_click_rate * 1.5)
        else:
            # Untested = moderate risk
            pred["phishing"] = 0.4

        row.predispositions = pred

        # ── Update patterns ──────────────────────────────────────
        patterns = list(row.patterns or [])
        if total_findings > 15:
            _add_pattern(patterns, "High finding density across missions")
        if rdp_smb_found:
            _add_pattern(patterns, "Active Directory / SMB exposure detected")
        if animus_used:
            _add_pattern(patterns, "Social engineering surface tested")
        if (row.patch_cycle_days or 0) > 90:
            _add_pattern(patterns, "Slow patching cycle (>90 days)")
        row.patterns = patterns

        db_session.commit()

        return _row_to_profile(row)

    def generate_genome(
        self,
        profile: OrganizationProfile,
        db_session,
    ) -> str:
        """Generate a Security Genome Report via Claude Opus."""

        from modules.llm_provider import get_provider
        provider = get_provider(task="reasoning")

        prompt = _build_genome_prompt(profile)
        _log.info("[MIRROR] generating genome for target=%s", profile.target)

        report = provider.chat(prompt, system=_GENOME_SYSTEM, max_tokens=2048)
        report = report.strip()

        # Persist
        row = db_session.query(OrganizationProfileModel).filter(
            OrganizationProfileModel.target == profile.target,
        ).first()
        if row:
            row.genome_report = report
            row.genome_generated_at = datetime.now(timezone.utc)
            db_session.commit()

        _log.info("[MIRROR] genome generated for %s (%d chars)", profile.target, len(report))
        return report


# ── Helpers ──────────────────────────────────────────────────────


def _add_pattern(patterns: list, pattern: str) -> None:
    """Add pattern if not already present (max 20)."""
    if pattern not in patterns:
        patterns.append(pattern)
    if len(patterns) > 20:
        patterns[:] = patterns[-20:]


def _row_to_profile(row: OrganizationProfileModel) -> OrganizationProfile:
    """Convert DB row to Pydantic model."""
    return OrganizationProfile(
        id=uuid.UUID(row.id) if row.id else uuid.uuid4(),
        target=row.target,
        last_updated=row.last_updated or datetime.now(timezone.utc),
        missions_count=row.missions_count or 0,
        patch_cycle_days=row.patch_cycle_days,
        phishing_click_rate=row.phishing_click_rate,
        credential_reuse_incidents=row.credential_reuse_incidents or 0,
        unreviewed_services=row.unreviewed_services or 0,
        predispositions=row.predispositions or {"ransomware": 0.0, "supply_chain": 0.0, "phishing": 0.0},
        patterns=row.patterns or [],
        genome_report=row.genome_report,
        genome_generated_at=row.genome_generated_at,
    )
