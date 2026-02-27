"""MENS — Mission-driven ENtity for Security.

Autonomous reasoning loop: observe → think → act → learn.
Every action validated by LEX Decision Guard before execution.
"""

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, Text
from sqlalchemy.types import JSON

from backend.lex import LexEngine, LexRule
from modules.database import Base, SessionLocal

_log = logging.getLogger("cyrber.mens")


# ── Available modules ────────────────────────────────────────────


AVAILABLE_MODULES: list[str] = [
    "nmap", "nuclei", "gobuster", "zap", "sqlmap",
    "testssl", "whatweb", "netexec", "bloodhound", "enum4linux",
    "certipy", "harvester", "subfinder", "httpx", "nikto",
    "wapiti", "searchsploit", "snmpwalk", "dnsrecon", "whois",
]

_MODULE_DESCRIPTIONS: dict[str, str] = {
    "nmap": "Port scanning and service detection",
    "nuclei": "Template-based vulnerability scanner",
    "gobuster": "Directory and file brute-force",
    "zap": "OWASP ZAP active web scanner",
    "sqlmap": "SQL injection detection and exploitation",
    "testssl": "TLS/SSL configuration audit",
    "whatweb": "Web technology fingerprinting",
    "netexec": "SMB/WinRM/LDAP enumeration and lateral movement",
    "bloodhound": "Active Directory attack path mapping",
    "enum4linux": "SMB/NetBIOS/LDAP enumeration",
    "certipy": "Active Directory Certificate Services audit",
    "harvester": "Email, subdomain, and name harvesting (OSINT)",
    "subfinder": "Passive subdomain enumeration",
    "httpx": "HTTP probing and technology detection",
    "nikto": "Web server misconfiguration scanner",
    "wapiti": "Web application vulnerability scanner",
    "searchsploit": "Offline Exploit-DB search for known CVEs",
    "snmpwalk": "SNMP enumeration",
    "dnsrecon": "DNS record enumeration and zone transfer",
    "whois": "WHOIS domain registration lookup",
}


def get_available_modules() -> list[str]:
    """Return the list of modules MENS can select from."""
    return list(AVAILABLE_MODULES)


# ── Module → scan function mapping ──────────────────────────────


def _get_scan_function(module_name: str):
    """Lazy-import and return the scan callable for a module.

    Returns None if module is unknown.
    """
    _IMPORT_MAP = {
        "nmap": ("modules.nmap_scan", "scan"),
        "nuclei": ("modules.nuclei_scan", "scan"),
        "gobuster": ("modules.gobuster_scan", "scan"),
        "zap": ("modules.zap_scan", "zap_scan"),
        "sqlmap": ("modules.sqlmap_scan", "scan"),
        "testssl": ("modules.testssl_scan", "scan"),
        "whatweb": ("modules.whatweb_scan", "scan"),
        "netexec": ("modules.netexec_scan", "netexec_scan"),
        "bloodhound": ("modules.bloodhound_scan", "bloodhound_scan"),
        "enum4linux": ("modules.enum4linux_scan", "enum4linux_scan"),
        "certipy": ("modules.certipy_scan", "run_certipy"),
        "harvester": ("modules.harvester_scan", "scan"),
        "subfinder": ("modules.subfinder_scan", "subfinder_scan"),
        "httpx": ("modules.httpx_scan", "httpx_scan"),
        "nikto": ("modules.nikto_scan", "scan"),
        "wapiti": ("modules.wapiti_scan", "wapiti_scan"),
        "searchsploit": ("modules.searchsploit_scan", "searchsploit_scan"),
        "snmpwalk": ("modules.snmpwalk_scan", "snmpwalk_scan"),
        "dnsrecon": ("modules.dnsrecon_scan", "dnsrecon_scan"),
        "whois": ("modules.whois_scan", "whois_scan"),
    }
    entry = _IMPORT_MAP.get(module_name)
    if not entry:
        return None
    mod_path, func_name = entry
    import importlib
    mod = importlib.import_module(mod_path)
    return getattr(mod, func_name)


# ── Pydantic models ─────────────────────────────────────────────


class MensIteration(BaseModel):
    """Single observe→think→act→learn cycle."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    mission_id: uuid.UUID
    iteration_number: int = 0
    phase: Literal["observe", "think", "act", "learn"] = "observe"
    module_selected: Optional[str] = None
    module_args: Optional[dict] = None
    cogitatio: Optional[str] = None
    result_summary: Optional[str] = None
    findings_count: int = 0
    approved: Optional[bool] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"from_attributes": True}


class MensMission(BaseModel):
    """A MENS autonomous mission."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    target: str
    objective: str
    lex_rule_id: uuid.UUID
    mode: Literal["comes", "liber", "iterum"] = "comes"
    status: Literal["pending", "running", "paused", "completed", "aborted"] = "pending"
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    created_by: str = "system"
    iterations: list[MensIteration] = Field(default_factory=list)
    fiducia: float = 0.0

    model_config = {"from_attributes": True}


# ── SQLAlchemy models ────────────────────────────────────────────


class MensMissionModel(Base):
    """Persistent storage for MENS missions."""

    __tablename__ = "mens_missions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String, nullable=False)
    objective = Column(Text, nullable=False)
    lex_rule_id = Column(String, nullable=False, index=True)
    mode = Column(String, default="comes")
    status = Column(String, default="pending")
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(String, default="system")
    fiducia = Column(Float, default=0.0)


class MensIterationModel(Base):
    """Persistent storage for MENS iteration steps."""

    __tablename__ = "mens_iterations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    mission_id = Column(String, nullable=False, index=True)
    iteration_number = Column(Integer, default=0)
    phase = Column(String, default="observe")
    module_selected = Column(String, nullable=True)
    module_args = Column(JSON, nullable=True)
    cogitatio = Column(Text, nullable=True)
    result_summary = Column(Text, nullable=True)
    findings_count = Column(Integer, default=0)
    approved = Column(Boolean, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ── Claude prompt ────────────────────────────────────────────────


_SYSTEM_PROMPT = """\
You are MENS (Mission-driven ENtity for Security), the autonomous reasoning \
core of the CYRBER penetration testing platform.

Your task is to decide the NEXT scanning module to run in order to achieve \
the mission objective. You reason step-by-step like a senior penetration tester.

RULES:
- Pick exactly ONE module per iteration.
- Only choose modules from the AVAILABLE list.
- Consider what has already been scanned — do not repeat modules unless \
  new information warrants it.
- If the objective is achieved or no further modules would help, set \
  "module" to "DONE".
- Estimate how much closer this step brings us to the objective as \
  "fiducia_delta" (0.0 to 0.2).

Respond ONLY with a JSON object (no markdown, no commentary):
{
  "module": "module_name_or_DONE",
  "args": {"target": "..."},
  "reasoning": "one paragraph explaining your decision",
  "fiducia_delta": 0.05
}
"""


def _build_think_prompt(
    mission: MensMission,
    context: dict,
    rule: LexRule,
) -> str:
    """Build the user prompt for the think phase."""
    modules_desc = "\n".join(
        f"  - {m}: {_MODULE_DESCRIPTIONS.get(m, '')}" for m in AVAILABLE_MODULES
    )

    # Filter modules by LEX rule
    if rule.allowed_modules is not None:
        allowed = [m for m in AVAILABLE_MODULES if m in rule.allowed_modules]
        modules_desc = "\n".join(
            f"  - {m}: {_MODULE_DESCRIPTIONS.get(m, '')}" for m in allowed
        )

    prev_iterations = ""
    for it in context.get("iterations", []):
        prev_iterations += (
            f"  #{it.get('number', '?')}: {it.get('module', '?')} → "
            f"{it.get('summary', 'no result')}\n"
        )
    if not prev_iterations:
        prev_iterations = "  (none yet — this is the first iteration)\n"

    recent_scans = ""
    for s in context.get("recent_scans", []):
        recent_scans += (
            f"  - {s.get('target', '?')} [{s.get('risk_level', '?')}] "
            f"findings={s.get('findings_count', 0)} "
            f"profile={s.get('profile', '?')}\n"
        )
    if not recent_scans:
        recent_scans = "  (no prior scans for this target)\n"

    intel_summary = ""
    for cve, info in context.get("intel", {}).items():
        intel_summary += f"  - {cve}: EPSS={info.get('epss', 'N/A')}, KEV={info.get('kev', False)}\n"
    if not intel_summary:
        intel_summary = "  (no CVE intel available yet)\n"

    scope_str = ", ".join(rule.scope_cidrs) if rule.scope_cidrs else "(unrestricted)"
    excluded_str = ", ".join(rule.excluded_hosts) if rule.excluded_hosts else "(none)"

    return f"""\
MISSION OBJECTIVE: {mission.objective}
TARGET: {mission.target}
MODE: {mission.mode}
CURRENT FIDUCIA (confidence): {mission.fiducia:.2f}

LEX CONSTRAINTS:
  Scope CIDRs: {scope_str}
  Excluded hosts: {excluded_str}
  Max CVSS without approval: {rule.max_cvss_without_approval}
  Max duration: {rule.max_duration_minutes} min

AVAILABLE MODULES:
{modules_desc}

PREVIOUS ITERATIONS:
{prev_iterations}
RECENT SCANS ON THIS TARGET:
{recent_scans}
THREAT INTEL:
{intel_summary}
Based on the above, decide the next module to run. Respond with JSON only."""


# ── Agent ────────────────────────────────────────────────────────


class MensAgent:
    """Autonomous MENS reasoning agent.

    Orchestrates the observe→think→act→learn loop, with every action
    validated by LexEngine before execution.
    """

    def __init__(self, mission: MensMission, lex_engine: LexEngine):
        self.mission = mission
        self.lex = lex_engine
        self._rule: Optional[LexRule] = None
        self._provider = None

    def _get_provider(self):
        """Lazy-init the Claude provider."""
        if self._provider is None:
            from modules.llm_provider import ClaudeProvider
            self._provider = ClaudeProvider(model="claude-opus-4-20250514")
        return self._provider

    def _get_rule(self) -> LexRule:
        """Load and cache the LEX rule for this mission."""
        if self._rule is None:
            self._rule = self.lex.load_rule(str(self.mission.lex_rule_id))
            if self._rule is None:
                raise RuntimeError(
                    f"LEX rule {self.mission.lex_rule_id} not found or inactive — "
                    "MENS cannot operate without an active LEX rule"
                )
        return self._rule

    # ── Phase: OBSERVE ───────────────────────────────────────────

    def observe(self, db_session) -> dict:
        """Gather context: recent scans, intel, iteration history."""
        from modules.database import Scan, EpssCache, KevCache

        # Recent scans for this target
        recent_rows = (
            db_session.query(Scan)
            .filter(Scan.target == self.mission.target)
            .order_by(Scan.created_at.desc())
            .limit(5)
            .all()
        )
        recent_scans = [
            {
                "target": r.target,
                "risk_level": r.risk_level,
                "findings_count": r.findings_count,
                "profile": r.profile,
                "created_at": str(r.created_at) if r.created_at else None,
            }
            for r in recent_rows
        ]

        # Collect CVE IDs from recent scan findings for intel enrichment
        cve_ids: set[str] = set()
        for row in recent_rows:
            if not row.raw_data:
                continue
            try:
                raw = json.loads(row.raw_data) if isinstance(row.raw_data, str) else {}
                nuclei = raw.get("nuclei", {})
                if isinstance(nuclei, dict):
                    for f in nuclei.get("findings", []):
                        for ref in (f.get("info", {}).get("reference") or []):
                            if isinstance(ref, str) and ref.startswith("CVE-"):
                                cve_ids.add(ref)
            except (json.JSONDecodeError, TypeError):
                pass

        # Enrich with EPSS/KEV intel
        intel: dict[str, dict] = {}
        for cve_id in list(cve_ids)[:20]:
            entry: dict = {}
            epss = db_session.query(EpssCache).filter(EpssCache.cve_id == cve_id).first()
            if epss:
                entry["epss"] = epss.epss_score
            kev = db_session.query(KevCache).filter(KevCache.cve_id == cve_id).first()
            entry["kev"] = kev is not None
            if entry:
                intel[cve_id] = entry

        # Iteration history
        iter_rows = (
            db_session.query(MensIterationModel)
            .filter(MensIterationModel.mission_id == str(self.mission.id))
            .order_by(MensIterationModel.iteration_number)
            .all()
        )
        iterations = [
            {
                "number": r.iteration_number,
                "module": r.module_selected,
                "summary": r.result_summary,
                "findings": r.findings_count,
                "phase": r.phase,
            }
            for r in iter_rows
        ]

        return {
            "recent_scans": recent_scans,
            "intel": intel,
            "iterations": iterations,
        }

    # ── Phase: THINK ─────────────────────────────────────────────

    def think(self, context: dict) -> MensIteration:
        """Ask Claude Opus to decide the next module."""
        rule = self._get_rule()
        provider = self._get_provider()

        prompt = _build_think_prompt(self.mission, context, rule)
        _log.info("[MENS] think: sending prompt to Claude Opus (%d chars)", len(prompt))

        raw_response = provider.chat(prompt, system=_SYSTEM_PROMPT, max_tokens=1024)
        _log.debug("[MENS] think: raw response: %s", raw_response[:500])

        # Parse JSON from response
        decision = self._parse_decision(raw_response)

        module_name = decision.get("module")
        reasoning = decision.get("reasoning", "")
        fiducia_delta = min(0.2, max(0.0, float(decision.get("fiducia_delta", 0.0))))
        args = decision.get("args", {"target": self.mission.target})

        # Ensure target is always in args
        if "target" not in args:
            args["target"] = self.mission.target

        # Use DB-sourced iteration history for correct numbering
        iteration_number = len(context.get("iterations", [])) + 1

        iteration = MensIteration(
            mission_id=self.mission.id,
            iteration_number=iteration_number,
            phase="think",
            module_selected=module_name,
            module_args=args,
            cogitatio=reasoning,
        )

        # If DONE — mission complete
        if module_name == "DONE":
            iteration.result_summary = "Agent decided mission objective is achieved."
            return iteration

        # Validate through LEX
        lex_decision = self.lex.check_all(
            target=args.get("target", self.mission.target),
            module_name=module_name,
            cvss=0.0,  # Not known yet at think phase
            start_time=self.mission.started_at,
            rule=rule,
        )

        if not lex_decision.allowed and not lex_decision.requires_approval:
            iteration.cogitatio += f"\n\n[LEX BLOCKED: {lex_decision.reason}]"
            iteration.approved = False
            _log.warning("[MENS] LEX blocked module=%s: %s", module_name, lex_decision.reason)

        if lex_decision.requires_approval:
            iteration.cogitatio += "\n\n[LEX: requires operator approval — CVSS threshold]"
            iteration.approved = None  # pending approval

        # Store fiducia_delta for learn phase
        iteration.module_args = {**(iteration.module_args or {}), "_fiducia_delta": fiducia_delta}

        return iteration

    def _parse_decision(self, raw: str) -> dict:
        """Extract JSON decision from Claude response."""
        text = raw.strip()

        # Strip markdown code fences
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
            text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Fallback: find first { ... } block
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    pass

        _log.error("[MENS] failed to parse Claude decision: %s", text[:200])
        return {"module": "DONE", "reasoning": "Failed to parse AI response", "fiducia_delta": 0.0}

    # ── Phase: ACT ───────────────────────────────────────────────

    def act(self, iteration: MensIteration, db_session) -> dict:
        """Execute the selected module. Respects COMES approval mode."""
        if iteration.module_selected == "DONE":
            return {"status": "done", "message": "Mission objective achieved"}

        # COMES mode: require explicit approval
        if self.mission.mode == "comes" and iteration.approved is None:
            self._save_iteration(iteration, db_session)
            _log.info("[MENS] COMES mode: awaiting approval for module=%s", iteration.module_selected)
            return {"status": "pending_approval"}

        if iteration.approved is False:
            _log.info("[MENS] iteration rejected by LEX or operator")
            return {"status": "rejected"}

        module_name = iteration.module_selected
        args = dict(iteration.module_args or {})
        args.pop("_fiducia_delta", None)  # Internal field, not for scan function

        target = args.pop("target", self.mission.target)

        scan_fn = _get_scan_function(module_name)
        if scan_fn is None:
            _log.error("[MENS] unknown module: %s", module_name)
            return {"status": "error", "message": f"Unknown module: {module_name}"}

        _log.info("[MENS] act: running %s on %s", module_name, target)
        iteration.phase = "act"

        try:
            result = scan_fn(target, **args) if args else scan_fn(target)
        except Exception as exc:
            _log.exception("[MENS] module %s failed: %s", module_name, exc)
            return {"status": "error", "message": str(exc)}

        return {"status": "completed", "result": result}

    # ── Phase: LEARN ─────────────────────────────────────────────

    def learn(self, iteration: MensIteration, result: dict, db_session) -> None:
        """Persist results, update fiducia, generate summary."""
        iteration.phase = "learn"

        # Count findings from result
        scan_result = result.get("result", {})
        if isinstance(scan_result, dict):
            findings = scan_result.get("findings", [])
            if isinstance(findings, list):
                iteration.findings_count = len(findings)

        # Generate summary via Claude Haiku
        iteration.result_summary = self._summarize_result(
            iteration.module_selected, scan_result
        )

        # Update fiducia
        fiducia_delta = (iteration.module_args or {}).get("_fiducia_delta", 0.0)
        self.mission.fiducia = min(1.0, self.mission.fiducia + fiducia_delta)

        # If module said DONE or fiducia is high enough
        if iteration.module_selected == "DONE" or self.mission.fiducia >= 0.95:
            self.mission.status = "completed"
            self.mission.completed_at = datetime.now(timezone.utc)

        # Persist iteration and update mission
        self._save_iteration(iteration, db_session)
        self._update_mission(db_session)

        # Track in mission object
        self.mission.iterations.append(iteration)

        _log.info(
            "[MENS] learn: module=%s findings=%d fiducia=%.2f",
            iteration.module_selected, iteration.findings_count, self.mission.fiducia,
        )

    def _summarize_result(self, module_name: str, scan_result) -> str:
        """Generate a short summary of scan results via Claude Haiku."""
        if not scan_result:
            return f"{module_name}: no results"

        snippet = json.dumps(scan_result, ensure_ascii=False, default=str)[:2000]

        try:
            from modules.llm_provider import ClaudeProvider
            haiku = ClaudeProvider(model="claude-haiku-4-5-20251001")
            summary = haiku.chat(
                f"Summarize this {module_name} scan result in one sentence "
                f"(max 100 tokens). Focus on key findings and risk.\n\n{snippet}",
                max_tokens=100,
            )
            return summary.strip()
        except Exception as exc:
            _log.warning("[MENS] Haiku summary failed: %s", exc)
            findings = scan_result.get("findings", []) if isinstance(scan_result, dict) else []
            return f"{module_name}: {len(findings)} findings"

    # ── Orchestrator ─────────────────────────────────────────────

    def run_iteration(self, db_session) -> MensIteration:
        """Execute one full observe→think→act→learn cycle."""
        rule = self._get_rule()

        # Check mission duration via LEX
        duration_ok, duration_msg = self.lex.validate_duration(
            self.mission.started_at, rule
        )
        if not duration_ok:
            _log.warning("[MENS] mission duration exceeded: %s", duration_msg)
            self.mission.status = "completed"
            self.mission.completed_at = datetime.now(timezone.utc)
            self._update_mission(db_session)
            return MensIteration(
                mission_id=self.mission.id,
                iteration_number=len(self.mission.iterations) + 1,
                phase="observe",
                cogitatio=f"Mission ended: {duration_msg}",
                result_summary=f"Duration limit reached: {duration_msg}",
            )

        # OBSERVE
        context = self.observe(db_session)

        # THINK
        iteration = self.think(context)

        # ACT
        if iteration.approved is False:
            # LEX blocked — skip act, go to learn with empty result
            result = {"status": "blocked", "message": iteration.cogitatio}
        elif iteration.module_selected == "DONE":
            result = {"status": "done"}
            self.mission.status = "completed"
            self.mission.completed_at = datetime.now(timezone.utc)
        else:
            result = self.act(iteration, db_session)
            if result.get("status") == "pending_approval":
                return iteration  # Paused — waiting for operator

        # LEARN
        self.learn(iteration, result, db_session)

        return iteration

    # ── DB persistence ───────────────────────────────────────────

    def _save_iteration(self, iteration: MensIteration, db_session) -> None:
        """Persist a MensIteration to the database."""
        args = dict(iteration.module_args or {})
        # Keep _fiducia_delta in DB so it survives COMES resume cycles

        row = MensIterationModel(
            id=str(iteration.id),
            mission_id=str(iteration.mission_id),
            iteration_number=iteration.iteration_number,
            phase=iteration.phase,
            module_selected=iteration.module_selected,
            module_args=args if args else None,
            cogitatio=iteration.cogitatio,
            result_summary=iteration.result_summary,
            findings_count=iteration.findings_count,
            approved=iteration.approved,
            created_at=iteration.created_at,
        )
        db_session.merge(row)
        db_session.commit()

    def _update_mission(self, db_session) -> None:
        """Update the mission row in the database."""
        row = db_session.query(MensMissionModel).filter(
            MensMissionModel.id == str(self.mission.id)
        ).first()
        if row:
            row.status = self.mission.status
            row.fiducia = self.mission.fiducia
            row.completed_at = self.mission.completed_at
            db_session.commit()
