"""MENS v2 — Mission-driven ENtity for Security.

Autonomous reasoning loop: observe -> think -> act -> learn.
Every action validated by LEX Decision Guard v2 (modules/lex.py).
"""

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal, Optional

from sqlalchemy import Column, String, Float, Integer, DateTime, Text, ForeignKey

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


# ── Three-head routing (Cerberus) ────────────────────────────


RATIO_MODULES: set[str] = {
    "nmap", "nuclei", "gobuster", "zap", "sqlmap", "testssl",
    "whatweb", "nikto", "wapiti", "searchsploit", "snmpwalk",
    "netexec", "enum4linux", "certipy", "trivy", "prowler",
}
ANIMUS_MODULES: set[str] = {
    "harvester", "sherlock", "maigret", "gophish",
    "evilginx", "beef", "gitleaks", "holehe",
}
FATUM_MODULES: set[str] = {
    "bloodhound", "impacket", "subfinder", "httpx",
    "fierce", "dnsx", "amass", "netdiscover",
}


def classify_head(module_name: str) -> Literal["RATIO", "ANIMUS", "FATUM"]:
    """Classify a module into one of the three Cerberus heads."""
    if module_name in ANIMUS_MODULES:
        return "ANIMUS"
    if module_name in FATUM_MODULES:
        return "FATUM"
    return "RATIO"


# ── Module -> scan function mapping ──────────────────────────────


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


# ── Data classes ─────────────────────────────────────────────────


@dataclass
class MensDecision:
    """Result of the think phase — what module to run and why."""

    module: str = ""
    target: str = ""
    reason: str = ""
    confidence: float = 0.0
    done: bool = False
    requires_approval: bool = False
    lex_warnings: list[str] = field(default_factory=list)


@dataclass
class MensMissionResult:
    """Final result of a completed MENS mission."""

    mission_id: str = ""
    iterations: int = 0
    findings_count: int = 0
    status: str = "completed"
    duration_seconds: float = 0.0
    summary: str = ""


# ── SQLAlchemy models (matching migration 0011) ─────────────────


class MensMissionModel(Base):
    """Persistent storage for MENS missions (v2)."""

    __tablename__ = "mens_missions"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    mission_id = Column(String(64), nullable=False, unique=True, index=True)
    target = Column(String(512), nullable=False)
    policy_id = Column(Integer, ForeignKey("lex_policies.id", ondelete="CASCADE"), nullable=False)
    mode = Column(String(20), nullable=False, server_default="COMES")
    status = Column(String(20), nullable=False, server_default="pending")
    started_at = Column(DateTime, server_default="now()")
    completed_at = Column(DateTime, nullable=True)
    iterations_count = Column(Integer, nullable=False, server_default="0")
    findings_count = Column(Integer, nullable=False, server_default="0")
    summary = Column(Text, nullable=True)
    created_by = Column(String(100), server_default="system")


class MensIterationModel(Base):
    """Persistent storage for MENS iteration steps (v2)."""

    __tablename__ = "mens_iterations"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    mission_id = Column(Integer, ForeignKey("mens_missions.id", ondelete="CASCADE"), nullable=False, index=True)
    iteration_number = Column(Integer, nullable=False, server_default="0")
    module_used = Column(String(100), nullable=True)
    target = Column(String(512), nullable=True)
    reason = Column(Text, nullable=True)
    confidence = Column(Float, nullable=False, server_default="0.0")
    result_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default="now()")


# ── Claude prompt ────────────────────────────────────────────────


_SYSTEM_PROMPT = """\
Jesteś MENS — Adversary Reasoning Engine systemu CYRBER.
Myślisz jak doświadczony pentester i atakujący.
Analizujesz cel i decydujesz który moduł skanowania uruchomić następny.

Odpowiedz TYLKO w formacie JSON (zero tekstu poza JSON):
{
  "module": "nazwa_modułu",
  "target": "cel",
  "reason": "uzasadnienie PO POLSKU, maksymalnie 2 zdania, pisz jak ekspert do klienta biznesowego - bez żargonu technicznego",
  "confidence": 0.5,
  "done": false
}

Jeśli misja zakończona — done: true, reason po polsku: co znalazłeś i jakie jest ryzyko.
"""

MAX_ITERATIONS = 50
MAX_DURATION_SECONDS = 28800  # 8h fallback


def _parse_decision(raw: str) -> dict:
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
    return {"module": "DONE", "reason": "Nie udało się sparsować odpowiedzi AI", "confidence": 0.0}


def _build_think_prompt(
    target: str,
    policy,
    context: dict,
) -> str:
    """Build the user prompt for the think phase."""
    # Build module list filtered by policy
    available = AVAILABLE_MODULES
    if policy.allowed_modules:
        available = [m for m in available if m in policy.allowed_modules]
    if policy.excluded_modules:
        available = [m for m in available if m not in policy.excluded_modules]

    modules_desc = "\n".join(
        f"  - {m}: {_MODULE_DESCRIPTIONS.get(m, '')}" for m in available
    )

    prev_iterations = ""
    for it in context.get("iterations", []):
        prev_iterations += (
            f"  #{it.get('number', '?')}: {it.get('module', '?')} -> "
            f"{it.get('summary', 'no result')}\n"
        )
    if not prev_iterations:
        prev_iterations = "  (none yet - this is the first iteration)\n"

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

    scope_str = ", ".join(policy.scope_cidrs) if policy.scope_cidrs else "(unrestricted)"
    excluded_str = ", ".join(policy.excluded_hosts) if policy.excluded_hosts else "(none)"

    return f"""\
TARGET: {target}
MODE: {policy.mode}

LEX POLICY CONSTRAINTS:
  Scope CIDRs: {scope_str}
  Excluded hosts: {excluded_str}
  Require approval CVSS: {policy.require_approval_cvss}
  Max duration: {policy.max_duration_seconds}s

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
    """Autonomous MENS v2 reasoning agent.

    Orchestrates the observe -> think -> act -> learn loop, with every action
    validated by LexEngine v2 before execution.
    """

    def __init__(self, mission_id: str, policy, db, llm_client=None):
        self.mission_id = mission_id
        self.policy = policy  # LexPolicy dataclass
        self.db = db
        self._provider = llm_client
        self._target_model: dict = {}  # accumulated target knowledge

    def _get_provider(self):
        """Lazy-init the LLM provider via task routing."""
        if self._provider is None:
            from modules.llm_provider import get_provider
            self._provider = get_provider(task="mens")
        return self._provider

    # ── Phase: OBSERVE ───────────────────────────────────────────

    def observe(self, target: str) -> dict:
        """Gather context: recent scans, intel, iteration history."""
        from modules.database import Scan, EpssCache, KevCache

        # Recent scans for this target
        recent_rows = (
            self.db.query(Scan)
            .filter(Scan.target == target)
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

        # Collect CVE IDs from recent scan findings
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
            epss = self.db.query(EpssCache).filter(EpssCache.cve_id == cve_id).first()
            if epss:
                entry["epss"] = epss.epss_score
            kev = self.db.query(KevCache).filter(KevCache.cve_id == cve_id).first()
            entry["kev"] = kev is not None
            if entry:
                intel[cve_id] = entry

        # Iteration history from DB
        mission_row = self.db.query(MensMissionModel).filter(
            MensMissionModel.mission_id == self.mission_id
        ).first()

        iterations = []
        if mission_row:
            iter_rows = (
                self.db.query(MensIterationModel)
                .filter(MensIterationModel.mission_id == mission_row.id)
                .order_by(MensIterationModel.iteration_number)
                .all()
            )
            iterations = [
                {
                    "number": r.iteration_number,
                    "module": r.module_used,
                    "summary": r.result_summary,
                    "target": r.target,
                }
                for r in iter_rows
            ]

        return {
            "recent_scans": recent_scans,
            "intel": intel,
            "iterations": iterations,
            "target_model": self._target_model,
        }

    # ── Phase: THINK ─────────────────────────────────────────────

    def think(self, target: str, context: dict) -> MensDecision:
        """Ask Claude Opus to decide the next module, then validate via LEX."""
        from modules.lex import LexEngine

        provider = self._get_provider()

        prompt = _build_think_prompt(target, self.policy, context)
        _log.info("[MENS] think: sending prompt to Claude Opus (%d chars)", len(prompt))

        raw_response = provider.chat(prompt, system=_SYSTEM_PROMPT, max_tokens=1024)
        _log.debug("[MENS] think: raw response: %s", raw_response[:500])

        parsed = _parse_decision(raw_response)

        module_name = parsed.get("module", "DONE")
        reason = parsed.get("reason", "") or parsed.get("reasoning", "")
        confidence = min(1.0, max(0.0, float(parsed.get("confidence", 0.0))))
        scan_target = parsed.get("target", target)

        # Honor "done" flag from prompt
        if parsed.get("done", False) and module_name != "DONE":
            module_name = "DONE"

        decision = MensDecision(
            module=module_name,
            target=scan_target,
            reason=reason,
            confidence=confidence,
        )

        # DONE -> mission complete
        if module_name == "DONE":
            decision.done = True
            return decision

        # Validate through LEX v2
        engine = LexEngine()
        lex_result = engine.validate_all(
            target=scan_target,
            module=module_name,
            cvss=0.0,  # Not known at think phase
            started_at=datetime.now(timezone.utc),
            policy=self.policy,
        )

        if not lex_result.allowed and not lex_result.requires_approval:
            decision.lex_warnings.append(f"BLOCKED: {lex_result.reason}")
            decision.module = ""  # Blocked — skip this module
            _log.warning("[MENS] LEX blocked module=%s: %s", module_name, lex_result.reason)

        if lex_result.requires_approval:
            decision.requires_approval = True
            decision.lex_warnings.append(f"APPROVAL REQUIRED: {lex_result.reason}")

        if lex_result.warnings:
            decision.lex_warnings.extend(lex_result.warnings)

        return decision

    # ── Phase: ACT ───────────────────────────────────────────────

    def act(self, decision: MensDecision) -> dict:
        """Execute the selected module."""
        if decision.done:
            return {"status": "done", "message": "Mission objective achieved"}

        if not decision.module:
            return {"status": "blocked", "message": "Module blocked by LEX"}

        # COMES mode: require explicit approval
        if self.policy.mode == "COMES" and decision.requires_approval:
            _log.info("[MENS] COMES mode: awaiting approval for module=%s", decision.module)
            return {"status": "pending_approval"}

        scan_fn = _get_scan_function(decision.module)
        if scan_fn is None:
            _log.error("[MENS] unknown module: %s", decision.module)
            return {"status": "error", "message": f"Unknown module: {decision.module}"}

        _log.info("[MENS] act: running %s on %s", decision.module, decision.target)

        try:
            result = scan_fn(decision.target)
        except Exception as exc:
            _log.exception("[MENS] module %s failed: %s", decision.module, exc)
            return {"status": "error", "message": str(exc)}

        return {"status": "completed", "result": result}

    # ── Phase: LEARN ─────────────────────────────────────────────

    def learn(self, decision: MensDecision, result: dict, mission_db_id: int) -> int:
        """Persist iteration, update target model. Returns findings count."""
        # Count findings from result
        findings_count = 0
        scan_result = result.get("result", {})
        if isinstance(scan_result, dict):
            findings = scan_result.get("findings", [])
            if isinstance(findings, list):
                findings_count = len(findings)

        # Generate summary
        summary = self._summarize_result(decision.module, scan_result)

        # Update target model
        if decision.module and scan_result:
            self._target_model[decision.module] = {
                "findings": findings_count,
                "summary": summary,
            }

        # Get iteration number
        existing_count = (
            self.db.query(MensIterationModel)
            .filter(MensIterationModel.mission_id == mission_db_id)
            .count()
        )

        # Save iteration to DB
        iteration_row = MensIterationModel(
            mission_id=mission_db_id,
            iteration_number=existing_count + 1,
            module_used=decision.module or None,
            target=decision.target,
            reason=decision.reason,
            confidence=decision.confidence,
            result_summary=summary,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(iteration_row)
        self.db.commit()

        _log.info(
            "[MENS] learn: module=%s findings=%d confidence=%.2f",
            decision.module, findings_count, decision.confidence,
        )

        return findings_count

    def _summarize_result(self, module_name: str, scan_result) -> str:
        """Generate a short summary of scan results via Claude Haiku."""
        if not scan_result:
            return f"{module_name}: no results"

        snippet = json.dumps(scan_result, ensure_ascii=False, default=str)[:2000]

        try:
            from modules.llm_provider import get_provider
            haiku = get_provider(task="summary")
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

    def run(self, target: str) -> MensMissionResult:
        """Run the full observe -> think -> act -> learn loop until done."""
        start_time = time.time()

        # Get mission DB row
        mission_row = self.db.query(MensMissionModel).filter(
            MensMissionModel.mission_id == self.mission_id
        ).first()
        if not mission_row:
            raise RuntimeError(f"Mission {self.mission_id} not found in DB")

        mission_db_id = mission_row.id
        total_findings = 0
        iteration_count = 0

        while iteration_count < MAX_ITERATIONS:
            # Check duration
            elapsed = time.time() - start_time
            max_dur = self.policy.max_duration_seconds or MAX_DURATION_SECONDS
            if elapsed > max_dur:
                _log.warning("[MENS] mission duration exceeded: %.0fs > %ds", elapsed, max_dur)
                break

            # Check if mission was aborted externally
            self.db.expire_all()
            fresh_row = self.db.query(MensMissionModel).filter(
                MensMissionModel.id == mission_db_id
            ).first()
            if not fresh_row or fresh_row.status == "aborted":
                _log.info("[MENS] mission aborted externally")
                break

            # OBSERVE
            context = self.observe(target)

            # THINK
            decision = self.think(target, context)

            # ACT
            result = self.act(decision)

            # Handle COMES pending_approval
            if result.get("status") == "pending_approval":
                mission_row.status = "paused"
                self.db.commit()
                _log.info("[MENS] COMES: paused for approval on module=%s", decision.module)
                return MensMissionResult(
                    mission_id=self.mission_id,
                    iterations=iteration_count,
                    findings_count=total_findings,
                    status="paused",
                    duration_seconds=time.time() - start_time,
                    summary="Awaiting operator approval",
                )

            # LEARN
            findings = self.learn(decision, result, mission_db_id)
            total_findings += findings
            iteration_count += 1

            # Update mission counters
            mission_row.iterations_count = iteration_count
            mission_row.findings_count = total_findings
            self.db.commit()

            # Check if done
            if decision.done:
                break

        # Finalize
        elapsed = time.time() - start_time
        status = "completed"

        self.db.expire_all()
        final_row = self.db.query(MensMissionModel).filter(
            MensMissionModel.id == mission_db_id
        ).first()
        if final_row:
            if final_row.status == "aborted":
                status = "aborted"
            else:
                final_row.status = "completed"
                final_row.completed_at = datetime.now(timezone.utc)
                final_row.iterations_count = iteration_count
                final_row.findings_count = total_findings
                final_row.summary = f"{iteration_count} iterations, {total_findings} findings in {elapsed:.0f}s"
                self.db.commit()

        return MensMissionResult(
            mission_id=self.mission_id,
            iterations=iteration_count,
            findings_count=total_findings,
            status=status,
            duration_seconds=elapsed,
            summary=f"{iteration_count} iterations, {total_findings} findings",
        )
