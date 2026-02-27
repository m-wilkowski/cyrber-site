from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float, ForeignKey
from sqlalchemy.types import JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
import json
import time
from dotenv import load_dotenv
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String, unique=True, index=True)
    target = Column(String, nullable=False)
    status = Column(String, default="pending")
    risk_level = Column(String)
    findings_count = Column(Integer, default=0)
    summary = Column(Text)
    recommendations = Column(Text)
    top_issues = Column(Text)
    ports = Column(Text)
    raw_data = Column(Text)
    scan_type = Column(String, default="full")
    profile = Column(String, default="STRAZNIK")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)

class User(Base):
    __tablename__ = "users"
    id            = Column(Integer, primary_key=True)
    username      = Column(String, unique=True, nullable=False, index=True)
    email         = Column(String, unique=True, nullable=True)
    password_hash = Column(String, nullable=False)
    role          = Column(String, default="viewer")   # admin / operator / viewer
    is_active     = Column(Boolean, default=True)
    created_by    = Column(String, nullable=True)
    created_at    = Column(DateTime, default=datetime.utcnow)
    last_login    = Column(DateTime, nullable=True)
    notes         = Column(Text, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user = Column(String, nullable=False)
    action = Column(String, nullable=False)
    target = Column(String)
    ip_address = Column(String)

class LicenseUsage(Base):
    __tablename__ = "license_usage"
    id         = Column(Integer, primary_key=True)
    month      = Column(String, unique=True, nullable=False, index=True)  # "2026-02"
    scans_count = Column(Integer, default=0)
    updated_at = Column(DateTime, default=datetime.utcnow)

class RemediationTask(Base):
    __tablename__ = "remediation_tasks"
    id              = Column(Integer, primary_key=True, index=True)
    scan_id         = Column(String, ForeignKey("scans.task_id", ondelete="CASCADE"), nullable=False, index=True)
    finding_name    = Column(String, nullable=False)
    finding_severity = Column(String, nullable=False)
    finding_module  = Column(String, nullable=True)
    owner           = Column(String, nullable=True)
    deadline        = Column(DateTime, nullable=True)
    status          = Column(String, default="open")  # open/in_progress/fixed/verified/wontfix
    notes           = Column(Text, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    verified_at     = Column(DateTime, nullable=True)
    retest_task_id  = Column(String, nullable=True)     # Celery task ID
    retest_status   = Column(String, nullable=True)     # pending/running/verified/reopened
    retest_at       = Column(DateTime, nullable=True)
    retest_result   = Column(JSON, nullable=True)

class Schedule(Base):
    __tablename__ = "schedules"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, nullable=False)
    interval_hours = Column(Integer, nullable=False)
    enabled = Column(Boolean, default=True)
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

class CveCache(Base):
    __tablename__ = "cve_cache"
    cve_id        = Column(String, primary_key=True)  # CVE-2024-12345
    cvss_score    = Column(Float)
    cvss_vector   = Column(String)
    description   = Column(Text)
    published     = Column(String)
    last_modified = Column(String)
    cwe_id        = Column(String)
    references    = Column(JSON)
    updated_at    = Column(DateTime, default=datetime.utcnow)

class KevCache(Base):
    __tablename__ = "kev_cache"
    cve_id             = Column(String, primary_key=True)
    vendor_project     = Column(String)
    product            = Column(String)
    vulnerability_name = Column(String)
    date_added         = Column(String)
    short_description  = Column(Text)
    required_action    = Column(Text)
    due_date           = Column(String)
    updated_at         = Column(DateTime, default=datetime.utcnow)

class EpssCache(Base):
    __tablename__ = "epss_cache"
    cve_id     = Column(String, primary_key=True)
    epss_score = Column(Float)    # 0.0 - 1.0
    percentile = Column(Float)
    updated_at = Column(DateTime, default=datetime.utcnow)

class IntelSyncLog(Base):
    __tablename__ = "intel_sync_log"
    id               = Column(Integer, primary_key=True)
    source           = Column(String)   # KEV/NVD/EPSS/ATT&CK/CAPEC-CWE-MAP/EUVD
    status           = Column(String)   # success/error
    records_updated  = Column(Integer)
    duration_seconds = Column(Float)
    error_message    = Column(Text, nullable=True)
    synced_at        = Column(DateTime, default=datetime.utcnow)

# ── ATT&CK Models ────────────────────────────────────────

class AttackTechnique(Base):
    __tablename__ = "attack_techniques"
    technique_id    = Column(String, primary_key=True)   # T1059.001
    name            = Column(String, nullable=False)
    description     = Column(Text)
    url             = Column(String)
    platforms       = Column(JSON)       # ["Windows", "Linux", ...]
    tactics         = Column(JSON)       # ["execution", "persistence"]
    data_sources    = Column(JSON)
    detection       = Column(Text)
    is_subtechnique = Column(Boolean, default=False)
    parent_id       = Column(String, ForeignKey("attack_techniques.technique_id", ondelete="SET NULL"), nullable=True)
    deprecated      = Column(Boolean, default=False)
    updated_at      = Column(DateTime, default=datetime.utcnow)

class AttackTactic(Base):
    __tablename__ = "attack_tactics"
    tactic_id   = Column(String, primary_key=True)  # TA0001
    short_name  = Column(String)                     # initial-access
    name        = Column(String, nullable=False)     # Initial Access
    description = Column(Text)
    url         = Column(String)
    updated_at  = Column(DateTime, default=datetime.utcnow)

class AttackMitigation(Base):
    __tablename__ = "attack_mitigations"
    mitigation_id = Column(String, primary_key=True)  # M1036
    name          = Column(String, nullable=False)
    description   = Column(Text)
    url           = Column(String)
    updated_at    = Column(DateTime, default=datetime.utcnow)

class AttackMitigationLink(Base):
    __tablename__ = "attack_mitigation_links"
    id            = Column(Integer, primary_key=True)
    technique_id  = Column(String, ForeignKey("attack_techniques.technique_id", ondelete="CASCADE"), index=True)
    mitigation_id = Column(String, ForeignKey("attack_mitigations.mitigation_id", ondelete="CASCADE"), index=True)
    description   = Column(Text)

class CweAttackMap(Base):
    __tablename__ = "cwe_attack_map"
    id           = Column(Integer, primary_key=True)
    cwe_id       = Column(String, index=True)   # CWE-89
    capec_id     = Column(String)                # CAPEC-66
    technique_id = Column(String, ForeignKey("attack_techniques.technique_id", ondelete="CASCADE"), index=True)
    updated_at   = Column(DateTime, default=datetime.utcnow)

class EuvdCache(Base):
    __tablename__ = "euvd_cache"
    euvd_id            = Column(String, primary_key=True)  # EUVD-2024-xxxxx
    description        = Column(Text)
    date_published     = Column(String)
    date_updated       = Column(String)
    base_score         = Column(Float)
    base_score_version = Column(String)
    base_score_vector  = Column(String)
    aliases            = Column(JSON)     # ["CVE-2024-3400", ...]
    epss               = Column(Float)
    vendor             = Column(String)
    product            = Column(String)
    references         = Column(JSON)
    updated_at         = Column(DateTime, default=datetime.utcnow)

class MispEvent(Base):
    __tablename__ = "misp_events"
    event_id       = Column(Integer, primary_key=True)
    uuid           = Column(String, unique=True, index=True)
    info           = Column(Text)
    threat_level_id = Column(Integer)
    analysis       = Column(Integer)
    date           = Column(String)
    org            = Column(String)
    tags           = Column(JSON)
    attribute_count = Column(Integer, default=0)
    updated_at     = Column(DateTime, default=datetime.utcnow)

class MispAttribute(Base):
    __tablename__ = "misp_attributes"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    attribute_id   = Column(Integer, unique=True, index=True)
    event_id       = Column(Integer, ForeignKey("misp_events.event_id", ondelete="CASCADE"), index=True)
    type           = Column(String)
    value          = Column(String, index=True)
    category       = Column(String)
    to_ids         = Column(Boolean, default=False)
    tags           = Column(JSON)
    updated_at     = Column(DateTime, default=datetime.utcnow)

class ShodanCache(Base):
    __tablename__ = "shodan_cache"
    ip             = Column(String, primary_key=True)
    ports          = Column(JSON)      # [80, 443, ...]
    cpes           = Column(JSON)      # ["cpe:/a:apache:httpd:2.4.41", ...]
    hostnames      = Column(JSON)      # ["example.com", ...]
    tags           = Column(JSON)      # ["cloud", "vpn", ...]
    vulns          = Column(JSON)      # ["CVE-2021-44228", ...]
    fetched_at     = Column(DateTime, default=datetime.utcnow)

class UrlhausCache(Base):
    __tablename__ = "urlhaus_cache"
    host           = Column(String, primary_key=True)
    urls_count     = Column(Integer, default=0)
    blacklisted    = Column(Boolean, default=False)
    tags           = Column(JSON)
    urls           = Column(JSON)      # top entries
    fetched_at     = Column(DateTime, default=datetime.utcnow)

class GreynoiseCache(Base):
    __tablename__ = "greynoise_cache"
    ip             = Column(String, primary_key=True)
    noise          = Column(Boolean, default=False)
    riot           = Column(Boolean, default=False)
    classification = Column(String)    # benign / malicious / unknown
    name           = Column(String)
    link           = Column(String)
    fetched_at     = Column(DateTime, default=datetime.utcnow)

class ExploitdbCache(Base):
    __tablename__ = "exploitdb_cache"
    exploit_id     = Column(Integer, primary_key=True)
    description    = Column(Text)
    cve            = Column(String, index=True)
    type           = Column(String)        # local / remote / webapps / dos / shellcode
    platform       = Column(String)
    port           = Column(Integer)
    date           = Column(String)
    author         = Column(String)
    url            = Column(String)
    updated_at     = Column(DateTime, default=datetime.utcnow)

class MalwarebazaarCache(Base):
    __tablename__ = "malwarebazaar_cache"
    sha256_hash    = Column(String, primary_key=True)
    md5_hash       = Column(String, index=True)
    sha1_hash      = Column(String, index=True)
    file_name      = Column(String)
    file_type      = Column(String)
    tags           = Column(JSON)       # ["Emotet", "trojan"]
    signature      = Column(String)     # "Emotet"
    first_seen     = Column(String)
    reporter       = Column(String)
    fetched_at     = Column(DateTime, default=datetime.utcnow)

class VerifyResult(Base):
    __tablename__ = "verify_results"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    query          = Column(String, index=True)
    query_type     = Column(String)            # url / email / company
    risk_score     = Column(Integer, default=0)
    verdict        = Column(String)            # BEZPIECZNE / PODEJRZANE / OSZUSTWO
    signals        = Column(JSON)
    red_flags      = Column(JSON)
    summary        = Column(Text)
    recommendation = Column(Text)
    narrative      = Column(Text)              # 4-6 sentence AI narrative
    trust_factors  = Column(JSON)              # list of trust factors
    signal_explanations = Column(JSON)         # per-signal explanations
    educational_tips = Column(JSON)            # [{icon, title, text}]
    problems       = Column(JSON)              # [{title, what_found, what_means, real_risk}]
    positives      = Column(JSON)              # [{title, what_found, what_means}]
    action         = Column(Text)              # what to do NOW
    immediate_actions = Column(JSON)           # ["action1", "action2"]
    if_paid_already = Column(JSON)             # ["step1", "step2"]
    report_to      = Column(JSON)              # [{institution, url, description}]
    created_at     = Column(DateTime, default=datetime.utcnow)
    created_by     = Column(String)

def init_db(retries=10, delay=3):
    from alembic.config import Config
    from alembic import command
    from sqlalchemy import inspect as sa_inspect
    for i in range(retries):
        try:
            alembic_cfg = Config("alembic.ini")
            alembic_cfg.set_main_option("sqlalchemy.url", str(engine.url))
            insp = sa_inspect(engine)
            tables = insp.get_table_names()
            if "scans" in tables and "alembic_version" not in tables:
                command.stamp(alembic_cfg, "head")
                print("Database stamped at head (existing schema)", flush=True)
            else:
                command.upgrade(alembic_cfg, "head")
                print("Database migrated successfully", flush=True)
            return
        except Exception as e:
            if i < retries - 1:
                print(f"DB not ready ({e}), retry {i+1}/{retries}...", flush=True)
                time.sleep(delay)
            else:
                raise

def save_scan(task_id: str, target: str, result: dict, scan_type: str = "full", profile: str = "STRAZNIK"):
    db = SessionLocal()
    try:
        analysis = result.get("analysis", {})
        ai_analysis = result.get("ai_analysis", {})
        scan = db.query(Scan).filter(Scan.task_id == task_id).first()
        if not scan:
            scan = Scan(task_id=task_id, target=target)
            db.add(scan)
        scan.status = "completed"
        scan.scan_type = scan_type
        scan.profile = profile
        scan.risk_level = analysis.get("risk_level") or ai_analysis.get("risk_level")
        fc = result.get("findings_count", 0) or ai_analysis.get("findings_count", 0)
        scan.findings_count = fc
        scan.summary = analysis.get("summary") or ai_analysis.get("executive_summary")
        scan.recommendations = analysis.get("recommendations")
        scan.top_issues = json.dumps(analysis.get("top_issues", []), ensure_ascii=False)
        scan.raw_data = json.dumps(result, ensure_ascii=False)
        scan.completed_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()

def get_scan_history(limit: int = 20):
    db = SessionLocal()
    try:
        scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()
        return [
            {
                "id": s.id,
                "task_id": s.task_id,
                "target": s.target,
                "status": s.status,
                "risk_level": s.risk_level,
                "findings_count": s.findings_count,
                "summary": s.summary,
                "profile": s.profile or "STRAZNIK",
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            }
            for s in scans
        ]
    finally:
        db.close()

def get_scan_by_task_id(task_id: str):
    db = SessionLocal()
    try:
        s = db.query(Scan).filter(Scan.task_id == task_id).first()
        if not s:
            return None
        base = {
            "id": s.id,
            "task_id": s.task_id,
            "target": s.target,
            "status": s.status,
            "risk_level": s.risk_level,
            "findings_count": s.findings_count,
            "summary": s.summary,
            "recommendations": s.recommendations,
            "profile": s.profile or "STRAZNIK",
            "top_issues": json.loads(s.top_issues) if s.top_issues else [],
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        if s.raw_data:
            raw = json.loads(s.raw_data)
            for key in ["ports", "nuclei", "gobuster", "whatweb", "testssl", "sqlmap", "nikto", "harvester", "masscan", "exploit_chains", "hacker_narrative", "fp_filter", "ipinfo", "enum4linux", "mitre", "abuseipdb", "otx", "exploitdb", "nvd", "whois", "dnsrecon", "amass", "cwe", "owasp", "wpscan", "zap", "wapiti", "joomscan", "cmsmap", "droopescan", "retirejs", "subfinder", "httpx", "naabu", "katana", "dnsx", "netdiscover", "arpscan", "fping", "traceroute", "nbtscan", "snmpwalk", "netexec", "bloodhound", "responder", "fierce", "smbmap", "onesixtyone", "ikescan", "sslyze", "searchsploit", "impacket", "ai_analysis", "exiftool", "certipy", "reflection"]:
                if key in raw:
                    base[key] = raw[key]
        return base
    finally:
        db.close()

def add_schedule(target: str, interval_hours: int):
    from datetime import timedelta
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        schedule = Schedule(
            target=target,
            interval_hours=interval_hours,
            next_run=now,
        )
        db.add(schedule)
        db.commit()
        db.refresh(schedule)
        return {"id": schedule.id, "target": schedule.target, "interval_hours": schedule.interval_hours, "next_run": schedule.next_run.isoformat()}
    finally:
        db.close()

def get_schedules():
    db = SessionLocal()
    try:
        schedules = db.query(Schedule).order_by(Schedule.created_at.desc()).all()
        return [
            {
                "id": s.id,
                "target": s.target,
                "interval_hours": s.interval_hours,
                "enabled": s.enabled,
                "last_run": s.last_run.isoformat() if s.last_run else None,
                "next_run": s.next_run.isoformat() if s.next_run else None,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in schedules
        ]
    finally:
        db.close()

def delete_schedule(schedule_id: int):
    db = SessionLocal()
    try:
        schedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
        if not schedule:
            return False
        db.delete(schedule)
        db.commit()
        return True
    finally:
        db.close()

def get_due_schedules():
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        schedules = db.query(Schedule).filter(
            Schedule.enabled == True,
            Schedule.next_run <= now
        ).all()
        return schedules
    finally:
        db.close()

def update_schedule_run(schedule_id: int):
    from datetime import timedelta
    db = SessionLocal()
    try:
        schedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
        if schedule:
            now = datetime.utcnow()
            schedule.last_run = now
            schedule.next_run = now + timedelta(hours=schedule.interval_hours)
            db.commit()
    finally:
        db.close()

def save_audit_log(user: str, action: str, target: str = None, ip_address: str = None):
    db = SessionLocal()
    try:
        log = AuditLog(user=user, action=action, target=target, ip_address=ip_address)
        db.add(log)
        db.commit()
    finally:
        db.close()

def get_audit_logs(limit: int = 100):
    db = SessionLocal()
    try:
        logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                "user": l.user,
                "action": l.action,
                "target": l.target,
                "ip_address": l.ip_address,
            }
            for l in logs
        ]
    finally:
        db.close()

def get_osint_history(limit: int = 20):
    db = SessionLocal()
    try:
        scans = db.query(Scan).filter(Scan.scan_type == "osint").order_by(Scan.created_at.desc()).limit(limit).all()
        results = []
        for s in scans:
            summary = {}
            search_type = "domain"
            if s.raw_data:
                try:
                    raw = json.loads(s.raw_data)
                    summary = raw.get("summary", {})
                    search_type = raw.get("search_type", "domain")
                except Exception:
                    pass
            results.append({
                "task_id": s.task_id,
                "target": s.target,
                "status": s.status,
                "search_type": search_type,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "summary": summary,
            })
        return results
    finally:
        db.close()

def get_osint_by_task_id(task_id: str):
    db = SessionLocal()
    try:
        s = db.query(Scan).filter(Scan.task_id == task_id, Scan.scan_type == "osint").first()
        if not s:
            return None
        if s.raw_data:
            try:
                data = json.loads(s.raw_data)
                data["task_id"] = s.task_id
                data["created_at"] = s.created_at.isoformat() if s.created_at else None
                data["completed_at"] = s.completed_at.isoformat() if s.completed_at else None
                return data
            except Exception:
                pass
        return {"task_id": s.task_id, "target": s.target, "status": s.status}
    finally:
        db.close()

# ── User CRUD ────────────────────────────────────────────

def _user_to_dict(u: "User") -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "created_by": u.created_by,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "notes": u.notes,
    }

def get_user_by_username(username: str) -> dict | None:
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.username == username).first()
        return _user_to_dict(u) if u else None
    finally:
        db.close()

def get_user_by_username_raw(username: str):
    """Return raw User row (with password_hash) for auth."""
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.username == username).first()
        if not u:
            return None
        d = _user_to_dict(u)
        d["password_hash"] = u.password_hash
        return d
    finally:
        db.close()

def get_user_by_id(user_id: int) -> dict | None:
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == user_id).first()
        return _user_to_dict(u) if u else None
    finally:
        db.close()

def create_user(username: str, password_hash: str, role: str = "viewer",
                email: str = None, created_by: str = None, notes: str = None) -> dict:
    db = SessionLocal()
    try:
        u = User(
            username=username, password_hash=password_hash, role=role,
            email=email, created_by=created_by, notes=notes,
        )
        db.add(u)
        db.commit()
        db.refresh(u)
        return _user_to_dict(u)
    finally:
        db.close()

def update_user(user_id: int, **kwargs) -> dict | None:
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == user_id).first()
        if not u:
            return None
        for k, v in kwargs.items():
            if hasattr(u, k) and v is not None:
                setattr(u, k, v)
        db.commit()
        db.refresh(u)
        return _user_to_dict(u)
    finally:
        db.close()

def delete_user(user_id: int) -> bool:
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == user_id).first()
        if not u:
            return False
        db.delete(u)
        db.commit()
        return True
    finally:
        db.close()

def list_users() -> list[dict]:
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.created_at.desc()).all()
        return [_user_to_dict(u) for u in users]
    finally:
        db.close()

def count_admins() -> int:
    db = SessionLocal()
    try:
        return db.query(User).filter(User.role == "admin", User.is_active == True).count()
    finally:
        db.close()

def count_active_users() -> int:
    db = SessionLocal()
    try:
        return db.query(User).filter(User.is_active == True).count()
    finally:
        db.close()

# ── License usage ────────────────────────────────────────

def get_scans_this_month() -> int:
    db = SessionLocal()
    try:
        month_key = datetime.utcnow().strftime("%Y-%m")
        row = db.query(LicenseUsage).filter(LicenseUsage.month == month_key).first()
        return row.scans_count if row else 0
    finally:
        db.close()

def increment_scan_count() -> int:
    db = SessionLocal()
    try:
        month_key = datetime.utcnow().strftime("%Y-%m")
        row = db.query(LicenseUsage).filter(LicenseUsage.month == month_key).first()
        if row:
            row.scans_count += 1
            row.updated_at = datetime.utcnow()
        else:
            row = LicenseUsage(month=month_key, scans_count=1)
            db.add(row)
        db.commit()
        return row.scans_count
    finally:
        db.close()

# ── Remediation CRUD ────────────────────────────────────

def _remediation_to_dict(t: "RemediationTask") -> dict:
    return {
        "id": t.id,
        "scan_id": t.scan_id,
        "finding_name": t.finding_name,
        "finding_severity": t.finding_severity,
        "finding_module": t.finding_module,
        "owner": t.owner,
        "deadline": t.deadline.isoformat() if t.deadline else None,
        "status": t.status,
        "notes": t.notes,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        "verified_at": t.verified_at.isoformat() if t.verified_at else None,
        "retest_task_id": t.retest_task_id,
        "retest_status": t.retest_status,
        "retest_at": t.retest_at.isoformat() if t.retest_at else None,
        "retest_result": t.retest_result,
    }

def get_remediation_tasks(scan_id: str) -> list[dict]:
    db = SessionLocal()
    try:
        tasks = db.query(RemediationTask).filter(
            RemediationTask.scan_id == scan_id
        ).order_by(RemediationTask.created_at.desc()).all()
        return [_remediation_to_dict(t) for t in tasks]
    finally:
        db.close()

def create_remediation_task(scan_id: str, finding_name: str, finding_severity: str,
                            finding_module: str = None, owner: str = None,
                            deadline: datetime = None, notes: str = None) -> dict:
    db = SessionLocal()
    try:
        t = RemediationTask(
            scan_id=scan_id, finding_name=finding_name,
            finding_severity=finding_severity, finding_module=finding_module,
            owner=owner, deadline=deadline, notes=notes,
        )
        db.add(t)
        db.commit()
        db.refresh(t)
        return _remediation_to_dict(t)
    finally:
        db.close()

def get_remediation_task_by_id(task_id: int) -> dict | None:
    db = SessionLocal()
    try:
        t = db.query(RemediationTask).filter(RemediationTask.id == task_id).first()
        return _remediation_to_dict(t) if t else None
    finally:
        db.close()

def update_remediation_task(task_id: int, **kwargs) -> dict | None:
    db = SessionLocal()
    try:
        t = db.query(RemediationTask).filter(RemediationTask.id == task_id).first()
        if not t:
            return None
        for k, v in kwargs.items():
            if hasattr(t, k) and v is not None:
                setattr(t, k, v)
        # Auto-set verified_at when status changes to verified
        if kwargs.get("status") == "verified" and not t.verified_at:
            t.verified_at = datetime.utcnow()
        elif kwargs.get("status") and kwargs["status"] != "verified":
            t.verified_at = None
        t.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(t)
        return _remediation_to_dict(t)
    finally:
        db.close()

def delete_remediation_task(task_id: int) -> bool:
    db = SessionLocal()
    try:
        t = db.query(RemediationTask).filter(RemediationTask.id == task_id).first()
        if not t:
            return False
        db.delete(t)
        db.commit()
        return True
    finally:
        db.close()

def bulk_create_remediation_tasks(scan_id: str, findings: list[dict]) -> list[dict]:
    """Create remediation tasks from findings, deduplicating by (name, severity, module)."""
    db = SessionLocal()
    try:
        existing = db.query(RemediationTask).filter(
            RemediationTask.scan_id == scan_id
        ).all()
        existing_keys = {
            (t.finding_name, t.finding_severity, t.finding_module) for t in existing
        }
        created = []
        for f in findings:
            name = f.get("name") or f.get("finding_name", "")
            sev = f.get("severity") or f.get("finding_severity", "info")
            mod = f.get("module") or f.get("finding_module") or f.get("_module")
            if not name:
                continue
            key = (name, sev, mod)
            if key in existing_keys:
                continue
            existing_keys.add(key)
            t = RemediationTask(
                scan_id=scan_id, finding_name=name,
                finding_severity=sev, finding_module=mod,
            )
            db.add(t)
            created.append(t)
        db.commit()
        for t in created:
            db.refresh(t)
        return [_remediation_to_dict(t) for t in created]
    finally:
        db.close()

def get_remediation_stats(scan_id: str) -> dict:
    db = SessionLocal()
    try:
        tasks = db.query(RemediationTask).filter(
            RemediationTask.scan_id == scan_id
        ).all()
        stats = {"total": 0, "open": 0, "in_progress": 0, "fixed": 0, "verified": 0, "wontfix": 0}
        for t in tasks:
            stats["total"] += 1
            s = t.status or "open"
            if s in stats:
                stats[s] += 1
        return stats
    finally:
        db.close()

# ── Intel Sync CRUD ─────────────────────────────────────

def upsert_kev_entries(entries: list[dict]) -> int:
    db = SessionLocal()
    try:
        count = 0
        for e in entries:
            cve_id = e.get("cveID")
            if not cve_id:
                continue
            row = db.query(KevCache).filter(KevCache.cve_id == cve_id).first()
            if row:
                row.vendor_project = e.get("vendorProject")
                row.product = e.get("product")
                row.vulnerability_name = e.get("vulnerabilityName")
                row.date_added = e.get("dateAdded")
                row.short_description = e.get("shortDescription")
                row.required_action = e.get("requiredAction")
                row.due_date = e.get("dueDate")
                row.updated_at = datetime.utcnow()
            else:
                row = KevCache(
                    cve_id=cve_id, vendor_project=e.get("vendorProject"),
                    product=e.get("product"), vulnerability_name=e.get("vulnerabilityName"),
                    date_added=e.get("dateAdded"), short_description=e.get("shortDescription"),
                    required_action=e.get("requiredAction"), due_date=e.get("dueDate"),
                )
                db.add(row)
            count += 1
        db.commit()
        return count
    finally:
        db.close()

def upsert_epss_entries(entries: list[dict]) -> int:
    db = SessionLocal()
    try:
        count = 0
        for e in entries:
            cve_id = e.get("cve")
            if not cve_id:
                continue
            score = float(e.get("epss", 0))
            pctl = float(e.get("percentile", 0))
            row = db.query(EpssCache).filter(EpssCache.cve_id == cve_id).first()
            if row:
                row.epss_score = score
                row.percentile = pctl
                row.updated_at = datetime.utcnow()
            else:
                row = EpssCache(cve_id=cve_id, epss_score=score, percentile=pctl)
                db.add(row)
            count += 1
        db.commit()
        return count
    finally:
        db.close()

def upsert_cve_entry(cve_id: str, data: dict) -> bool:
    db = SessionLocal()
    try:
        row = db.query(CveCache).filter(CveCache.cve_id == cve_id).first()
        if row:
            for k, v in data.items():
                if hasattr(row, k):
                    setattr(row, k, v)
            row.updated_at = datetime.utcnow()
        else:
            row = CveCache(cve_id=cve_id, **data)
            db.add(row)
        db.commit()
        return True
    finally:
        db.close()

def get_intel_enrichment(cve_id: str) -> dict:
    db = SessionLocal()
    try:
        result = {"cve_id": cve_id}
        cve = db.query(CveCache).filter(CveCache.cve_id == cve_id).first()
        if cve:
            result["cvss_score"] = cve.cvss_score
            result["cvss_vector"] = cve.cvss_vector
            result["description"] = cve.description
            result["cwe_id"] = cve.cwe_id
            result["references"] = cve.references
            result["published"] = cve.published
        kev = db.query(KevCache).filter(KevCache.cve_id == cve_id).first()
        result["in_kev"] = kev is not None
        if kev:
            result["kev_vendor"] = kev.vendor_project
            result["kev_product"] = kev.product
            result["kev_action"] = kev.required_action
            result["kev_due_date"] = kev.due_date
        epss = db.query(EpssCache).filter(EpssCache.cve_id == cve_id).first()
        if epss:
            result["epss_score"] = epss.epss_score
            result["epss_percentile"] = epss.percentile
        return result
    finally:
        db.close()

def save_intel_sync_log(source: str, status: str, records_updated: int,
                        duration_seconds: float, error_message: str = None):
    db = SessionLocal()
    try:
        log = IntelSyncLog(
            source=source, status=status, records_updated=records_updated,
            duration_seconds=duration_seconds, error_message=error_message,
        )
        db.add(log)
        db.commit()
    finally:
        db.close()

def get_intel_sync_logs(limit: int = 10) -> list[dict]:
    db = SessionLocal()
    try:
        logs = db.query(IntelSyncLog).order_by(IntelSyncLog.synced_at.desc()).limit(limit).all()
        return [
            {
                "id": l.id, "source": l.source, "status": l.status,
                "records_updated": l.records_updated,
                "duration_seconds": round(l.duration_seconds, 2) if l.duration_seconds else None,
                "error_message": l.error_message,
                "synced_at": l.synced_at.isoformat() if l.synced_at else None,
            }
            for l in logs
        ]
    finally:
        db.close()

def get_intel_cache_counts() -> dict:
    db = SessionLocal()
    try:
        return {
            "kev": db.query(KevCache).count(),
            "cve": db.query(CveCache).count(),
            "epss": db.query(EpssCache).count(),
            "attack_techniques": db.query(AttackTechnique).count(),
            "attack_tactics": db.query(AttackTactic).count(),
            "attack_mitigations": db.query(AttackMitigation).count(),
            "euvd": db.query(EuvdCache).count(),
            "misp_events": db.query(MispEvent).count(),
            "misp_attributes": db.query(MispAttribute).count(),
            "shodan": db.query(ShodanCache).count(),
            "urlhaus": db.query(UrlhausCache).count(),
            "greynoise": db.query(GreynoiseCache).count(),
            "exploitdb": db.query(ExploitdbCache).count(),
            "malwarebazaar": db.query(MalwarebazaarCache).count(),
        }
    finally:
        db.close()

def save_verify_result(data: dict, created_by: str = "system") -> int:
    db = SessionLocal()
    try:
        row = VerifyResult(
            query=data.get("query", ""),
            query_type=data.get("type", ""),
            risk_score=data.get("risk_score", 0),
            verdict=data.get("verdict", ""),
            signals=data.get("signals"),
            red_flags=data.get("red_flags"),
            summary=data.get("summary", ""),
            recommendation=data.get("recommendation", ""),
            narrative=data.get("narrative", ""),
            trust_factors=data.get("trust_factors"),
            signal_explanations=data.get("signal_explanations"),
            educational_tips=data.get("educational_tips"),
            problems=data.get("problems"),
            positives=data.get("positives"),
            action=data.get("action", ""),
            immediate_actions=data.get("immediate_actions"),
            if_paid_already=data.get("if_paid_already"),
            report_to=data.get("report_to"),
            created_by=created_by,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    finally:
        db.close()


def get_verify_result_by_id(result_id: int) -> dict | None:
    db = SessionLocal()
    try:
        r = db.query(VerifyResult).filter(VerifyResult.id == result_id).first()
        if not r:
            return None
        return {
            "id": r.id,
            "query": r.query,
            "type": r.query_type,
            "query_type": r.query_type,
            "risk_score": r.risk_score,
            "verdict": r.verdict,
            "signals": r.signals,
            "red_flags": r.red_flags,
            "summary": r.summary,
            "recommendation": r.recommendation,
            "narrative": r.narrative,
            "trust_factors": r.trust_factors,
            "signal_explanations": r.signal_explanations,
            "educational_tips": r.educational_tips,
            "problems": r.problems,
            "positives": r.positives,
            "action": r.action,
            "immediate_actions": r.immediate_actions,
            "if_paid_already": r.if_paid_already,
            "report_to": r.report_to,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "created_by": r.created_by,
        }
    finally:
        db.close()

def get_verify_history(limit: int = 50) -> list[dict]:
    db = SessionLocal()
    try:
        rows = db.query(VerifyResult).order_by(VerifyResult.created_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "query": r.query,
                "query_type": r.query_type,
                "risk_score": r.risk_score,
                "verdict": r.verdict,
                "red_flags": r.red_flags,
                "summary": r.summary,
                "recommendation": r.recommendation,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "created_by": r.created_by,
            }
            for r in rows
        ]
    finally:
        db.close()

def get_all_cve_ids_from_findings() -> list[str]:
    """Extract unique CVE IDs from all scan raw_data."""
    import re
    db = SessionLocal()
    try:
        scans = db.query(Scan.raw_data).filter(Scan.raw_data.isnot(None)).all()
        cve_ids = set()
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
        for (raw_data,) in scans:
            if raw_data:
                cve_ids.update(cve_pattern.findall(raw_data))
        return sorted(cve_ids)
    finally:
        db.close()

# ── Timeline / Security Scores ──────────────────────────

def get_scans_by_target(target: str) -> list[dict]:
    """Return all completed scans for a target, chronological order."""
    db = SessionLocal()
    try:
        scans = db.query(Scan).filter(
            Scan.target == target,
            Scan.status == "completed",
        ).order_by(Scan.created_at.asc()).all()
        results = []
        for s in scans:
            raw = {}
            if s.raw_data:
                try:
                    raw = json.loads(s.raw_data)
                except Exception:
                    pass
            results.append({
                "task_id": s.task_id,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "risk_level": s.risk_level,
                "findings_count": s.findings_count or 0,
                "profile": s.profile or "STRAZNIK",
                "raw": raw,
            })
        return results
    finally:
        db.close()

# ── ATT&CK CRUD ──────────────────────────────────────────

def upsert_attack_techniques(entries: list[dict]) -> int:
    db = SessionLocal()
    try:
        count = 0
        for e in entries:
            tid = e.get("technique_id")
            if not tid:
                continue
            row = db.query(AttackTechnique).filter(AttackTechnique.technique_id == tid).first()
            if row:
                for k, v in e.items():
                    if hasattr(row, k) and k != "technique_id":
                        setattr(row, k, v)
                row.updated_at = datetime.utcnow()
            else:
                row = AttackTechnique(**e)
                db.add(row)
            count += 1
        db.commit()
        return count
    finally:
        db.close()

def upsert_attack_tactics(entries: list[dict]) -> int:
    db = SessionLocal()
    try:
        count = 0
        for e in entries:
            tid = e.get("tactic_id")
            if not tid:
                continue
            row = db.query(AttackTactic).filter(AttackTactic.tactic_id == tid).first()
            if row:
                for k, v in e.items():
                    if hasattr(row, k) and k != "tactic_id":
                        setattr(row, k, v)
                row.updated_at = datetime.utcnow()
            else:
                row = AttackTactic(**e)
                db.add(row)
            count += 1
        db.commit()
        return count
    finally:
        db.close()

def upsert_attack_mitigations(entries: list[dict]) -> int:
    db = SessionLocal()
    try:
        count = 0
        for e in entries:
            mid = e.get("mitigation_id")
            if not mid:
                continue
            row = db.query(AttackMitigation).filter(AttackMitigation.mitigation_id == mid).first()
            if row:
                for k, v in e.items():
                    if hasattr(row, k) and k != "mitigation_id":
                        setattr(row, k, v)
                row.updated_at = datetime.utcnow()
            else:
                row = AttackMitigation(**e)
                db.add(row)
            count += 1
        db.commit()
        return count
    finally:
        db.close()

def upsert_attack_mitigation_links(entries: list[dict]) -> int:
    """Upsert mitigation→technique links. Deletes old links and inserts fresh."""
    db = SessionLocal()
    try:
        db.query(AttackMitigationLink).delete()
        for e in entries:
            row = AttackMitigationLink(
                technique_id=e.get("technique_id"),
                mitigation_id=e.get("mitigation_id"),
                description=e.get("description"),
            )
            db.add(row)
        db.commit()
        return len(entries)
    finally:
        db.close()

def upsert_cwe_attack_map(entries: list[dict]) -> int:
    """Upsert CWE→technique mappings. Replaces all. Skips entries with unknown technique_id."""
    db = SessionLocal()
    try:
        db.query(CweAttackMap).delete()
        existing_techs = {t.technique_id for t in db.query(AttackTechnique.technique_id).all()}
        count = 0
        for e in entries:
            if e.get("technique_id") in existing_techs:
                row = CweAttackMap(
                    cwe_id=e.get("cwe_id"),
                    capec_id=e.get("capec_id"),
                    technique_id=e.get("technique_id"),
                )
                db.add(row)
                count += 1
        db.commit()
        return count
    finally:
        db.close()

def upsert_euvd_entries(entries: list[dict]) -> int:
    db = SessionLocal()
    try:
        count = 0
        for e in entries:
            eid = e.get("euvd_id")
            if not eid:
                continue
            row = db.query(EuvdCache).filter(EuvdCache.euvd_id == eid).first()
            if row:
                for k, v in e.items():
                    if hasattr(row, k) and k != "euvd_id":
                        setattr(row, k, v)
                row.updated_at = datetime.utcnow()
            else:
                row = EuvdCache(**e)
                db.add(row)
            count += 1
        db.commit()
        return count
    finally:
        db.close()

def get_attack_technique(technique_id: str) -> dict | None:
    db = SessionLocal()
    try:
        t = db.query(AttackTechnique).filter(AttackTechnique.technique_id == technique_id).first()
        if not t:
            return None
        return {
            "technique_id": t.technique_id, "name": t.name,
            "description": t.description, "url": t.url,
            "platforms": t.platforms, "tactics": t.tactics,
            "data_sources": t.data_sources, "detection": t.detection,
            "is_subtechnique": t.is_subtechnique, "parent_id": t.parent_id,
            "deprecated": t.deprecated,
        }
    finally:
        db.close()

def search_attack_techniques(query: str = "", tactic: str = "", limit: int = 50) -> list[dict]:
    db = SessionLocal()
    try:
        q = db.query(AttackTechnique).filter(AttackTechnique.deprecated == False)
        if query:
            pattern = f"%{query}%"
            q = q.filter(
                (AttackTechnique.technique_id.ilike(pattern)) |
                (AttackTechnique.name.ilike(pattern))
            )
        if tactic:
            # tactics is JSON array, use text-based filter
            q = q.filter(AttackTechnique.tactics.cast(String).ilike(f"%{tactic}%"))
        rows = q.order_by(AttackTechnique.technique_id).limit(limit).all()
        return [
            {
                "technique_id": t.technique_id, "name": t.name,
                "url": t.url, "tactics": t.tactics,
                "is_subtechnique": t.is_subtechnique,
            }
            for t in rows
        ]
    finally:
        db.close()

def get_attack_tactics() -> list[dict]:
    db = SessionLocal()
    try:
        rows = db.query(AttackTactic).order_by(AttackTactic.tactic_id).all()
        return [
            {
                "tactic_id": t.tactic_id, "short_name": t.short_name,
                "name": t.name, "description": t.description, "url": t.url,
            }
            for t in rows
        ]
    finally:
        db.close()

def get_mitigations_for_technique(technique_id: str) -> list[dict]:
    db = SessionLocal()
    try:
        links = db.query(AttackMitigationLink).filter(
            AttackMitigationLink.technique_id == technique_id
        ).all()
        results = []
        for link in links:
            mit = db.query(AttackMitigation).filter(
                AttackMitigation.mitigation_id == link.mitigation_id
            ).first()
            if mit:
                results.append({
                    "mitigation_id": mit.mitigation_id, "name": mit.name,
                    "description": mit.description, "url": mit.url,
                    "link_description": link.description,
                })
        return results
    finally:
        db.close()

def get_techniques_for_cwe(cwe_id: str) -> list[dict]:
    """Get ATT&CK techniques mapped to a CWE via CAPEC."""
    db = SessionLocal()
    try:
        maps = db.query(CweAttackMap).filter(CweAttackMap.cwe_id == cwe_id).all()
        results = []
        seen = set()
        for m in maps:
            if m.technique_id in seen:
                continue
            seen.add(m.technique_id)
            t = db.query(AttackTechnique).filter(
                AttackTechnique.technique_id == m.technique_id
            ).first()
            if t:
                results.append({
                    "technique_id": t.technique_id, "name": t.name,
                    "url": t.url, "tactics": t.tactics,
                    "capec_id": m.capec_id,
                })
        return results
    finally:
        db.close()

def get_euvd_by_cve(cve_id: str) -> dict | None:
    """Lookup EUVD entry by CVE alias."""
    db = SessionLocal()
    try:
        # aliases is JSON array, search with text match
        rows = db.query(EuvdCache).filter(
            EuvdCache.aliases.cast(String).ilike(f"%{cve_id}%")
        ).all()
        for row in rows:
            aliases = row.aliases or []
            if cve_id in aliases:
                return {
                    "euvd_id": row.euvd_id, "description": row.description,
                    "date_published": row.date_published,
                    "base_score": row.base_score,
                    "base_score_vector": row.base_score_vector,
                    "aliases": row.aliases, "vendor": row.vendor,
                    "product": row.product, "epss": row.epss,
                    "url": f"https://euvd.enisa.europa.eu/detail/{row.euvd_id}",
                }
        return None
    finally:
        db.close()

def upsert_misp_events(events: list[dict]) -> int:
    db = SessionLocal()
    try:
        count = 0
        for e in events:
            eid = e.get("event_id")
            if not eid:
                continue
            row = db.query(MispEvent).filter(MispEvent.event_id == eid).first()
            if row:
                for k, v in e.items():
                    if hasattr(row, k) and k != "event_id":
                        setattr(row, k, v)
                row.updated_at = datetime.utcnow()
            else:
                row = MispEvent(**e)
                db.add(row)
            count += 1
        db.commit()
        return count
    finally:
        db.close()

def upsert_misp_attributes(attributes: list[dict]) -> int:
    db = SessionLocal()
    try:
        count = 0
        for a in attributes:
            aid = a.get("attribute_id")
            if not aid:
                continue
            row = db.query(MispAttribute).filter(MispAttribute.attribute_id == aid).first()
            if row:
                for k, v in a.items():
                    if hasattr(row, k) and k != "attribute_id" and k != "id":
                        setattr(row, k, v)
                row.updated_at = datetime.utcnow()
            else:
                row = MispAttribute(**{k: v for k, v in a.items() if k != "id"})
                db.add(row)
            count += 1
        db.commit()
        return count
    finally:
        db.close()

def get_misp_by_cve(cve_id: str) -> dict | None:
    """Find MISP attributes matching a CVE ID."""
    db = SessionLocal()
    try:
        attrs = db.query(MispAttribute).filter(
            MispAttribute.type == "vulnerability",
            MispAttribute.value.ilike(f"%{cve_id}%")
        ).all()
        if not attrs:
            return None
        event_ids = list({a.event_id for a in attrs})
        events = db.query(MispEvent).filter(MispEvent.event_id.in_(event_ids)).all()
        return {
            "cve_id": cve_id,
            "event_count": len(events),
            "events": [
                {"event_id": ev.event_id, "info": ev.info, "threat_level_id": ev.threat_level_id,
                 "org": ev.org, "date": ev.date, "tags": ev.tags}
                for ev in events[:5]
            ],
        }
    finally:
        db.close()

def get_misp_by_indicator(value: str) -> list[dict]:
    """Search MISP attributes by any value."""
    db = SessionLocal()
    try:
        attrs = db.query(MispAttribute).filter(
            MispAttribute.value.ilike(f"%{value}%")
        ).limit(50).all()
        return [
            {"attribute_id": a.attribute_id, "event_id": a.event_id,
             "type": a.type, "value": a.value, "category": a.category,
             "to_ids": a.to_ids, "tags": a.tags}
            for a in attrs
        ]
    finally:
        db.close()

def search_misp_events(query: str, limit: int = 20) -> list[dict]:
    """Search MISP events by info field."""
    db = SessionLocal()
    try:
        events = db.query(MispEvent).filter(
            MispEvent.info.ilike(f"%{query}%")
        ).order_by(MispEvent.updated_at.desc()).limit(limit).all()
        return [
            {"event_id": ev.event_id, "uuid": ev.uuid, "info": ev.info,
             "threat_level_id": ev.threat_level_id, "analysis": ev.analysis,
             "date": ev.date, "org": ev.org, "tags": ev.tags,
             "attribute_count": ev.attribute_count}
            for ev in events
        ]
    finally:
        db.close()

def upsert_shodan_cache(ip: str, data: dict) -> None:
    db = SessionLocal()
    try:
        row = db.query(ShodanCache).filter(ShodanCache.ip == ip).first()
        if row:
            row.ports = data.get("ports")
            row.cpes = data.get("cpes")
            row.hostnames = data.get("hostnames")
            row.tags = data.get("tags")
            row.vulns = data.get("vulns")
            row.fetched_at = datetime.utcnow()
        else:
            row = ShodanCache(ip=ip, ports=data.get("ports"), cpes=data.get("cpes"),
                              hostnames=data.get("hostnames"), tags=data.get("tags"),
                              vulns=data.get("vulns"))
            db.add(row)
        db.commit()
    finally:
        db.close()

def get_shodan_cache(ip: str) -> dict | None:
    db = SessionLocal()
    try:
        row = db.query(ShodanCache).filter(ShodanCache.ip == ip).first()
        if not row:
            return None
        return {"ip": row.ip, "ports": row.ports, "cpes": row.cpes,
                "hostnames": row.hostnames, "tags": row.tags, "vulns": row.vulns,
                "fetched_at": str(row.fetched_at)}
    finally:
        db.close()

def upsert_urlhaus_cache(host: str, data: dict) -> None:
    db = SessionLocal()
    try:
        row = db.query(UrlhausCache).filter(UrlhausCache.host == host).first()
        if row:
            row.urls_count = data.get("urls_count", 0)
            row.blacklisted = data.get("blacklisted", False)
            row.tags = data.get("tags")
            row.urls = data.get("urls")
            row.fetched_at = datetime.utcnow()
        else:
            row = UrlhausCache(host=host, urls_count=data.get("urls_count", 0),
                               blacklisted=data.get("blacklisted", False),
                               tags=data.get("tags"), urls=data.get("urls"))
            db.add(row)
        db.commit()
    finally:
        db.close()

def get_urlhaus_cache(host: str) -> dict | None:
    db = SessionLocal()
    try:
        row = db.query(UrlhausCache).filter(UrlhausCache.host == host).first()
        if not row:
            return None
        return {"host": row.host, "urls_count": row.urls_count,
                "blacklisted": row.blacklisted, "tags": row.tags,
                "urls": row.urls, "fetched_at": str(row.fetched_at)}
    finally:
        db.close()

def upsert_greynoise_cache(ip: str, data: dict) -> None:
    db = SessionLocal()
    try:
        row = db.query(GreynoiseCache).filter(GreynoiseCache.ip == ip).first()
        if row:
            row.noise = data.get("noise", False)
            row.riot = data.get("riot", False)
            row.classification = data.get("classification")
            row.name = data.get("name")
            row.link = data.get("link")
            row.fetched_at = datetime.utcnow()
        else:
            row = GreynoiseCache(ip=ip, noise=data.get("noise", False),
                                 riot=data.get("riot", False),
                                 classification=data.get("classification"),
                                 name=data.get("name"), link=data.get("link"))
            db.add(row)
        db.commit()
    finally:
        db.close()

def get_greynoise_cache(ip: str) -> dict | None:
    db = SessionLocal()
    try:
        row = db.query(GreynoiseCache).filter(GreynoiseCache.ip == ip).first()
        if not row:
            return None
        return {"ip": row.ip, "noise": row.noise, "riot": row.riot,
                "classification": row.classification, "name": row.name,
                "link": row.link, "fetched_at": str(row.fetched_at)}
    finally:
        db.close()

def upsert_exploitdb_entries(entries: list[dict]) -> int:
    db = SessionLocal()
    try:
        count = 0
        for e in entries:
            eid = e.get("exploit_id")
            if not eid:
                continue
            row = db.query(ExploitdbCache).filter(ExploitdbCache.exploit_id == eid).first()
            if row:
                for k, v in e.items():
                    if hasattr(row, k) and k != "exploit_id":
                        setattr(row, k, v)
                row.updated_at = datetime.utcnow()
            else:
                row = ExploitdbCache(**e)
                db.add(row)
            count += 1
        db.commit()
        return count
    finally:
        db.close()

def get_exploitdb_by_cve(cve_id: str) -> list[dict]:
    """Find ExploitDB entries matching a CVE ID."""
    db = SessionLocal()
    try:
        rows = db.query(ExploitdbCache).filter(
            ExploitdbCache.cve == cve_id
        ).all()
        return [
            {"exploit_id": r.exploit_id, "description": r.description,
             "type": r.type, "platform": r.platform, "port": r.port,
             "date": r.date, "author": r.author,
             "url": r.url or f"https://www.exploit-db.com/exploits/{r.exploit_id}"}
            for r in rows
        ]
    finally:
        db.close()

def search_exploitdb(query: str, limit: int = 20) -> list[dict]:
    """Search ExploitDB cache by description or CVE."""
    db = SessionLocal()
    try:
        rows = db.query(ExploitdbCache).filter(
            (ExploitdbCache.description.ilike(f"%{query}%")) |
            (ExploitdbCache.cve.ilike(f"%{query}%"))
        ).order_by(ExploitdbCache.date.desc()).limit(limit).all()
        return [
            {"exploit_id": r.exploit_id, "description": r.description,
             "cve": r.cve, "type": r.type, "platform": r.platform,
             "date": r.date, "author": r.author,
             "url": r.url or f"https://www.exploit-db.com/exploits/{r.exploit_id}"}
            for r in rows
        ]
    finally:
        db.close()

def upsert_malwarebazaar_entries(entries: list[dict]) -> int:
    """Batch upsert MalwareBazaar hash entries."""
    db = SessionLocal()
    try:
        count = 0
        for e in entries:
            sha256 = e.get("sha256_hash")
            if not sha256:
                continue
            row = db.query(MalwarebazaarCache).filter(MalwarebazaarCache.sha256_hash == sha256).first()
            if row:
                for k, v in e.items():
                    if hasattr(row, k) and k != "sha256_hash":
                        setattr(row, k, v)
                row.fetched_at = datetime.utcnow()
            else:
                row = MalwarebazaarCache(**e)
                db.add(row)
            count += 1
        db.commit()
        return count
    finally:
        db.close()

def get_malwarebazaar_by_hash(hash_val: str) -> dict | None:
    """Find MalwareBazaar entry by sha256, md5, or sha1 hash."""
    db = SessionLocal()
    try:
        row = db.query(MalwarebazaarCache).filter(
            (MalwarebazaarCache.sha256_hash == hash_val) |
            (MalwarebazaarCache.md5_hash == hash_val) |
            (MalwarebazaarCache.sha1_hash == hash_val)
        ).first()
        if not row:
            return None
        return {
            "sha256_hash": row.sha256_hash, "md5_hash": row.md5_hash,
            "sha1_hash": row.sha1_hash, "file_name": row.file_name,
            "file_type": row.file_type, "tags": row.tags or [],
            "signature": row.signature, "first_seen": row.first_seen,
            "reporter": row.reporter,
        }
    finally:
        db.close()

def get_remediation_counts_for_scan(scan_id: str) -> dict:
    """Return remediation task counts for a single scan."""
    db = SessionLocal()
    try:
        tasks = db.query(RemediationTask).filter(
            RemediationTask.scan_id == scan_id
        ).all()
        total = len(tasks)
        verified = sum(1 for t in tasks if t.status == "verified")
        fixed = sum(1 for t in tasks if t.status in ("fixed", "verified"))
        return {"total": total, "remediated": fixed, "verified": verified}
    finally:
        db.close()

def get_unique_targets_with_stats() -> list[dict]:
    """Return unique targets with scan count + last scan info, top 10 by scan count."""
    db = SessionLocal()
    try:
        from sqlalchemy import func, desc
        # Subquery: count + max date per target
        rows = db.query(
            Scan.target,
            func.count(Scan.id).label("scan_count"),
            func.max(Scan.created_at).label("last_scan_at"),
        ).filter(
            Scan.status == "completed",
        ).group_by(Scan.target).order_by(desc("scan_count")).limit(10).all()

        results = []
        for target, scan_count, last_scan_at in rows:
            # Get last 2 scans for trend
            last_two = db.query(Scan).filter(
                Scan.target == target, Scan.status == "completed"
            ).order_by(Scan.created_at.desc()).limit(2).all()

            last_risk = last_two[0].risk_level if last_two else None
            prev_risk = last_two[1].risk_level if len(last_two) > 1 else None
            last_task_id = last_two[0].task_id if last_two else None
            last_findings = last_two[0].findings_count or 0 if last_two else 0

            results.append({
                "target": target,
                "scan_count": scan_count,
                "last_scan_at": last_scan_at.isoformat() if last_scan_at else None,
                "last_task_id": last_task_id,
                "last_risk_level": last_risk,
                "prev_risk_level": prev_risk,
                "last_findings_count": last_findings,
            })
        return results
    finally:
        db.close()
