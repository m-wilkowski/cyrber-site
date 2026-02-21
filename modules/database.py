from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, text, inspect as sa_inspect
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
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user = Column(String, nullable=False)
    action = Column(String, nullable=False)
    target = Column(String)
    ip_address = Column(String)

class Schedule(Base):
    __tablename__ = "schedules"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, nullable=False)
    interval_hours = Column(Integer, nullable=False)
    enabled = Column(Boolean, default=True)
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

def init_db(retries=10, delay=3):
    for i in range(retries):
        try:
            Base.metadata.create_all(bind=engine)
            # Migrate: add scan_type column if missing
            try:
                insp = sa_inspect(engine)
                cols = [c['name'] for c in insp.get_columns('scans')]
                if 'scan_type' not in cols:
                    with engine.begin() as conn:
                        conn.execute(text("ALTER TABLE scans ADD COLUMN scan_type VARCHAR DEFAULT 'full'"))
                    print("Migration: added scan_type column")
            except Exception:
                pass
            print("Database initialized successfully")
            return
        except Exception as e:
            if i < retries - 1:
                print(f"DB not ready, retrying in {delay}s... ({i+1}/{retries})")
                time.sleep(delay)
            else:
                raise e

def save_scan(task_id: str, target: str, result: dict, scan_type: str = "full"):
    db = SessionLocal()
    try:
        analysis = result.get("analysis", {})
        scan = db.query(Scan).filter(Scan.task_id == task_id).first()
        if not scan:
            scan = Scan(task_id=task_id, target=target)
            db.add(scan)
        scan.status = "completed"
        scan.scan_type = scan_type
        scan.risk_level = analysis.get("risk_level")
        scan.findings_count = result.get("findings_count", 0)
        scan.summary = analysis.get("summary")
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
            "top_issues": json.loads(s.top_issues) if s.top_issues else [],
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        if s.raw_data:
            raw = json.loads(s.raw_data)
            for key in ["ports", "nuclei", "gobuster", "whatweb", "testssl", "sqlmap", "nikto", "harvester", "masscan", "exploit_chains", "hacker_narrative", "fp_filter", "ipinfo", "enum4linux", "mitre", "abuseipdb", "otx", "exploitdb", "nvd", "whois", "dnsrecon", "amass", "cwe", "owasp", "wpscan", "zap", "wapiti", "joomscan", "cmsmap", "droopescan", "retirejs", "subfinder", "httpx", "naabu", "katana", "dnsx", "netdiscover", "arpscan", "fping", "traceroute", "nbtscan", "snmpwalk", "netexec"]:
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
