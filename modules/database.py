from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
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
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)

def init_db(retries=10, delay=3):
    for i in range(retries):
        try:
            Base.metadata.create_all(bind=engine)
            print("Database initialized successfully")
            return
        except Exception as e:
            if i < retries - 1:
                print(f"DB not ready, retrying in {delay}s... ({i+1}/{retries})")
                time.sleep(delay)
            else:
                raise e

def save_scan(task_id: str, target: str, result: dict):
    db = SessionLocal()
    try:
        analysis = result.get("analysis", {})
        scan = db.query(Scan).filter(Scan.task_id == task_id).first()
        if not scan:
            scan = Scan(task_id=task_id, target=target)
            db.add(scan)
        scan.status = "completed"
        scan.risk_level = analysis.get("risk_level")
        scan.findings_count = result.get("findings_count", 0)
        scan.summary = analysis.get("summary")
        scan.recommendations = analysis.get("recommendations")
        scan.top_issues = json.dumps(analysis.get("top_issues", []), ensure_ascii=False)
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
        return {
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
    finally:
        db.close()
