"""Celery task for running MENS v2 autonomous agent missions."""

import logging
import os
import sys
from datetime import datetime, timezone

# Ensure /app is in sys.path so 'backend.*' imports work inside Celery worker
_app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from celery.exceptions import SoftTimeLimitExceeded

from modules.tasks import celery_app
from modules.database import SessionLocal

_log = logging.getLogger("cyrber.mens_task")


@celery_app.task(bind=True, soft_time_limit=28800, time_limit=28860)
def run_mens_mission(self, mission_db_id: int, target: str, policy_dict: dict, org_id: int):
    """Run MENS v2 reasoning loop until completion, abort, or iteration limit.

    Args:
        mission_db_id: Integer PK of the mens_missions row.
        target: Target to scan.
        policy_dict: Serialized LexPolicy fields.
        org_id: Organization ID.
    """
    # sys.path inside function body — Celery prefork pattern
    import os as _os, sys as _sys
    _root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    if _root not in _sys.path:
        _sys.path.insert(0, _root)

    from modules.mind_agent import MensAgent, MensMissionModel
    from modules.lex import LexPolicy

    db = SessionLocal()
    try:
        # Load mission row
        row = db.query(MensMissionModel).filter(
            MensMissionModel.id == mission_db_id
        ).first()
        if not row:
            _log.error("[MENS task] mission id=%d not found", mission_db_id)
            return {"status": "error", "message": "Mission not found"}

        # Mark as running
        row.status = "running"
        db.commit()

        # Reconstruct LexPolicy from dict
        policy = LexPolicy(
            mission_id=policy_dict.get("mission_id", ""),
            organization_id=policy_dict.get("organization_id", org_id),
            scope_cidrs=policy_dict.get("scope_cidrs", []),
            excluded_hosts=policy_dict.get("excluded_hosts", []),
            allowed_modules=policy_dict.get("allowed_modules", []),
            excluded_modules=policy_dict.get("excluded_modules", []),
            time_windows=policy_dict.get("time_windows", []),
            require_approval_cvss=policy_dict.get("require_approval_cvss", 9.0),
            max_duration_seconds=policy_dict.get("max_duration_seconds", 28800),
            max_targets=policy_dict.get("max_targets", 50),
            mode=policy_dict.get("mode", "COMES"),
        )

        agent = MensAgent(
            mission_id=row.mission_id,
            policy=policy,
            db=db,
        )

        _log.info(
            "[MENS task] starting mission id=%d mission_id=%s target=%s mode=%s",
            mission_db_id, row.mission_id, target, policy.mode,
        )

        result = agent.run(target)

        _log.info(
            "[MENS task] mission %s finished: %d iterations, %d findings, status=%s",
            row.mission_id, result.iterations, result.findings_count, result.status,
        )

        # MIRROR hook on completion
        if result.status == "completed":
            try:
                _update_mirror_profile(row.mission_id, target, db)
            except Exception as exc:
                _log.warning("[MENS task] MIRROR update failed: %s", exc)

        return {
            "status": result.status,
            "mission_id": row.mission_id,
            "iterations": result.iterations,
            "findings_count": result.findings_count,
        }

    except SoftTimeLimitExceeded:
        _log.warning("[MENS task] mission id=%d hit time limit", mission_db_id)
        _abort_mission(db, mission_db_id, "Time limit exceeded (8h)")
        return {"status": "timeout", "mission_db_id": mission_db_id}
    except Exception as exc:
        _log.exception("[MENS task] mission id=%d failed: %s", mission_db_id, exc)
        _abort_mission(db, mission_db_id, str(exc))
        return {"status": "error", "mission_db_id": mission_db_id, "message": str(exc)}
    finally:
        db.close()


def _abort_mission(db, mission_db_id: int, error_msg: str):
    """Mark mission as aborted."""
    from modules.mind_agent import MensMissionModel

    try:
        row = db.query(MensMissionModel).filter(
            MensMissionModel.id == mission_db_id
        ).first()
        if row:
            row.status = "aborted"
            row.completed_at = datetime.now(timezone.utc)
            row.summary = f"[ERROR] {error_msg}"
            db.commit()
    except Exception:
        _log.exception("[MENS task] failed to abort mission id=%d", mission_db_id)


def _update_mirror_profile(mission_id: str, target: str, db):
    """Build mission summary and feed it to MIRROR engine."""
    from modules.mind_agent import MensMissionModel, MensIterationModel
    from backend.mirror import MirrorEngine

    mission_row = db.query(MensMissionModel).filter(
        MensMissionModel.mission_id == mission_id
    ).first()
    if not mission_row:
        return

    iter_rows = (
        db.query(MensIterationModel)
        .filter(MensIterationModel.mission_id == mission_row.id)
        .order_by(MensIterationModel.iteration_number)
        .all()
    )

    iterations_data = [
        {
            "module": r.module_used,
            "findings_count": 0,
            "result_summary": r.result_summary,
            "head": classify_head_safe(r.module_used),
        }
        for r in iter_rows
    ]

    mission_summary = {
        "iterations": iterations_data,
        "iteration_count": len(iterations_data),
    }

    engine = MirrorEngine()
    engine.update_profile(target, mission_summary, db)
    _log.info("[MENS task] MIRROR profile updated for target=%s", target)


def classify_head_safe(module_name: str) -> str:
    """Classify head, handling None module names."""
    if not module_name:
        return "RATIO"
    try:
        from modules.mind_agent import classify_head
        return classify_head(module_name)
    except Exception:
        return "RATIO"
