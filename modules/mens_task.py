"""Celery task for running MENS autonomous agent iterations."""

import logging
import uuid
from datetime import datetime, timezone

from celery.exceptions import SoftTimeLimitExceeded

from modules.tasks import celery_app
from modules.database import SessionLocal

_log = logging.getLogger("cyrber.mens_task")

MAX_ITERATIONS = 50


@celery_app.task(bind=True, soft_time_limit=28800, time_limit=28860)
def mens_run_task(self, mission_id: str):
    """Run MENS reasoning loop until completion, abort, or iteration limit.

    Each iteration: observe → think → act → learn.
    Max 50 iterations as safety guard.
    """
    from backend.mind_agent import (
        MensAgent,
        MensMission,
        MensMissionModel,
        MensIterationModel,
    )
    from backend.lex import LexEngine

    db = SessionLocal()
    try:
        row = db.query(MensMissionModel).filter(
            MensMissionModel.id == mission_id
        ).first()
        if not row:
            _log.error("[MENS task] mission %s not found", mission_id)
            return {"status": "error", "message": "Mission not found"}

        # Build Pydantic mission from DB row
        mission = MensMission(
            id=uuid.UUID(row.id),
            target=row.target,
            objective=row.objective,
            lex_rule_id=uuid.UUID(row.lex_rule_id),
            mode=row.mode,
            status=row.status,
            started_at=row.started_at or datetime.now(timezone.utc),
            created_by=row.created_by or "system",
            fiducia=row.fiducia or 0.0,
        )

        lex_engine = LexEngine()
        agent = MensAgent(mission, lex_engine)

        _log.info("[MENS task] starting mission %s, target=%s, mode=%s",
                  mission_id, mission.target, mission.mode)

        iteration_count = 0

        while mission.status == "running" and iteration_count < MAX_ITERATIONS:
            # Refresh mission status from DB (may have been aborted externally)
            db.expire_all()
            db_row = db.query(MensMissionModel).filter(
                MensMissionModel.id == mission_id
            ).first()
            if not db_row or db_row.status != "running":
                _log.info("[MENS task] mission %s no longer running (status=%s)",
                          mission_id, db_row.status if db_row else "deleted")
                break

            iteration = agent.run_iteration(db)
            iteration_count += 1

            _log.info(
                "[MENS task] iteration #%d: module=%s phase=%s fiducia=%.2f",
                iteration.iteration_number,
                iteration.module_selected,
                iteration.phase,
                mission.fiducia,
            )

            # COMES mode: pause for approval
            if mission.mode == "comes" and iteration.approved is None:
                _log.info("[MENS task] COMES: pausing for approval on iteration #%d",
                          iteration.iteration_number)
                db_row.status = "paused"
                db.commit()
                break

            # Agent decided DONE
            if iteration.module_selected == "DONE":
                break

        # Final status update
        db.expire_all()
        final_row = db.query(MensMissionModel).filter(
            MensMissionModel.id == mission_id
        ).first()
        if final_row and final_row.status == "running":
            if iteration_count >= MAX_ITERATIONS:
                final_row.status = "completed"
                final_row.completed_at = datetime.now(timezone.utc)
                _log.warning("[MENS task] mission %s hit iteration limit (%d)",
                             mission_id, MAX_ITERATIONS)
            db.commit()

        _log.info("[MENS task] mission %s finished: %d iterations, status=%s",
                  mission_id, iteration_count,
                  final_row.status if final_row else "unknown")

        return {
            "status": "ok",
            "mission_id": mission_id,
            "iterations": iteration_count,
        }

    except SoftTimeLimitExceeded:
        _log.warning("[MENS task] mission %s hit time limit", mission_id)
        _abort_mission(db, mission_id, "Time limit exceeded (8h)")
        return {"status": "timeout", "mission_id": mission_id}
    except Exception as exc:
        _log.exception("[MENS task] mission %s failed: %s", mission_id, exc)
        _abort_mission(db, mission_id, str(exc))
        return {"status": "error", "mission_id": mission_id, "message": str(exc)}
    finally:
        db.close()


def _abort_mission(db, mission_id: str, error_msg: str):
    """Mark mission as aborted and store error in last iteration."""
    from backend.mind_agent import MensMissionModel, MensIterationModel

    try:
        row = db.query(MensMissionModel).filter(
            MensMissionModel.id == mission_id
        ).first()
        if row:
            row.status = "aborted"
            row.completed_at = datetime.now(timezone.utc)

        # Store error in the last iteration
        last_it = (
            db.query(MensIterationModel)
            .filter(MensIterationModel.mission_id == mission_id)
            .order_by(MensIterationModel.iteration_number.desc())
            .first()
        )
        if last_it:
            last_it.result_summary = f"[ERROR] {error_msg}"
        db.commit()
    except Exception:
        _log.exception("[MENS task] failed to abort mission %s", mission_id)
