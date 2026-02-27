"""Dashboard, scheduler, notifications, audit, RAG, scan-agent, security scores."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
import json

from backend.deps import (
    limiter, get_current_user, require_role, audit,
    _RISK_SCORE_MAP,
)
from backend.schemas import ScheduleCreate, ScanAgentRequest
from modules.database import (
    add_schedule, get_schedules, delete_schedule,
    get_audit_logs, get_scan_by_task_id,
    get_unique_targets_with_stats,
)
from modules.tasks import agent_scan_task
from modules.notify import (
    send_scan_notification,
    SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_TO,
    SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL,
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
)

router = APIRouter(tags=["dashboard"])


# ── Agent start ──

@router.get("/agent/start")
@limiter.limit("3/minute")
async def agent_start(
    request: Request,
    target: str = Query(...),
    user: dict = Depends(require_role("admin", "operator")),
):
    task = agent_scan_task.delay(target)
    audit(request, user, "agent_start", target)
    return {"task_id": task.id, "status": "started", "target": target, "mode": "agent"}


# ── Scheduler ──

@router.post("/schedules")
async def create_schedule(
    request: Request,
    schedule: ScheduleCreate,
    user: dict = Depends(require_role("admin", "operator")),
):
    if schedule.interval_hours < 1:
        raise HTTPException(status_code=400, detail="interval_hours must be >= 1")
    result = add_schedule(schedule.target, schedule.interval_hours)
    audit(request, user, "schedule_create", schedule.target)
    return result


@router.get("/schedules")
async def list_schedules(user: dict = Depends(get_current_user)):
    return get_schedules()


@router.delete("/schedules/{schedule_id}")
async def remove_schedule(
    request: Request,
    schedule_id: int,
    user: dict = Depends(require_role("admin", "operator")),
):
    ok = delete_schedule(schedule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Schedule not found")
    audit(request, user, "schedule_delete", str(schedule_id))
    return {"status": "deleted", "id": schedule_id}


# ── Notifications ──

@router.get("/notifications/status")
async def notifications_status(user: dict = Depends(get_current_user)):
    return {
        "email": bool(SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_TO),
        "slack": bool(SLACK_WEBHOOK_URL),
        "discord": bool(DISCORD_WEBHOOK_URL),
        "telegram": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID),
    }


@router.post("/notifications/test")
@limiter.limit("3/minute")
async def notifications_test(
    request: Request,
    user: dict = Depends(require_role("admin", "operator")),
):
    test_result = {
        "target": "test.example.com",
        "findings_count": 42,
        "analysis": {
            "risk_level": "MEDIUM",
            "summary": "This is a test notification from CYRBER to verify your notification channels are configured correctly.",
        },
    }
    ok = send_scan_notification("test.example.com", "test-0000-0000", test_result)
    audit(request, user, "notifications_test")
    return {"sent": ok, "message": "Test notification dispatched to all configured channels"}


# ── Audit logs ──

@router.get("/audit")
async def audit_logs(limit: int = 100, user: dict = Depends(require_role("admin"))):
    return get_audit_logs(limit)


# ── RAG ──

@router.post("/rag/build-index")
async def build_rag_index(current_user: dict = Depends(require_role("admin"))):
    """Buduje indeks RAG z knowledge_base"""
    from modules.rag_knowledge import get_rag
    result = get_rag().build_index()
    return result


@router.get("/rag/search")
async def rag_search(q: str, top_k: int = 5, current_user: dict = Depends(get_current_user)):
    """Semantic search w knowledge base"""
    from modules.rag_knowledge import get_rag
    results = get_rag().search(q, top_k=top_k)
    return {"query": q, "results": results}


# ── Scan AI Agent (conversational) ──

@router.post("/api/scan-agent")
@limiter.limit("30/minute")
async def scan_agent(
    request: Request,
    body: ScanAgentRequest,
    user: dict = Depends(get_current_user),
):
    from modules.llm_provider import ClaudeProvider

    scan = get_scan_by_task_id(body.task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target = scan.get("target", "")
    risk = scan.get("risk_level", "N/A")
    findings_count = scan.get("findings_count", 0)
    ai = scan.get("ai_analysis") or {}
    summary = ai.get("executive_summary") or scan.get("summary") or ""
    narrative = (scan.get("hacker_narrative") or {}).get("executive_summary", "")

    top_findings = []
    nuclei = scan.get("nuclei") or {}
    for f in (nuclei.get("findings") or [])[:10]:
        info = f.get("info") or {}
        top_findings.append(f"{info.get('severity', 'info').upper()}: {info.get('name', f.get('template_id', ''))}")

    if scan.get("sqlmap", {}).get("vulnerable"):
        top_findings.insert(0, "CRITICAL: SQL Injection (SQLMap)")

    for a in (scan.get("zap", {}).get("alerts") or [])[:5]:
        top_findings.append(f"{a.get('risk', 'info').upper()}: {a.get('name', '')}")

    chains_summary = ""
    chains_raw = scan.get("exploit_chains") or {}
    chains_list = chains_raw.get("chains") if isinstance(chains_raw, dict) else chains_raw
    if isinstance(chains_list, list) and chains_list:
        chain_descs = []
        for c in chains_list[:3]:
            steps = c.get("steps") or c.get("chain") or []
            step_names = [s.get("action") or s.get("technique") or "" for s in steps[:4]]
            chain_descs.append(" -> ".join(step_names))
        chains_summary = "\n".join(chain_descs)

    system_prompt = (
        "You are the CYRBER AI cybersecurity expert. You respond concisely and helpfully "
        "in English. You have full context of the security scan.\n\n"
        f"TARGET: {target}\n"
        f"RISK LEVEL: {risk}\n"
        f"FINDINGS COUNT: {findings_count}\n"
        f"SUMMARY: {summary[:500]}\n"
        f"NARRATIVE: {narrative[:500]}\n"
        f"TOP FINDINGS:\n" + "\n".join(top_findings[:15]) + "\n"
    )
    if chains_summary:
        system_prompt += f"\nEXPLOIT CHAINS:\n{chains_summary}\n"

    system_prompt += (
        "\nRespond concisely (max 3-4 sentences). "
        "If the question is about a CVE, explain what it is and how to fix it. "
        "If the question is about a scan parameter, explain in the context of this target."
    )

    try:
        provider = ClaudeProvider(model="claude-haiku-4-5-20251001")
        prompt_parts = []
        for msg in (body.history or [])[-8:]:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "user":
                prompt_parts.append(f"User: {content}")
            elif role == "assistant":
                prompt_parts.append(f"AI: {content}")
        prompt_parts.append(f"User: {body.message}")
        prompt = "\n".join(prompt_parts)

        response_text = provider.chat(prompt, system=system_prompt, max_tokens=800)
        return {"response": response_text.strip()}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI agent failed: {str(e)}")


# ── Dashboard security scores ──

@router.get("/api/dashboard/security-scores")
async def dashboard_security_scores(
    current_user: dict = Depends(require_role("admin", "operator")),
):
    targets = get_unique_targets_with_stats()
    results = []
    for t in targets:
        last_risk = t["last_risk_level"]
        prev_risk = t["prev_risk_level"]
        last_score = _RISK_SCORE_MAP.get(last_risk, 50) if last_risk else 50
        prev_score = _RISK_SCORE_MAP.get(prev_risk, 50) if prev_risk else None

        if prev_score is not None:
            if last_score < prev_score:
                trend = "improving"
            elif last_score > prev_score:
                trend = "degrading"
            else:
                trend = "stable"
        else:
            trend = "new"

        results.append({
            "target": t["target"],
            "scan_count": t["scan_count"],
            "last_scan_at": t["last_scan_at"],
            "last_task_id": t["last_task_id"],
            "risk_score": last_score,
            "risk_level": last_risk,
            "findings_count": t["last_findings_count"],
            "trend": trend,
        })
    return {"targets": results}
