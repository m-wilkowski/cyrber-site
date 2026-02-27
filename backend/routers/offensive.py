"""Offensive tools: Garak, BeEF, Evilginx2, webhooks."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.deps import limiter, get_current_user, require_role, audit
from backend.schemas import GarakScanRequest, BeefRunModule, EvilginxLureCreate
from modules.tasks import full_scan_task
from modules.webhook import WazuhAlert, extract_target

# ── Garak imports ──
from modules.garak_scan import (
    is_available as garak_available,
    get_status as garak_status,
    list_probes as garak_probes,
    start_scan as garak_start,
    get_scan as garak_get,
    list_scans as garak_list,
)

# ── BeEF imports ──
from modules.beef_xss import (
    is_available as beef_available,
    get_status as beef_status,
    get_hooks as beef_hooks,
    get_hook_detail as beef_hook_detail,
    get_modules as beef_modules,
    get_module_detail as beef_module_detail,
    run_module as beef_run_module,
    get_module_result as beef_module_result,
    get_logs as beef_logs,
)

# ── Evilginx imports ──
from modules.evilginx_phishing import (
    is_available as evilginx_available,
    get_sessions as evilginx_sessions,
    get_session as evilginx_session,
    delete_session as evilginx_delete,
    list_phishlets as evilginx_phishlets,
    get_phishlet as evilginx_phishlet,
    get_stats as evilginx_stats,
    get_config as evilginx_config,
    get_credentials as evilginx_credentials,
    get_lures as evilginx_lures,
    create_lure as evilginx_create_lure,
    delete_lure as evilginx_delete_lure,
    get_status as evilginx_status,
)

router = APIRouter(tags=["offensive"])


# ── Availability checks ──

def _require_garak():
    if not garak_available():
        raise HTTPException(
            status_code=503,
            detail="Garak not available — start with: docker compose --profile ai-security up -d",
        )


def _require_beef():
    if not beef_available():
        raise HTTPException(
            status_code=503,
            detail="BeEF not available — start with: docker compose --profile phishing up -d",
        )


def _require_evilginx():
    if not evilginx_available():
        raise HTTPException(
            status_code=503,
            detail="Evilginx2 not available — start with: docker compose --profile phishing up -d",
        )


# ── Garak ──

@router.get("/garak/status")
async def garak_get_status(user: dict = Depends(get_current_user)):
    return garak_status()


@router.get("/garak/probes")
async def garak_get_probes(user: dict = Depends(get_current_user)):
    _require_garak()
    return garak_probes()


@router.post("/garak/scan")
async def garak_post_scan(
    request: Request,
    body: GarakScanRequest,
    user: dict = Depends(require_role("admin", "operator")),
):
    _require_garak()
    result = garak_start(
        target_type=body.target_type,
        target_name=body.target_name,
        probes=body.probes,
        probe_tags=body.probe_tags,
        generations=body.generations,
        api_key=body.api_key,
        api_base=body.api_base,
    )
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    audit(request, user, "garak_scan_start", f"{body.target_type}/{body.target_name}")
    return result


@router.get("/garak/scan/{scan_id}")
async def garak_get_scan(scan_id: str, user: dict = Depends(get_current_user)):
    _require_garak()
    result = garak_get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.get("/garak/scans")
async def garak_list_all(user: dict = Depends(get_current_user)):
    _require_garak()
    return garak_list()


# ── BeEF ──

@router.get("/beef/status")
async def beef_get_status(user: dict = Depends(get_current_user)):
    return beef_status()


@router.get("/beef/hooks")
async def beef_get_hooks(user: dict = Depends(get_current_user)):
    _require_beef()
    return beef_hooks()


@router.get("/beef/hooks/{session}")
async def beef_get_hook(session: str, user: dict = Depends(get_current_user)):
    _require_beef()
    detail = beef_hook_detail(session)
    if not detail:
        raise HTTPException(status_code=404, detail="Hooked browser not found")
    return detail


@router.get("/beef/modules")
async def beef_get_modules(user: dict = Depends(get_current_user)):
    _require_beef()
    return beef_modules()


@router.get("/beef/modules/{module_id}")
async def beef_get_module(module_id: str, user: dict = Depends(get_current_user)):
    _require_beef()
    detail = beef_module_detail(module_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Module not found")
    return detail


@router.post("/beef/modules/run")
async def beef_post_run_module(
    request: Request,
    body: BeefRunModule,
    user: dict = Depends(require_role("admin", "operator")),
):
    _require_beef()
    result = beef_run_module(body.session, body.module_id, body.options)
    if not result:
        raise HTTPException(status_code=502, detail="Failed to execute module on BeEF")
    audit(request, user, "beef_run_module", f"{body.session}/{body.module_id}")
    return result


@router.get("/beef/modules/{session}/{module_id}/{cmd_id}")
async def beef_get_result(
    session: str, module_id: str, cmd_id: str,
    user: dict = Depends(get_current_user),
):
    _require_beef()
    result = beef_module_result(session, module_id, cmd_id)
    if not result:
        raise HTTPException(status_code=404, detail="Command result not found")
    return result


@router.get("/beef/logs")
async def beef_get_logs(session: str | None = None, user: dict = Depends(get_current_user)):
    _require_beef()
    return beef_logs(session)


# ── Evilginx2 ──

@router.get("/evilginx/stats")
async def evilginx_get_stats(user: dict = Depends(get_current_user)):
    return evilginx_stats()


@router.get("/evilginx/sessions")
async def evilginx_get_sessions(user: dict = Depends(get_current_user)):
    _require_evilginx()
    return evilginx_sessions()


@router.get("/evilginx/sessions/{session_id}")
async def evilginx_get_session(session_id: str, user: dict = Depends(get_current_user)):
    _require_evilginx()
    s = evilginx_session(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return s


@router.delete("/evilginx/sessions/{session_id}")
async def evilginx_delete_session(
    request: Request,
    session_id: str,
    user: dict = Depends(require_role("admin", "operator")),
):
    _require_evilginx()
    if not evilginx_delete(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    audit(request, user, "evilginx_session_delete", session_id)
    return {"status": "deleted", "session_id": session_id}


@router.get("/evilginx/phishlets")
async def evilginx_get_phishlets(user: dict = Depends(get_current_user)):
    _require_evilginx()
    return evilginx_phishlets()


@router.get("/evilginx/phishlets/{name}")
async def evilginx_get_phishlet(name: str, user: dict = Depends(get_current_user)):
    _require_evilginx()
    p = evilginx_phishlet(name)
    if not p:
        raise HTTPException(status_code=404, detail="Phishlet not found")
    return p


@router.get("/evilginx/config")
async def evilginx_get_config(user: dict = Depends(get_current_user)):
    _require_evilginx()
    return evilginx_config()


@router.get("/api/evilginx/status")
async def evilginx_get_status_api(user: dict = Depends(get_current_user)):
    return evilginx_status()


@router.get("/api/evilginx/credentials")
async def evilginx_get_credentials(user: dict = Depends(get_current_user)):
    _require_evilginx()
    return evilginx_credentials()


@router.get("/api/evilginx/lures")
async def evilginx_get_lures(user: dict = Depends(get_current_user)):
    _require_evilginx()
    return evilginx_lures()


@router.post("/api/evilginx/lures")
async def evilginx_create_lure_api(
    request: Request,
    body: EvilginxLureCreate,
    user: dict = Depends(require_role("admin", "operator")),
):
    _require_evilginx()
    try:
        lure = evilginx_create_lure(body.phishlet, body.redirect_url, body.path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit(request, user, "evilginx_lure_create", f"phishlet={body.phishlet}")
    return lure


@router.delete("/api/evilginx/lures/{lure_id}")
async def evilginx_delete_lure_api(
    request: Request,
    lure_id: int,
    user: dict = Depends(require_role("admin", "operator")),
):
    _require_evilginx()
    if not evilginx_delete_lure(lure_id):
        raise HTTPException(status_code=404, detail="Lure not found")
    audit(request, user, "evilginx_lure_delete", str(lure_id))
    return {"status": "deleted", "lure_id": lure_id}


# ── Webhooks ──

@router.post("/webhook/wazuh")
@limiter.limit("30/minute")
async def wazuh_webhook(
    request: Request,
    alert: WazuhAlert,
    user: dict = Depends(require_role("admin", "operator")),
):
    target = extract_target(alert)
    if not target:
        return {"status": "ignored", "reason": "no valid target extracted"}
    task = full_scan_task.delay(target)
    audit(request, user, "webhook_wazuh", target)
    return {
        "status": "scan_started",
        "target": target,
        "task_id": task.id,
        "trigger": "wazuh_alert",
        "rule_id": alert.rule_id,
    }


@router.post("/webhook/generic")
@limiter.limit("30/minute")
async def generic_webhook(
    request: Request,
    payload: dict,
    user: dict = Depends(require_role("admin", "operator")),
):
    target = payload.get("target") or payload.get("ip") or payload.get("host")
    if not target:
        return {"status": "ignored", "reason": "no target field in payload"}
    task = full_scan_task.delay(target)
    audit(request, user, "webhook_generic", target)
    return {
        "status": "scan_started",
        "target": target,
        "task_id": task.id,
        "trigger": "webhook",
    }
