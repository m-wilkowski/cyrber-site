"""Static HTML pages, health check, root redirect."""

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials

from backend.deps import _NO_CACHE, bearer_scheme, _get_user_or_share_token

router = APIRouter(tags=["pages"])


@router.get("/login")
async def login_page():
    return FileResponse("static/login.html")


@router.get("/command-center")
async def command_center():
    return FileResponse("static/command_center.html", headers=_NO_CACHE)


@router.get("/ui")
async def ui():
    return FileResponse("static/index.html", headers=_NO_CACHE)


@router.get("/dashboard")
async def dashboard():
    return FileResponse("static/dashboard.html", headers=_NO_CACHE)


@router.get("/scheduler")
async def scheduler():
    return FileResponse("static/scheduler.html", headers=_NO_CACHE)


@router.get("/phishing")
async def phishing_page():
    return FileResponse("static/phishing.html", headers=_NO_CACHE)


@router.get("/osint")
async def osint_page():
    return FileResponse("static/osint.html", media_type="text/html", headers=_NO_CACHE)


@router.get("/verify")
async def verify_page():
    return FileResponse("static/verify.html", headers=_NO_CACHE)


@router.get("/topology")
async def topology_page():
    return FileResponse("static/topology.html", headers=_NO_CACHE)


@router.get("/mission-control")
async def mission_control_page():
    return FileResponse("static/mission_control.html", headers=_NO_CACHE)


@router.get("/mirror")
async def mirror_page():
    return FileResponse("static/mirror.html", headers=_NO_CACHE)


@router.get("/admin")
async def admin_page():
    return FileResponse("static/admin.html", headers=_NO_CACHE)


@router.get("/report/{task_id}")
async def report_page(
    task_id: str,
    token: str = Query(None),
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    _get_user_or_share_token(task_id, token, credentials)
    return FileResponse("static/report.html", headers=_NO_CACHE)


@router.get("/scan/{task_id}/detail")
async def scan_detail_page(task_id: str):
    return FileResponse("static/scan_detail.html", headers=_NO_CACHE)


@router.get("/api/health")
async def health():
    return {"status": "ok"}


@router.get("/")
async def root():
    return RedirectResponse(url="/ui")
