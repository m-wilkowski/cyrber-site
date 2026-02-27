"""CYRBER API — FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from passlib.hash import sha256_crypt
import os

from backend.deps import limiter
from modules.database import init_db, get_user_by_username, create_user

# ── App ──
app = FastAPI(title="CYRBER API", version="0.3.0")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'self'"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.mount("/static", StaticFiles(directory="static"), name="static")

# ── Database init + bootstrap admin ──
init_db()

if not get_user_by_username("admin"):
    _default_hash = sha256_crypt.hash(os.getenv("CYRBER_PASS", "cyrber2024"))
    create_user(
        username=os.getenv("CYRBER_USER", "admin"),
        password_hash=_default_hash,
        role="admin",
        created_by="system",
        notes="Default admin created at startup",
    )
    print("Bootstrap: created default admin user")
else:
    print("Bootstrap: admin user already exists, skipping")

# ── Include routers ──
from backend.routers.pages import router as pages_router
from backend.routers.auth import router as auth_router
from backend.routers.admin import router as admin_router
from backend.routers.scans import router as scans_router
from backend.routers.scan_tools import router as scan_tools_router
from backend.routers.topology import router as topology_router
from backend.routers.osint import router as osint_router
from backend.routers.phishing import router as phishing_router
from backend.routers.offensive import router as offensive_router
from backend.routers.verify import router as verify_router
from backend.routers.intelligence import router as intelligence_router
from backend.routers.remediation import router as remediation_router
from backend.routers.dashboard import router as dashboard_router
from backend.routers.mind import router as mind_router

app.include_router(pages_router)
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(scans_router)
app.include_router(scan_tools_router)
app.include_router(topology_router)
app.include_router(osint_router)
app.include_router(phishing_router)
app.include_router(offensive_router)
app.include_router(verify_router)
app.include_router(intelligence_router)
app.include_router(remediation_router)
app.include_router(dashboard_router)
app.include_router(mind_router)
