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
from backend.routers.mens import router as mens_router
from backend.routers.mirror import router as mirror_router
from backend.routers.proof import router as proof_router
from backend.routers.findings import router as findings_router
from backend.routers.compliance import router as compliance_router
from backend.routers.organizations import router as organizations_router
from backend.routers.lex import router as lex_router
from backend.routers.llm import router as llm_router
from backend.routers.integrations import router as integrations_router

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
app.include_router(mens_router)
app.include_router(mirror_router)
app.include_router(proof_router)
app.include_router(findings_router)
app.include_router(compliance_router)
app.include_router(organizations_router)
app.include_router(lex_router)
app.include_router(llm_router)
app.include_router(integrations_router)


# ── LLM Status Banner ──
def _print_llm_status():
    """Print LLM provider status at startup."""
    try:
        from modules.llm_router import cyrber_llm
        from modules.database import SessionLocal
        from modules.organizations import Organization

        providers = cyrber_llm.get_active_providers()
        active = [
            f"{n} (P{info['priority']})"
            for n, info in sorted(providers.items(), key=lambda x: x[1]["priority"])
            if info["enabled"] and info["available"]
        ]

        banner = "\n" + "-" * 60
        banner += "\n  CYRBER LLM STATUS"
        banner += "\n" + "-" * 60
        banner += f"\n  Active providers: {', '.join(active) if active else 'NONE'}"

        # Per-org settings
        try:
            db = SessionLocal()
            orgs = db.query(Organization).filter(Organization.is_active == True).all()
            if orgs:
                banner += f"\n  Organizations ({len(orgs)}):"
                for org in orgs:
                    mode = (org.llm_mode or "cloud").upper()
                    provider = org.preferred_provider or "anthropic"
                    custom_url = f" ({org.ollama_base_url})" if org.ollama_base_url else ""
                    banner += f"\n    {org.name:<30} {mode:<8} {provider}{custom_url}"
            db.close()
        except Exception:
            pass

        banner += "\n" + "-" * 60
        print(banner, flush=True)
    except Exception as exc:
        print(f"LLM status: unavailable ({exc})", flush=True)


_print_llm_status()
