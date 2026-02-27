"""Shared dependencies for CYRBER API routers."""

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter
from slowapi.util import get_remote_address
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import os
import sys
import secrets
import logging

# ── Ensure modules/ is importable ──
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.database import get_user_by_username, save_audit_log

# ── Cache headers ──
_NO_CACHE = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

# ── Redis config ──
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# ── Logger ──
_logger = logging.getLogger("cyrber")


def _check_production_secrets():
    """Warn loudly if running with default/well-known secrets."""
    warnings = []

    jwt_secret = os.getenv("JWT_SECRET", "change_me_in_production")
    if jwt_secret in ("change_me_in_production", "change_me", "secret"):
        warnings.append("JWT_SECRET is default – JWT tokens can be forged!")

    cyrber_pass = os.getenv("CYRBER_PASS", "cyrber2024")
    if cyrber_pass in ("cyrber2024", "admin", "password", "cyrber"):
        warnings.append("CYRBER_PASS is default – admin account has a known password!")

    pg_pass = os.getenv("POSTGRES_PASSWORD", "cyrber123")
    if pg_pass in ("cyrber123", "postgres", "password"):
        warnings.append("POSTGRES_PASSWORD is default – database is not secured!")

    license_secret = os.getenv("CYRBER_LICENSE_SECRET", "cyrber-license-secret-2024")
    if license_secret == "cyrber-license-secret-2024":
        warnings.append("CYRBER_LICENSE_SECRET is default – licenses can be forged!")

    if warnings:
        banner = "\n" + "=" * 60
        banner += "\n  CYRBER SECURITY WARNING"
        banner += "\n" + "=" * 60
        for w in warnings:
            banner += f"\n  * {w}"
        banner += "\n" + "=" * 60
        banner += "\n  Set these variables in .env before production deployment!"
        banner += "\n" + "=" * 60 + "\n"
        print(banner, flush=True)
        for w in warnings:
            _logger.warning("SECURITY: %s", w)


_check_production_secrets()


def _load_jwt_secret() -> str:
    env_val = os.getenv("JWT_SECRET")
    if env_val:
        return env_val
    secret_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jwt_secret")
    if os.path.exists(secret_path):
        with open(secret_path) as f:
            return f.read().strip()
    _logger.warning("JWT_SECRET not set — generating and persisting to %s", secret_path)
    new_secret = secrets.token_hex(32)
    with open(secret_path, "w") as f:
        f.write(new_secret)
    return new_secret


JWT_SECRET = _load_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 8

bearer_scheme = HTTPBearer(auto_error=False)
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])


def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """Returns dict with username, role, id, is_active from DB."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(
            credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM]
        )
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Account disabled")
    return user


def require_role(*allowed_roles: str):
    """Dependency factory: raises 403 if current user's role not in allowed_roles."""
    def _checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires role: {', '.join(allowed_roles)}",
            )
        return current_user
    return _checker


def audit(request: Request, user, action: str, target: str = None):
    username = user["username"] if isinstance(user, dict) else user
    ip = request.client.host if request.client else "unknown"
    save_audit_log(user=username, action=action, target=target, ip_address=ip)


def _get_user_or_share_token(
    task_id: str,
    token: str = None,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """Authenticate via JWT header OR HMAC share token query param."""
    if credentials:
        try:
            return get_current_user(credentials)
        except HTTPException:
            pass
    if token:
        import hmac
        import hashlib
        expected = hmac.new(
            JWT_SECRET.encode(), task_id.encode(), hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(token, expected):
            return {"username": "_shared_link", "role": "viewer"}
    raise HTTPException(
        status_code=401,
        detail="Not authenticated — provide JWT or valid share token",
    )


def _get_user_from_token(token: str) -> dict:
    """Walidacja JWT z query param (SSE nie obsługuje custom headers)."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = get_user_by_username(username)
    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="User inactive or not found")
    return user


# ── Risk helpers ──

_RISK_PL_TO_EN = {
    "KRYTYCZNE": "CRITICAL",
    "WYSOKIE": "HIGH",
    "ŚREDNIE": "MEDIUM",
    "SREDNIE": "MEDIUM",
    "NISKIE": "LOW",
}
_RISK_SCORE_MAP = {
    "CRITICAL": 90,
    "HIGH": 70,
    "MEDIUM": 40,
    "LOW": 15,
    # Legacy PL keys for backward compat
    "KRYTYCZNE": 90,
    "WYSOKIE": 70,
    "ŚREDNIE": 40,
    "SREDNIE": 40,
    "NISKIE": 15,
}


def _normalize_risk(risk: str) -> str:
    """Normalize PL risk level to EN. Pass-through if already EN."""
    if not risk:
        return risk
    return _RISK_PL_TO_EN.get(risk.upper(), risk.upper())


def _extract_severity_counts(raw: dict) -> dict:
    """Extract finding severity counts from raw scan data."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    # Walk through known module keys that contain findings lists
    for key in raw:
        if key in ("nuclei", "sqlmap", "ai_analysis"):
            continue
        val = raw[key]
        if not isinstance(val, dict):
            continue
        findings = val.get("findings", [])
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity", "")).lower()
            if sev in counts:
                counts[sev] += 1
    # Nuclei results
    nuclei = raw.get("nuclei", {})
    if isinstance(nuclei, dict):
        for item in nuclei.get("results", nuclei.get("findings", [])):
            if isinstance(item, dict):
                sev = str(
                    item.get("severity", item.get("info", {}).get("severity", ""))
                ).lower()
                if sev in counts:
                    counts[sev] += 1
    # sqlmap
    sqlmap = raw.get("sqlmap", {})
    if isinstance(sqlmap, dict) and sqlmap.get("vulnerable"):
        counts["critical"] += 1
    return counts


# ── Finding classification ──

_FINDING_NAMES = {
    "sql": "SQL Injection Vulnerability",
    "xss": "Cross-Site Scripting (XSS)",
    "rce": "Remote Code Execution",
    "lfi": "Local File Inclusion",
    "rfi": "Remote File Inclusion",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "xxe": "XML External Entity (XXE)",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "open-redirect": "Open Redirect",
    "directory-listing": "Directory Listing Enabled",
    "default-login": "Default Credentials",
    "info-disclosure": "Information Disclosure",
    "misconfig": "Server Misconfiguration",
    "ssl": "SSL/TLS Certificate Issue",
    "cve": "Known Software Vulnerability",
}

_FINDING_DESCS = {
    "sql": "An attacker could read or modify the company database, including customer data and passwords.",
    "xss": "An attacker could hijack user sessions and steal login credentials.",
    "rce": "An attacker could gain full control over the server and company data.",
    "lfi": "An attacker could read sensitive server files, including configuration and passwords.",
    "rfi": "An attacker could execute malicious code on the company server.",
    "ssrf": "An attacker could access internal company systems.",
    "xxe": "An attacker could read server files through crafted XML data.",
    "idor": "An attacker could access other users' data without authorization.",
    "csrf": "An attacker could perform operations on behalf of a logged-in user.",
    "open-redirect": "Users could be redirected to fake login pages.",
    "directory-listing": "Server directory structure is publicly visible, facilitating attacks.",
    "default-login": "System uses factory-default credentials, enabling immediate access.",
    "info-disclosure": "Server exposes technical information useful for attackers.",
    "misconfig": "Improper configuration allows bypassing security controls.",
    "ssl": "Communication could be intercepted by third parties.",
    "cve": "Software contains a known vulnerability with readily available exploit tools.",
}


def _classify_finding(name_lower):
    for key in _FINDING_NAMES:
        if key in name_lower:
            return key
    return "cve"
