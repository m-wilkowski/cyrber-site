"""
BeEF-XSS integration for CYRBER.

REST API client for Browser Exploitation Framework.
Manages hooked browsers, command modules, and session logs.
"""

import logging
import os

import requests

log = logging.getLogger("beef_xss")

BEEF_URL = os.getenv("BEEF_URL", "http://beef:3000")
BEEF_USER = os.getenv("BEEF_USER", "cyrber")
BEEF_PASS = os.getenv("BEEF_PASS", "cyrber_beef_2024")

_token: str | None = None


# ── Auth ─────────────────────────────────────────────────────────

def _login() -> str | None:
    """Authenticate to BeEF and cache the API token."""
    global _token
    if _token:
        return _token
    try:
        r = requests.post(
            f"{BEEF_URL}/api/admin/login",
            json={"username": BEEF_USER, "password": BEEF_PASS},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("success"):
            _token = data["token"]
            log.info("[beef] Authenticated, token cached")
            return _token
        log.warning("[beef] Login failed: %s", data)
        return None
    except requests.ConnectionError:
        log.debug("[beef] Not reachable at %s", BEEF_URL)
        return None
    except Exception as e:
        log.warning("[beef] Login error: %s", e)
        return None


def _reset_token():
    """Force re-authentication on next call."""
    global _token
    _token = None


def _get(path: str) -> dict | list | None:
    """GET request to BeEF API with auto-login and token retry."""
    token = _login()
    if not token:
        return None
    try:
        r = requests.get(f"{BEEF_URL}/api/{path}?token={token}", timeout=15)
        if r.status_code == 401:
            _reset_token()
            token = _login()
            if not token:
                return None
            r = requests.get(f"{BEEF_URL}/api/{path}?token={token}", timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning("[beef] GET %s failed: %s", path, e)
        return None


def _post(path: str, data: dict) -> dict | None:
    """POST request to BeEF API with auto-login and token retry."""
    token = _login()
    if not token:
        return None
    try:
        r = requests.post(
            f"{BEEF_URL}/api/{path}?token={token}",
            json=data, timeout=15,
        )
        if r.status_code == 401:
            _reset_token()
            token = _login()
            if not token:
                return None
            r = requests.post(
                f"{BEEF_URL}/api/{path}?token={token}",
                json=data, timeout=15,
            )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning("[beef] POST %s failed: %s", path, e)
        return None


# ── Availability ─────────────────────────────────────────────────

def is_available() -> bool:
    """Check if BeEF is reachable and we can authenticate."""
    return _login() is not None


# ── Hooked Browsers ──────────────────────────────────────────────

def get_hooks() -> dict:
    """List all hooked browsers (online + offline)."""
    data = _get("hooks")
    if not data:
        return {"online": [], "offline": []}

    def _parse_browsers(browsers: dict) -> list[dict]:
        result = []
        for session_id, info in browsers.items():
            result.append({
                "session": session_id,
                "ip": info.get("ip", ""),
                "browser": f"{info.get('BrowserName', '')} {info.get('BrowserVersion', '')}".strip(),
                "os": f"{info.get('OsName', '')} {info.get('OsVersion', '')}".strip(),
                "domain": info.get("domain", ""),
                "page_uri": info.get("page_uri", ""),
                "port": info.get("port", ""),
            })
        return result

    return {
        "online": _parse_browsers(data.get("hooked-browsers", {}).get("online", {})),
        "offline": _parse_browsers(data.get("hooked-browsers", {}).get("offline", {})),
    }


def get_hook_detail(session: str) -> dict | None:
    """Get detailed info for a specific hooked browser."""
    return _get(f"hooks/{session}")


# ── Command Modules ──────────────────────────────────────────────

def get_modules() -> list[dict]:
    """List all available BeEF command modules."""
    data = _get("modules")
    if not data:
        return []
    modules = []
    for mod_id, info in data.items():
        modules.append({
            "id": mod_id,
            "name": info.get("name", ""),
            "category": info.get("category", ""),
        })
    return modules


def get_module_detail(module_id: str) -> dict | None:
    """Get detail for a specific module (description, options)."""
    return _get(f"modules/{module_id}")


def run_module(session: str, module_id: str, options: dict | None = None) -> dict | None:
    """Execute a command module on a hooked browser."""
    return _post(f"modules/{session}/{module_id}", options or {})


def get_module_result(session: str, module_id: str, cmd_id: str) -> dict | None:
    """Retrieve result of a previously executed command."""
    return _get(f"modules/{session}/{module_id}/{cmd_id}")


# ── Logs ─────────────────────────────────────────────────────────

def get_logs(session: str | None = None) -> dict | None:
    """Get logs — global or per-session."""
    path = f"logs/{session}" if session else "logs"
    return _get(path)


# ── Stats / overview ─────────────────────────────────────────────

def get_status() -> dict:
    """Build a status overview for the CYRBER dashboard."""
    if not is_available():
        return {"available": False, "error": "BeEF not reachable"}

    hooks = get_hooks()
    modules = get_modules()
    return {
        "available": True,
        "url": BEEF_URL,
        "hooks_online": len(hooks.get("online", [])),
        "hooks_offline": len(hooks.get("offline", [])),
        "modules_count": len(modules),
        "hook_js_url": f"{BEEF_URL}/hook.js",
    }
