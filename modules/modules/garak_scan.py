"""
Garak LLM security scanner integration for CYRBER.

REST client for the dedicated garak Docker container.
Scans LLM endpoints for prompt injection, jailbreaks, and other vulnerabilities.
"""

import logging
import os
import time

import requests

log = logging.getLogger("garak_scan")

GARAK_URL = os.getenv("GARAK_URL", "http://garak:5000")

_PROBE_CATEGORIES = {
    "prompt_injection": "encoding,promptinject,dan,smuggling",
    "data_leakage": "leakreplay,apikey,packagehallucination",
    "toxicity": "realtoxicityprompts,lmrc",
    "jailbreak": "dan,grandma,goodside,tap",
    "full": "all",
}


# ── Availability ─────────────────────────────────────────────────

def is_available() -> bool:
    """Check if garak container is reachable."""
    try:
        r = requests.get(f"{GARAK_URL}/status", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def get_status() -> dict:
    """Get garak container status and version."""
    try:
        r = requests.get(f"{GARAK_URL}/status", timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        return {"status": "unavailable", "error": "Garak not reachable"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ── Probes ───────────────────────────────────────────────────────

def list_probes() -> list[str]:
    """List available garak probes."""
    try:
        r = requests.get(f"{GARAK_URL}/probes", timeout=30)
        r.raise_for_status()
        return r.json().get("probes", [])
    except Exception as e:
        log.warning("[garak] Failed to list probes: %s", e)
        return []


# ── Scanning ─────────────────────────────────────────────────────

def start_scan(
    target_type: str = "openai",
    target_name: str = "gpt-4",
    probes: str = "encoding,dan,promptinject",
    probe_tags: str = "",
    generations: int = 3,
    api_key: str = "",
    api_base: str = "",
) -> dict:
    """Start an async garak scan. Returns scan_id for polling."""
    if not is_available():
        return {"error": "Garak not available — start with: docker compose --profile ai-security up -d"}

    # Resolve probe category shortcuts
    probes = _PROBE_CATEGORIES.get(probes, probes)

    try:
        r = requests.post(
            f"{GARAK_URL}/scan",
            json={
                "target_type": target_type,
                "target_name": target_name,
                "probes": probes,
                "probe_tags": probe_tags,
                "generations": generations,
                "api_key": api_key,
                "api_base": api_base,
            },
            timeout=15,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning("[garak] Failed to start scan: %s", e)
        return {"error": str(e)}


def get_scan(scan_id: str) -> dict | None:
    """Get scan status and results."""
    try:
        r = requests.get(f"{GARAK_URL}/scan/{scan_id}", timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning("[garak] Failed to get scan %s: %s", scan_id, e)
        return None


def list_scans() -> list[dict]:
    """List all scans."""
    try:
        r = requests.get(f"{GARAK_URL}/scans", timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning("[garak] Failed to list scans: %s", e)
        return []


def run_scan_sync(
    target_type: str = "openai",
    target_name: str = "gpt-4",
    probes: str = "encoding,dan,promptinject",
    probe_tags: str = "",
    generations: int = 3,
    api_key: str = "",
    api_base: str = "",
    timeout: int = 600,
    poll_interval: int = 5,
) -> dict:
    """Start a scan and wait for completion (blocking)."""
    result = start_scan(
        target_type=target_type, target_name=target_name,
        probes=probes, probe_tags=probe_tags, generations=generations,
        api_key=api_key, api_base=api_base,
    )
    if "error" in result:
        return result

    scan_id = result.get("scan_id")
    if not scan_id:
        return {"error": "No scan_id returned"}

    elapsed = 0
    while elapsed < timeout:
        time.sleep(poll_interval)
        elapsed += poll_interval
        scan = get_scan(scan_id)
        if not scan:
            continue
        if scan["status"] in ("completed", "failed"):
            return scan

    return {"error": f"Scan timed out after {timeout}s", "scan_id": scan_id}
