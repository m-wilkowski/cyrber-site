"""
CYRBER on-prem license system.

License key = base64(JSON payload + HMAC-SHA256 signature).
Tiers: demo (no key), basic, pro, enterprise.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, date

log = logging.getLogger("license")

LICENSE_PATH = os.getenv("CYRBER_LICENSE_PATH", "/app/license.key")
LICENSE_SECRET = os.getenv("CYRBER_LICENSE_SECRET", "cyrber-license-secret-2024").encode()

# ── Tier definitions ─────────────────────────────────────

TIERS = {
    "demo": {
        "max_users": 1,
        "max_scans_per_month": 5,
        "allowed_profiles": ["SZCZENIAK"],
        "features": ["scan", "reports"],
    },
    "basic": {
        "max_users": 3,
        "max_scans_per_month": 50,
        "allowed_profiles": ["SZCZENIAK"],
        "features": ["scan", "reports"],
    },
    "pro": {
        "max_users": 10,
        "max_scans_per_month": 0,  # 0 = unlimited
        "allowed_profiles": ["SZCZENIAK", "STRAZNIK"],
        "features": ["scan", "reports", "osint", "scheduler", "webhooks"],
    },
    "enterprise": {
        "max_users": 0,  # 0 = unlimited
        "max_scans_per_month": 0,
        "allowed_profiles": ["SZCZENIAK", "STRAZNIK", "CERBER"],
        "features": ["scan", "reports", "osint", "scheduler", "webhooks", "phishing", "garak", "beef", "agent"],
    },
}

# ── Signature ────────────────────────────────────────────

def _sign(payload_bytes: bytes) -> str:
    return hmac.new(LICENSE_SECRET, payload_bytes, hashlib.sha256).hexdigest()


def _encode_key(data: dict) -> str:
    """Encode license data dict to a signed base64 key string."""
    payload = {k: v for k, v in data.items() if k != "signature"}
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = _sign(payload_json.encode())
    payload["signature"] = sig
    full_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return base64.b64encode(full_json.encode()).decode()


def _decode_key(key_str: str) -> dict | None:
    """Decode base64 key string to license data dict. Returns None on failure."""
    try:
        raw = base64.b64decode(key_str.strip()).decode()
        data = json.loads(raw)
        return data
    except Exception as e:
        log.warning("[license] Failed to decode key: %s", e)
        return None


# ── Core functions ───────────────────────────────────────

def load_license() -> dict | None:
    """Load license from env var or file. Returns decoded dict or None."""
    # 1. Try env var
    env_key = os.getenv("CYRBER_LICENSE_KEY", "").strip()
    if env_key:
        data = _decode_key(env_key)
        if data and validate_license(data):
            return data

    # 2. Try file
    if os.path.isfile(LICENSE_PATH):
        try:
            with open(LICENSE_PATH, "r") as f:
                key_str = f.read().strip()
            if key_str:
                data = _decode_key(key_str)
                if data and validate_license(data):
                    return data
        except Exception as e:
            log.warning("[license] Failed to read %s: %s", LICENSE_PATH, e)

    return None


def validate_license(data: dict) -> bool:
    """Validate HMAC signature and expiration date."""
    if not data or "signature" not in data:
        return False

    # Check signature
    sig = data["signature"]
    payload = {k: v for k, v in data.items() if k != "signature"}
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    expected_sig = _sign(payload_json.encode())

    if not hmac.compare_digest(sig, expected_sig):
        log.warning("[license] Invalid signature")
        return False

    # Check expiration
    expires_str = data.get("expires_at", "")
    if expires_str:
        try:
            expires = date.fromisoformat(expires_str)
            if expires < date.today():
                log.warning("[license] License expired on %s", expires_str)
                return False
        except ValueError:
            log.warning("[license] Invalid expires_at format: %s", expires_str)
            return False

    return True


def get_license_info() -> dict:
    """Return safe license info (no signature). Falls back to demo tier."""
    lic = load_license()
    if not lic:
        return {
            "status": "demo",
            "tier": "demo",
            "customer": "DEMO MODE",
            "license_id": None,
            "issued_at": None,
            "expires_at": None,
            **TIERS["demo"],
        }

    tier = lic.get("tier", "basic")
    tier_defaults = TIERS.get(tier, TIERS["basic"])

    # Check if expired (for status badge)
    status = "active"
    expires_str = lic.get("expires_at", "")
    if expires_str:
        try:
            if date.fromisoformat(expires_str) < date.today():
                status = "expired"
        except ValueError:
            pass

    return {
        "status": status,
        "tier": tier,
        "customer": lic.get("customer", ""),
        "license_id": lic.get("license_id", ""),
        "issued_at": lic.get("issued_at"),
        "expires_at": lic.get("expires_at"),
        "max_users": lic.get("max_users", tier_defaults["max_users"]),
        "max_scans_per_month": lic.get("max_scans_per_month", tier_defaults["max_scans_per_month"]),
        "allowed_profiles": lic.get("allowed_profiles", tier_defaults["allowed_profiles"]),
        "features": lic.get("features", tier_defaults["features"]),
    }


def check_feature(feature: str) -> bool:
    """Check if a feature is allowed by current license."""
    info = get_license_info()
    return feature in info["features"]


def check_profile(profile: str) -> bool:
    """Check if a scan profile is allowed by current license."""
    info = get_license_info()
    return profile.upper() in info["allowed_profiles"]


def check_user_limit(current_users: int) -> bool:
    """Check if adding another user is within license limits. 0 = unlimited."""
    info = get_license_info()
    limit = info["max_users"]
    if limit == 0:
        return True
    return current_users < limit


def check_scan_limit(scans_this_month: int) -> bool:
    """Check if running another scan is within license limits. 0 = unlimited."""
    info = get_license_info()
    limit = info["max_scans_per_month"]
    if limit == 0:
        return True
    return scans_this_month < limit


# ── License key generator ────────────────────────────────

def generate_license(
    customer: str,
    tier: str = "basic",
    days: int = 365,
    max_users: int | None = None,
    max_scans: int | None = None,
    features: list[str] | None = None,
    profiles: list[str] | None = None,
) -> str:
    """Generate a signed license key. Returns base64 string."""
    tier_defaults = TIERS.get(tier, TIERS["basic"])

    issued = date.today()
    from datetime import timedelta
    expires = issued + timedelta(days=days)

    data = {
        "license_id": str(uuid.uuid4()),
        "customer": customer,
        "tier": tier,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "max_users": max_users if max_users is not None else tier_defaults["max_users"],
        "max_scans_per_month": max_scans if max_scans is not None else tier_defaults["max_scans_per_month"],
        "allowed_profiles": profiles or tier_defaults["allowed_profiles"],
        "features": features or tier_defaults["features"],
    }

    return _encode_key(data)


def activate_license(key_str: str) -> dict:
    """Validate a key string and save to LICENSE_PATH. Returns result dict."""
    data = _decode_key(key_str)
    if not data:
        return {"ok": False, "error": "Invalid license key format"}

    if not validate_license(data):
        # Check if it's specifically expired vs bad signature
        expires_str = data.get("expires_at", "")
        if expires_str:
            try:
                if date.fromisoformat(expires_str) < date.today():
                    return {"ok": False, "error": f"License expired on {expires_str}"}
            except ValueError:
                pass
        return {"ok": False, "error": "Invalid license signature"}

    try:
        os.makedirs(os.path.dirname(LICENSE_PATH) or ".", exist_ok=True)
        with open(LICENSE_PATH, "w") as f:
            f.write(key_str.strip())
        log.info("[license] Activated: %s (%s) tier=%s expires=%s",
                 data.get("customer"), data.get("license_id"), data.get("tier"), data.get("expires_at"))
        return {"ok": True, "license": get_license_info()}
    except Exception as e:
        return {"ok": False, "error": f"Failed to save license: {e}"}
