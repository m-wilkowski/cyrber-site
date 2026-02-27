"""Input validation and sanitization for scan targets.

Prevents command injection, path traversal, and malformed input
before any target reaches subprocess or scan tool.
"""

import ipaddress
import re
from typing import Optional

from fastapi import HTTPException

# ── Regex patterns ──────────────────────────────────────────────

PATTERNS = {
    "ipv4": re.compile(r"^(\d{1,3}\.){3}\d{1,3}$"),
    "ipv4_cidr": re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"),
    "ipv6": re.compile(r"^[0-9a-fA-F:]+$"),
    "domain": re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
        r"\.[a-zA-Z]{2,}$"
    ),
    "url": re.compile(r"^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$"),
    "hostname": re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-.]{0,253}[a-zA-Z0-9]$"),
}

# Characters that must never appear in a target string
DANGEROUS_CHARS = [
    ";", "&", "|", "`", "$", "(", ")", "{", "}",
    "<", ">", "\\", "'", '"', "\n", "\r", "\t",
]

DANGEROUS_SEQUENCES = ["&&", "||", ">>", "<<", "..", "~/"]

MAX_TARGET_LENGTH = 253


# ── Sanitization ────────────────────────────────────────────────


def sanitize_target(target: str) -> str:
    """Strip whitespace and reject targets with dangerous characters.

    Returns the cleaned target string.
    Raises ValueError if the target contains shell-dangerous characters.
    """
    if not isinstance(target, str):
        raise ValueError("target must be a string")

    target = target.strip()

    if not target:
        raise ValueError("target is empty")

    if len(target) > MAX_TARGET_LENGTH:
        raise ValueError(f"target too long ({len(target)} > {MAX_TARGET_LENGTH})")

    for seq in DANGEROUS_SEQUENCES:
        if seq in target:
            raise ValueError(f"target contains dangerous sequence: {seq!r}")

    for ch in DANGEROUS_CHARS:
        if ch in target:
            raise ValueError(f"target contains dangerous character: {ch!r}")

    return target


# ── Validation ──────────────────────────────────────────────────


def validate_target(target: str) -> tuple[bool, str, str]:
    """Validate a target string.

    Returns (valid, target_type, reason).
    target_type is one of: ipv4, ipv4_cidr, ipv6, domain, url, hostname.
    reason is "ok" or an error description.
    """
    # 1. Sanitize first
    try:
        target = sanitize_target(target)
    except ValueError as e:
        return False, "", str(e)

    # 2. Try URL (must be before domain/hostname since URLs contain dots)
    if PATTERNS["url"].match(target):
        return True, "url", "ok"

    # 3. Try IPv4 CIDR
    if PATTERNS["ipv4_cidr"].match(target):
        valid, reason = validate_cidr(target)
        if valid:
            return True, "ipv4_cidr", "ok"
        return False, "ipv4_cidr", reason

    # 4. Try IPv4
    if PATTERNS["ipv4"].match(target):
        try:
            ipaddress.ip_address(target)
            return True, "ipv4", "ok"
        except ValueError:
            return False, "ipv4", f"invalid IPv4 address: {target}"

    # 5. Try IPv6
    if PATTERNS["ipv6"].match(target):
        try:
            ipaddress.ip_address(target)
            return True, "ipv6", "ok"
        except ValueError:
            return False, "ipv6", f"invalid IPv6 address: {target}"

    # 6. Try domain
    if PATTERNS["domain"].match(target):
        return True, "domain", "ok"

    # 7. Try hostname
    if PATTERNS["hostname"].match(target):
        return True, "hostname", "ok"

    return False, "", f"target does not match any valid format: {target}"


def validate_port(port: int) -> tuple[bool, str]:
    """Validate a port number (1–65535)."""
    if not isinstance(port, int) or port < 1 or port > 65535:
        return False, f"port must be 1–65535, got {port}"
    return True, "ok"


def validate_cidr(cidr: str) -> tuple[bool, str]:
    """Validate CIDR notation via ipaddress.ip_network()."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True, "ok"
    except ValueError as e:
        return False, f"invalid CIDR: {e}"


def require_valid_target(target: str) -> str:
    """Validate and sanitize a target, raise HTTPException(400) if invalid.

    Returns the sanitized target string on success.
    """
    try:
        target = sanitize_target(target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid target: {e}")

    valid, target_type, reason = validate_target(target)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Invalid target: {reason}")

    return target
