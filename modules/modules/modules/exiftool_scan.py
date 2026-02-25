"""
Exiftool metadata extraction module for CYRBER.

Downloads images from target URL and extracts EXIF metadata:
GPS coordinates, device info, software, timestamps, author data.
Useful for security awareness demonstrations.
"""

import json
import logging
import os
import re
import subprocess
import tempfile
from urllib.parse import urljoin

log = logging.getLogger("exiftool_scan")

_MAX_IMAGES = 5
_DOWNLOAD_TIMEOUT = 15
_INTERESTING_FIELDS = {
    "GPSLatitude", "GPSLongitude", "GPSPosition",
    "Make", "Model", "Software", "DateTime", "DateTimeOriginal",
    "Artist", "Copyright", "Comment", "UserComment",
    "ImageDescription", "XPAuthor", "XPComment",
}


def scan(target: str) -> dict:
    """Run exiftool metadata extraction on images found at target URL."""
    image_urls = _discover_images(target)
    if not image_urls:
        return {
            "target": target,
            "images_analyzed": 0,
            "findings": [],
            "gps_found": 0,
            "risk_summary": "No images found on target",
        }

    findings = []
    with tempfile.TemporaryDirectory(prefix="exiftool_") as tmpdir:
        for i, url in enumerate(image_urls[:_MAX_IMAGES]):
            filepath = os.path.join(tmpdir, f"img_{i}")
            if not _download_file(url, filepath):
                continue
            meta = _extract_metadata(filepath)
            if meta is None:
                continue
            finding = _build_finding(url, meta)
            findings.append(finding)

    gps_count = sum(1 for f in findings if f.get("gps"))
    return {
        "target": target,
        "images_analyzed": len(findings),
        "findings": findings,
        "gps_found": gps_count,
        "risk_summary": _risk_summary(findings, gps_count),
    }


def _discover_images(target: str) -> list[str]:
    """Fetch target page and extract image URLs (img src, og:image)."""
    try:
        result = subprocess.run(
            ["curl", "-sL", "-m", str(_DOWNLOAD_TIMEOUT), "-A",
             "Mozilla/5.0 CYRBER Scanner", target],
            capture_output=True, text=True, timeout=_DOWNLOAD_TIMEOUT + 5,
        )
        html = result.stdout
        if not html:
            return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    urls = set()
    # <img src="...">
    for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.I):
        urls.add(m.group(1))
    # og:image
    for m in re.finditer(
        r'<meta[^>]+(?:property|name)=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']',
        html, re.I,
    ):
        urls.add(m.group(1))
    # Reverse order og:image (content before property)
    for m in re.finditer(
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']og:image["\']',
        html, re.I,
    ):
        urls.add(m.group(1))

    # Filter to actual image extensions
    image_exts = (".jpg", ".jpeg", ".png", ".gif", ".tiff", ".tif", ".webp", ".bmp", ".heic")
    resolved = []
    for u in urls:
        full = urljoin(target, u)
        if any(full.lower().split("?")[0].endswith(ext) for ext in image_exts):
            resolved.append(full)

    return resolved[:_MAX_IMAGES]


def _download_file(url: str, filepath: str) -> bool:
    """Download a file using curl."""
    try:
        result = subprocess.run(
            ["curl", "-sL", "-m", str(_DOWNLOAD_TIMEOUT), "-o", filepath, url],
            capture_output=True, timeout=_DOWNLOAD_TIMEOUT + 5,
        )
        return result.returncode == 0 and os.path.exists(filepath) and os.path.getsize(filepath) > 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _extract_metadata(filepath: str) -> dict | None:
    """Run exiftool -json on a file and return parsed metadata."""
    try:
        result = subprocess.run(
            ["exiftool", "-json", filepath],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        return data[0] if data else None
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return None
    except Exception as e:
        log.warning("[exiftool] Error extracting metadata: %s", e)
        return None


def _build_finding(url: str, meta: dict) -> dict:
    """Build a finding dict from raw exiftool metadata."""
    gps = {}
    lat = meta.get("GPSLatitude") or meta.get("GPSPosition", "").split(",")[0].strip()
    lon = meta.get("GPSLongitude")
    if not lon and "," in meta.get("GPSPosition", ""):
        lon = meta.get("GPSPosition", "").split(",")[1].strip()
    if lat and lon:
        gps = {"latitude": str(lat), "longitude": str(lon)}

    make = meta.get("Make", "")
    model = meta.get("Model", "")
    device = f"{make} {model}".strip() if (make or model) else ""

    software = meta.get("Software", "")
    datetime_val = meta.get("DateTimeOriginal") or meta.get("DateTime", "")
    artist = meta.get("Artist") or meta.get("XPAuthor", "")
    copyright_val = meta.get("Copyright", "")
    comment = meta.get("Comment") or meta.get("UserComment") or meta.get("ImageDescription", "")

    # Risk assessment
    if gps:
        risk = "high"
    elif device or software or artist:
        risk = "medium"
    else:
        risk = "low"

    finding = {
        "url": url,
        "gps": gps,
        "device": device,
        "software": software,
        "datetime": str(datetime_val),
        "artist": artist,
        "copyright": copyright_val,
        "comment": str(comment)[:200] if comment else "",
        "risk": risk,
    }
    # Drop empty fields
    return {k: v for k, v in finding.items() if v or k in ("url", "risk")}


def _risk_summary(findings: list[dict], gps_count: int) -> str:
    """Generate human-readable risk summary."""
    if not findings:
        return "No metadata extracted from images"

    parts = []
    if gps_count:
        parts.append(f"GPS coordinates found in {gps_count} image(s) — physical location exposed")
    device_count = sum(1 for f in findings if f.get("device"))
    if device_count:
        parts.append(f"Device info leaked in {device_count} image(s)")
    artist_count = sum(1 for f in findings if f.get("artist"))
    if artist_count:
        parts.append(f"Author/artist name found in {artist_count} image(s)")

    if not parts:
        return "Images found but no sensitive metadata detected"
    return "; ".join(parts)
