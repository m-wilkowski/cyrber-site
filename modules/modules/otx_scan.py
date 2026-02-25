import os
import re
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_BASE = "https://otx.alienvault.com/api/v1"


def _resolve_to_ip(host: str) -> str:
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


def _otx_get(path: str) -> dict:
    """Make authenticated GET request to OTX API."""
    r = requests.get(
        f"{OTX_BASE}{path}",
        headers={"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"},
        timeout=20,
    )
    r.raise_for_status()
    return r.json()


def scan(target: str) -> dict:
    """Query AlienVault OTX for threat intelligence data."""
    if not OTX_API_KEY:
        return {"skipped": True, "reason": "OTX_API_KEY not set"}

    # Strip protocol/path
    host = re.sub(r'^https?://', '', target)
    host = host.split('/')[0].split(':')[0]
    ip = _resolve_to_ip(host)

    # Determine if target is an IP or domain
    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))

    results = {"domain_general": {}, "domain_malware": {}, "ip_general": {}}

    def fetch_domain_general():
        if is_ip:
            return {}
        return _otx_get(f"/indicators/domain/{host}/general")

    def fetch_domain_malware():
        if is_ip:
            return {}
        return _otx_get(f"/indicators/domain/{host}/malware")

    def fetch_ip_general():
        return _otx_get(f"/indicators/IPv4/{ip}/general")

    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(fetch_domain_general): "domain_general",
                executor.submit(fetch_domain_malware): "domain_malware",
                executor.submit(fetch_ip_general): "ip_general",
            }
            for future in as_completed(futures, timeout=25):
                key = futures[future]
                try:
                    results[key] = future.result()
                except requests.HTTPError as e:
                    status = e.response.status_code if e.response else 0
                    if status == 400:
                        results[key] = {}
                    elif status == 403:
                        return {"target": host, "ip": ip, "skipped": True, "reason": "Invalid OTX API key"}
                    elif status == 429:
                        return {"target": host, "ip": ip, "skipped": True, "reason": "OTX rate limit exceeded"}
                    else:
                        results[key] = {}
                except Exception:
                    results[key] = {}
    except requests.Timeout:
        return {"target": host, "ip": ip, "skipped": False, "error": "Timeout (20s)"}
    except Exception as e:
        return {"target": host, "ip": ip, "skipped": False, "error": str(e)}

    # Merge data from all endpoints
    dg = results["domain_general"]
    dm = results["domain_malware"]
    ig = results["ip_general"]

    # Pulse count (combine domain + IP pulses, deduplicate by pulse ID)
    pulse_ids = set()
    all_pulses = []
    for src in [dg, ig]:
        for pulse in (src.get("pulse_info", {}) or {}).get("pulses", []):
            pid = pulse.get("id", "")
            if pid and pid not in pulse_ids:
                pulse_ids.add(pid)
                all_pulses.append(pulse)
    pulse_count = len(all_pulses)

    # Tags from pulses
    tags = set()
    for pulse in all_pulses:
        for tag in (pulse.get("tags", []) or []):
            if tag:
                tags.add(tag)

    # Malware families
    malware_families = set()
    for entry in (dm.get("data", []) or []):
        family = entry.get("malware_family") or entry.get("hash") or ""
        if family:
            malware_families.add(family)

    # Geo / ASN from IP general
    country = ig.get("country_code", "") or ig.get("country_name", "")
    asn = ig.get("asn", "")
    organization = ""
    if asn and isinstance(asn, str) and " " in asn:
        organization = asn.split(" ", 1)[1]
        asn = asn.split(" ", 1)[0]

    # Validation
    validation = []
    for v in (dg.get("validation", []) or []):
        if isinstance(v, dict):
            validation.append({"source": v.get("source", ""), "name": v.get("name", "")})
        elif isinstance(v, str):
            validation.append({"source": v, "name": v})

    # Related indicators (from pulses, max 10)
    related_indicators = []
    seen_indicators = set()
    for pulse in all_pulses[:5]:
        for ioc in (pulse.get("indicators", []) or [])[:10]:
            ind_val = ioc.get("indicator", "")
            if ind_val and ind_val not in seen_indicators and ind_val != host and ind_val != ip:
                seen_indicators.add(ind_val)
                related_indicators.append({
                    "type": ioc.get("type", ""),
                    "indicator": ind_val,
                    "description": ioc.get("description", "") or pulse.get("name", ""),
                })
            if len(related_indicators) >= 10:
                break
        if len(related_indicators) >= 10:
            break

    # Threat score
    threat_score = min(100, pulse_count * 10)

    return {
        "target": host,
        "ip": ip,
        "skipped": False,
        "pulse_count": pulse_count,
        "threat_score": threat_score,
        "malware_families": sorted(malware_families),
        "tags": sorted(tags),
        "country": country,
        "asn": asn,
        "organization": organization,
        "validation": validation,
        "related_indicators": related_indicators,
    }
