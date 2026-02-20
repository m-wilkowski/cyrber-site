import os
import re
import socket
import requests

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
IPINFO_BASE = "https://ipinfo.io"


def _resolve_to_ip(host: str) -> str:
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


def scan(target: str) -> dict:
    """Query ipinfo.io for IP enrichment data."""
    # Strip protocol/path
    host = re.sub(r'^https?://', '', target)
    host = host.split('/')[0].split(':')[0]

    ip = _resolve_to_ip(host)
    params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}

    try:
        # Main endpoint
        r = requests.get(
            f"{IPINFO_BASE}/{ip}",
            params=params,
            timeout=15,
        )

        if r.status_code == 429:
            return {"target": host, "ip": ip, "found": False, "error": "IPinfo rate limit exceeded"}

        r.raise_for_status()
        data = r.json()

        # Parse org field "AS13335 Cloudflare, Inc." → asn + org
        org_raw = data.get("org", "")
        asn = ""
        org = org_raw
        if org_raw.startswith("AS"):
            parts = org_raw.split(" ", 1)
            asn = parts[0]
            org = parts[1] if len(parts) > 1 else ""

        # Parse loc "37.7749,-122.4194" → lat, lon
        loc_raw = data.get("loc", "")
        lat, lon = "", ""
        if loc_raw and "," in loc_raw:
            parts = loc_raw.split(",")
            lat = parts[0]
            lon = parts[1]

        result = {
            "target": host,
            "found": True,
            "ip": data.get("ip", ip),
            "hostname": data.get("hostname", ""),
            "org": org,
            "asn": asn,
            "country": data.get("country", ""),
            "region": data.get("region", ""),
            "city": data.get("city", ""),
            "loc": {"lat": lat, "lon": lon},
            "timezone": data.get("timezone", ""),
            "postal": data.get("postal", ""),
        }

        # Privacy endpoint (requires paid token)
        if IPINFO_TOKEN:
            try:
                pr = requests.get(
                    f"{IPINFO_BASE}/{ip}/privacy",
                    params={"token": IPINFO_TOKEN},
                    timeout=10,
                )
                if pr.status_code == 200:
                    privacy = pr.json()
                    result["is_vpn"] = privacy.get("vpn", False)
                    result["is_proxy"] = privacy.get("proxy", False)
                    result["is_tor"] = privacy.get("tor", False)
                    result["is_datacenter"] = privacy.get("hosting", False)
                    result["is_relay"] = privacy.get("relay", False)
            except Exception:
                pass

        return result

    except requests.Timeout:
        return {"target": host, "ip": ip, "found": False, "error": "Timeout (15s)"}
    except requests.HTTPError as e:
        status = e.response.status_code if e.response else 0
        return {"target": host, "ip": ip, "found": False, "error": f"IPinfo API error ({status})"}
    except Exception as e:
        return {"target": host, "ip": ip, "found": False, "error": str(e)}
