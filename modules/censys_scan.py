import os
import re
import socket
import requests

CENSYS_API_TOKEN = os.getenv("CENSYS_API_TOKEN", "")
CENSYS_BASE = "https://search.censys.io/api/v2"


def _resolve_to_ip(host: str) -> str:
    """Resolve hostname to IP — Censys API accepts only IPs."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


def scan(target: str) -> dict:
    """Query Censys Search API v2 for host intelligence."""
    if not CENSYS_API_TOKEN:
        return {"target": target, "skipped": True, "reason": "CENSYS_API_TOKEN not set"}

    # Strip protocol/path, extract host
    host = re.sub(r'^https?://', '', target)
    host = host.split('/')[0].split(':')[0]

    # Resolve to IP
    ip = _resolve_to_ip(host)

    try:
        r = requests.get(
            f"{CENSYS_BASE}/hosts/{ip}",
            headers={"Authorization": f"Bearer {CENSYS_API_TOKEN}"},
            timeout=30,
        )

        if r.status_code == 404:
            return {"target": host, "ip": ip, "found": False, "reason": "Host not found in Censys"}

        r.raise_for_status()
        data = r.json().get("result", {})

        # Autonomous system
        asys = data.get("autonomous_system", {}) or {}
        autonomous_system = {
            "asn": asys.get("asn"),
            "name": asys.get("name", ""),
            "description": asys.get("description", ""),
            "bgp_prefix": asys.get("bgp_prefix", ""),
            "country_code": asys.get("country_code", ""),
        }

        # Services (ports)
        services = []
        for svc in data.get("services", []):
            svc_info = {
                "port": svc.get("port"),
                "transport_protocol": svc.get("transport_protocol", "TCP"),
                "service_name": svc.get("service_name", ""),
                "product": "",
                "version": "",
                "banner": "",
            }
            # Extract software info
            sw = svc.get("software", [])
            if sw:
                svc_info["product"] = sw[0].get("product", "")
                svc_info["version"] = sw[0].get("version", "")
            # Extract banner snippet from common protocols
            if svc.get("banner"):
                svc_info["banner"] = (svc["banner"] or "")[:200]
            elif svc.get("http", {}).get("response", {}).get("headers", {}).get("server"):
                svc_info["banner"] = svc["http"]["response"]["headers"]["server"]
            services.append(svc_info)

        # Location
        location = data.get("location", {}) or {}
        geo = {
            "country": location.get("country", ""),
            "country_code": location.get("country_code", ""),
            "city": location.get("city", ""),
            "province": location.get("province", ""),
            "coordinates": location.get("coordinates", {}),
        }

        return {
            "target": host,
            "found": True,
            "ip": data.get("ip", ip),
            "autonomous_system": autonomous_system,
            "services_count": len(services),
            "services": services,
            "labels": data.get("labels", []),
            "geo": geo,
            "os": (data.get("operating_system", {}) or {}).get("product", ""),
            "last_updated_at": data.get("last_updated_at", ""),
        }

    except requests.Timeout:
        return {"target": host, "ip": ip, "found": False, "error": "Timeout (30s)"}
    except requests.HTTPError as e:
        status = e.response.status_code if e.response else 0
        if status == 401:
            return {"target": host, "ip": ip, "found": False, "error": "Invalid Censys API token"}
        if status == 429:
            return {"target": host, "ip": ip, "found": False, "error": "Censys rate limit exceeded"}
        return {"target": host, "ip": ip, "found": False, "error": f"Censys API error ({status})"}
    except Exception as e:
        return {"target": host, "ip": ip if 'ip' in dir() else host, "found": False, "error": str(e)}
