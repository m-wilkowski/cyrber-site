# Shodan - requires paid plan
# Replaced by censys_scan.py (free tier available)
#
# import os
# import re
# import requests
#
# SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
# SHODAN_BASE = "https://api.shodan.io"
#
#
# def scan(target: str) -> dict:
#     """Query Shodan API for host intelligence (ports, CVEs, geo, org)."""
#     if not SHODAN_API_KEY:
#         return {"target": target, "skipped": True, "reason": "SHODAN_API_KEY not set"}
#
#     host = re.sub(r'^https?://', '', target)
#     host = host.split('/')[0].split(':')[0]
#
#     try:
#         r = requests.get(
#             f"{SHODAN_BASE}/shodan/host/{host}",
#             params={"key": SHODAN_API_KEY},
#             timeout=30,
#         )
#
#         if r.status_code == 404:
#             return {"target": host, "found": False, "reason": "Host not found in Shodan"}
#
#         r.raise_for_status()
#         data = r.json()
#
#         ports = []
#         cves = set()
#         for item in data.get("data", []):
#             port_info = {
#                 "port": item.get("port"),
#                 "transport": item.get("transport", "tcp"),
#                 "product": item.get("product", ""),
#                 "version": item.get("version", ""),
#                 "banner": (item.get("data", "") or "")[:200],
#             }
#             ports.append(port_info)
#             for cve in item.get("vulns", {}).keys():
#                 cves.add(cve)
#
#         geo = {
#             "country": data.get("country_name", ""),
#             "country_code": data.get("country_code", ""),
#             "city": data.get("city", ""),
#             "latitude": data.get("latitude"),
#             "longitude": data.get("longitude"),
#         }
#
#         return {
#             "target": host, "found": True,
#             "ip": data.get("ip_str", host),
#             "org": data.get("org", ""),
#             "isp": data.get("isp", ""),
#             "os": data.get("os", ""),
#             "hostnames": data.get("hostnames", []),
#             "domains": data.get("domains", []),
#             "ports_count": len(ports), "ports": ports,
#             "cves_count": len(cves), "cves": sorted(cves),
#             "geo": geo,
#             "last_update": data.get("last_update", ""),
#         }
#
#     except requests.Timeout:
#         return {"target": host, "found": False, "error": "Timeout (30s)"}
#     except requests.HTTPError as e:
#         status = e.response.status_code if e.response else 0
#         if status == 401:
#             return {"target": host, "found": False, "error": "Invalid Shodan API key"}
#         if status == 429:
#             return {"target": host, "found": False, "error": "Shodan rate limit exceeded"}
#         return {"target": host, "found": False, "error": f"Shodan API error ({status})"}
#     except Exception as e:
#         return {"target": host, "found": False, "error": str(e)}
