import os
import re
import socket
import requests

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

CATEGORY_MAP = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def _resolve_to_ip(host: str) -> str:
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


def scan(target: str) -> dict:
    """Query AbuseIPDB for IP reputation data."""
    if not ABUSEIPDB_API_KEY:
        return {"skipped": True, "reason": "ABUSEIPDB_API_KEY not set"}

    # Strip protocol/path
    host = re.sub(r'^https?://', '', target)
    host = host.split('/')[0].split(':')[0]

    ip = _resolve_to_ip(host)

    try:
        r = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": "true",
            },
            timeout=15,
        )

        if r.status_code == 401:
            return {"target": host, "ip": ip, "skipped": True, "reason": "Invalid API key"}
        if r.status_code == 422:
            return {"target": host, "ip": ip, "skipped": True, "reason": "Invalid IP address"}
        if r.status_code == 429:
            return {"target": host, "ip": ip, "skipped": True, "reason": "Rate limit exceeded"}

        r.raise_for_status()
        data = r.json().get("data", {})

        # Map category numbers to names
        raw_categories = data.get("reports", [])
        category_ids = set()
        for report in raw_categories:
            for cat_id in (report.get("categories", []) or []):
                category_ids.add(cat_id)
        categories = [CATEGORY_MAP.get(cid, f"Category {cid}") for cid in sorted(category_ids)]

        return {
            "target": host,
            "ip": data.get("ipAddress", ip),
            "skipped": False,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt", ""),
            "isp": data.get("isp", ""),
            "usage_type": data.get("usageType", ""),
            "domain": data.get("domain", ""),
            "country_code": data.get("countryCode", ""),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "categories": categories,
            "num_distinct_users": data.get("numDistinctUsers", 0),
        }

    except requests.Timeout:
        return {"target": host, "ip": ip, "skipped": False, "error": "Timeout (15s)"}
    except requests.HTTPError as e:
        status = e.response.status_code if e.response else 0
        return {"target": host, "ip": ip, "skipped": False, "error": f"AbuseIPDB API error ({status})"}
    except Exception as e:
        return {"target": host, "ip": ip, "skipped": False, "error": str(e)}
