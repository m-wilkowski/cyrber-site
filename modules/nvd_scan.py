import os
import json
import time
import requests

from modules.exploitdb_scan import extract_cves

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
CACHE_PATH = os.getenv("NVD_CACHE_PATH", "/app/data/nvd_cache.json")
CACHE_TTL = 86400  # 24 hours


def _load_cache():
    """Load CVE cache from disk."""
    if not os.path.exists(CACHE_PATH):
        return {}
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[nvd] Failed to load cache: {e}")
        return {}


def _save_cache(cache):
    """Save CVE cache to disk."""
    cache_dir = os.path.dirname(CACHE_PATH)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
    except Exception as e:
        print(f"[nvd] Failed to save cache: {e}")


def _fetch_cve(cve_id, headers):
    """Fetch a single CVE from NVD API v2."""
    try:
        r = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=20,
        )
        if r.status_code == 403:
            print(f"[nvd] Rate limited on {cve_id}")
            return None
        if r.status_code == 404:
            return None
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        return vulns[0].get("cve", {})
    except Exception as e:
        print(f"[nvd] Error fetching {cve_id}: {e}")
        return None


def _parse_cve(cve_data):
    """Parse NVD CVE response into structured dict."""
    cve_id = cve_data.get("id", "")

    # Description (EN)
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # CVSS v3.1 or v2
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    cvss_severity = ""
    cvss_vector = ""

    # Try CVSS v3.1 first
    cvss31 = metrics.get("cvssMetricV31", [])
    if cvss31:
        cvss_data = cvss31[0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore")
        cvss_severity = cvss_data.get("baseSeverity", "").upper()
        cvss_vector = cvss_data.get("vectorString", "")

    # Try CVSS v3.0
    if cvss_score is None:
        cvss30 = metrics.get("cvssMetricV30", [])
        if cvss30:
            cvss_data = cvss30[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity", "").upper()
            cvss_vector = cvss_data.get("vectorString", "")

    # Fallback to CVSS v2
    if cvss_score is None:
        cvss2 = metrics.get("cvssMetricV2", [])
        if cvss2:
            cvss_data = cvss2[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString", "")
            # v2 doesn't have baseSeverity, derive from score
            if cvss_score is not None:
                if cvss_score >= 9.0:
                    cvss_severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    cvss_severity = "HIGH"
                elif cvss_score >= 4.0:
                    cvss_severity = "MEDIUM"
                else:
                    cvss_severity = "LOW"

    if cvss_score is None:
        cvss_score = 0.0
        cvss_severity = "UNKNOWN"

    # CWE IDs
    cwe_ids = []
    weaknesses = cve_data.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    # References (max 5)
    references = []
    exploit_available = False
    for ref in cve_data.get("references", [])[:5]:
        url = ref.get("url", "")
        references.append(url)
        if "exploit-db.com" in url:
            exploit_available = True

    # Also check all references for exploit tag
    for ref in cve_data.get("references", []):
        tags = ref.get("tags", [])
        if "Exploit" in tags:
            exploit_available = True
            break
        if "exploit-db.com" in ref.get("url", ""):
            exploit_available = True
            break

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "cwe_ids": cwe_ids,
        "references": references,
        "published": cve_data.get("published", ""),
        "last_modified": cve_data.get("lastModified", ""),
        "exploit_available": exploit_available,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def nvd_scan(scan_results: dict) -> dict:
    """Lookup CVEs found in scan results against NVD API v2.

    Args:
        scan_results: Combined scan results dict with nuclei, nmap, nikto data.

    Returns:
        Dict with cves list, counts by severity, and lookup metadata.
    """
    cves = extract_cves(scan_results)
    if not cves:
        return {"skipped": True, "reason": "No CVEs found"}

    cache = _load_cache()
    now = time.time()

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    rate_delay = 1.0 if NVD_API_KEY else 6.0

    results = []
    fetched = 0

    for cve_id in cves:
        # Check cache
        cached = cache.get(cve_id)
        if cached and (now - cached.get("_cached_at", 0)) < CACHE_TTL:
            entry = {k: v for k, v in cached.items() if not k.startswith("_")}
            results.append(entry)
            continue

        # Rate limiting
        if fetched > 0:
            time.sleep(rate_delay)

        cve_data = _fetch_cve(cve_id, headers)
        fetched += 1

        if cve_data:
            parsed = _parse_cve(cve_data)
            results.append(parsed)
            # Cache with timestamp
            cache[cve_id] = {**parsed, "_cached_at": now}
        else:
            # Cache miss/error - store minimal entry to avoid re-fetching
            minimal = {
                "cve_id": cve_id,
                "description": "Details unavailable",
                "cvss_score": 0.0,
                "cvss_severity": "UNKNOWN",
                "cvss_vector": "",
                "cwe_ids": [],
                "references": [],
                "published": "",
                "last_modified": "",
                "exploit_available": False,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
            results.append(minimal)
            cache[cve_id] = {**minimal, "_cached_at": now}

    _save_cache(cache)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    results.sort(key=lambda c: (severity_order.get(c["cvss_severity"], 5), -(c.get("cvss_score") or 0)))

    critical_count = sum(1 for c in results if c["cvss_severity"] == "CRITICAL")
    high_count = sum(1 for c in results if c["cvss_severity"] == "HIGH")
    medium_count = sum(1 for c in results if c["cvss_severity"] == "MEDIUM")
    low_count = sum(1 for c in results if c["cvss_severity"] == "LOW")

    return {
        "cves": results,
        "total": len(results),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "fetched_from_api": fetched,
    }
