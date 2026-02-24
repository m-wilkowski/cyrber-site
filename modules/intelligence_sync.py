"""
CYRBER Intelligence Sync — KEV / EPSS / NVD enrichment.
Pobiera dane z publicznych baz podatności i zapisuje do cache w PostgreSQL.
"""
import time
import logging
import requests

from modules.database import (
    upsert_kev_entries, upsert_epss_entries, upsert_cve_entry,
    get_intel_enrichment, save_intel_sync_log,
)

log = logging.getLogger("cyrber.intel")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

REQUEST_TIMEOUT = 60


def sync_kev() -> int:
    """Download full CISA KEV catalog and upsert to kev_cache."""
    t0 = time.time()
    try:
        resp = requests.get(KEV_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        count = upsert_kev_entries(vulns)
        duration = time.time() - t0
        save_intel_sync_log("KEV", "success", count, duration)
        log.info(f"KEV sync complete: {count} entries in {duration:.1f}s")
        return count
    except Exception as e:
        duration = time.time() - t0
        save_intel_sync_log("KEV", "error", 0, duration, str(e))
        log.error(f"KEV sync failed: {e}")
        raise


def sync_epss(cve_ids: list[str]) -> int:
    """Fetch EPSS scores for given CVE IDs in batches of 100."""
    if not cve_ids:
        save_intel_sync_log("EPSS", "success", 0, 0.0)
        return 0

    t0 = time.time()
    total = 0
    try:
        for i in range(0, len(cve_ids), 100):
            batch = cve_ids[i:i + 100]
            params = {"cve": ",".join(batch)}
            resp = requests.get(EPSS_URL, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            entries = data.get("data", [])
            count = upsert_epss_entries(entries)
            total += count
            # Respect rate limits
            if i + 100 < len(cve_ids):
                time.sleep(0.5)
        duration = time.time() - t0
        save_intel_sync_log("EPSS", "success", total, duration)
        log.info(f"EPSS sync complete: {total} entries in {duration:.1f}s")
        return total
    except Exception as e:
        duration = time.time() - t0
        save_intel_sync_log("EPSS", "error", total, duration, str(e))
        log.error(f"EPSS sync failed: {e}")
        raise


def sync_nvd_cve(cve_id: str) -> dict | None:
    """Fetch single CVE from NVD API 2.0 and cache it."""
    t0 = time.time()
    try:
        resp = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_item = vulns[0].get("cve", {})
        metrics = cve_item.get("metrics", {})

        # Extract CVSS — prefer v3.1, fallback v3.0, then v2
        cvss_score = None
        cvss_vector = None
        for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(ver, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                break

        # Extract description (English preferred)
        desc = ""
        for d in cve_item.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # Extract CWE
        cwe_id = None
        for weakness in cve_item.get("weaknesses", []):
            for wd in weakness.get("description", []):
                val = wd.get("value", "")
                if val.startswith("CWE-"):
                    cwe_id = val
                    break
            if cwe_id:
                break

        # Extract references
        refs = [r.get("url") for r in cve_item.get("references", []) if r.get("url")]

        entry = {
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "description": desc,
            "published": cve_item.get("published"),
            "last_modified": cve_item.get("lastModified"),
            "cwe_id": cwe_id,
            "references": refs[:20],
        }
        upsert_cve_entry(cve_id, entry)

        duration = time.time() - t0
        save_intel_sync_log("NVD", "success", 1, duration)
        return entry
    except Exception as e:
        duration = time.time() - t0
        save_intel_sync_log("NVD", "error", 0, duration, str(e))
        log.error(f"NVD sync failed for {cve_id}: {e}")
        raise


def enrich_finding(cve_id: str) -> dict:
    """Get enrichment data for a CVE. Uses cache, falls back to NVD on-demand."""
    result = get_intel_enrichment(cve_id)

    # If no CVE data in cache, fetch on-demand from NVD
    if result.get("cvss_score") is None:
        try:
            sync_nvd_cve(cve_id)
            result = get_intel_enrichment(cve_id)
        except Exception:
            pass  # Return whatever we have

    # Calculate priority
    cvss = result.get("cvss_score") or 0
    epss = result.get("epss_score") or 0
    kev = result.get("in_kev", False)
    result["priority"] = calculate_priority(cvss, epss, kev)

    return result


def calculate_priority(cvss: float, epss: float, kev: bool) -> str:
    """Calculate remediation priority based on CVSS + EPSS + KEV."""
    if kev:
        return "CRITICAL"
    if cvss >= 9.0:
        return "CRITICAL"
    if epss > 0.7:
        if cvss >= 7.0:
            return "CRITICAL"
        return "HIGH"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0:
        return "LOW"
    return "INFO"
