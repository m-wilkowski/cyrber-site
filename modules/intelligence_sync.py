"""
CYRBER Intelligence Sync — KEV / EPSS / NVD / ATT&CK / CAPEC / EUVD / Shodan / URLhaus / GreyNoise enrichment.
Pobiera dane z publicznych baz podatności i zapisuje do cache w PostgreSQL.
"""
import time
import logging
import requests
from datetime import datetime, timedelta

from modules.database import (
    upsert_kev_entries, upsert_epss_entries, upsert_cve_entry,
    get_intel_enrichment, save_intel_sync_log,
    upsert_attack_techniques, upsert_attack_tactics,
    upsert_attack_mitigations, upsert_attack_mitigation_links,
    upsert_cwe_attack_map, upsert_euvd_entries,
    get_techniques_for_cwe, get_euvd_by_cve,
    upsert_shodan_cache, get_shodan_cache,
    upsert_urlhaus_cache, get_urlhaus_cache,
    upsert_greynoise_cache, get_greynoise_cache,
)

log = logging.getLogger("cyrber.intel")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CAPEC_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
EUVD_URL = "https://euvdservices.enisa.europa.eu/api/search"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1"
GREYNOISE_API_URL = "https://api.greynoise.io/v3/community"

REQUEST_TIMEOUT = 60
ATTACK_TIMEOUT = 120  # enterprise-attack.json is ~30MB


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


## ── ATT&CK Sync ──────────────────────────────────────────

def _extract_external_id(obj: dict, source_name: str) -> str | None:
    """Extract external_id from STIX external_references for a given source."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name:
            return ref.get("external_id")
    return None

def _extract_url(obj: dict, source_name: str) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name:
            return ref.get("url")
    return None


def sync_attack() -> dict:
    """Download MITRE ATT&CK Enterprise STIX bundle, parse and upsert techniques/tactics/mitigations."""
    t0 = time.time()
    try:
        log.info("ATT&CK sync: downloading enterprise-attack.json...")
        resp = requests.get(ATTACK_URL, timeout=ATTACK_TIMEOUT)
        resp.raise_for_status()
        bundle = resp.json()
        objects = bundle.get("objects", [])
        log.info(f"ATT&CK sync: {len(objects)} STIX objects downloaded")

        # Build ID→object map for relationship resolution
        id_map = {obj.get("id"): obj for obj in objects}

        techniques = []
        tactics = []
        mitigations = []
        mitigation_links = []

        for obj in objects:
            obj_type = obj.get("type")
            revoked = obj.get("revoked", False)
            deprecated = obj.get("x_mitre_deprecated", False)

            if obj_type == "attack-pattern":
                tid = _extract_external_id(obj, "mitre-attack")
                if not tid:
                    continue
                url = _extract_url(obj, "mitre-attack") or f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                # Extract tactics from kill_chain_phases
                obj_tactics = []
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        obj_tactics.append(phase.get("phase_name"))
                # Determine parent
                parent_id = None
                is_sub = obj.get("x_mitre_is_subtechnique", False)
                if is_sub and "." in tid:
                    parent_id = tid.rsplit(".", 1)[0]

                techniques.append({
                    "technique_id": tid,
                    "name": obj.get("name", ""),
                    "description": (obj.get("description", "") or "")[:5000],
                    "url": url,
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": obj_tactics,
                    "data_sources": obj.get("x_mitre_data_sources", []),
                    "detection": (obj.get("x_mitre_detection", "") or "")[:3000],
                    "is_subtechnique": is_sub,
                    "parent_id": parent_id,
                    "deprecated": revoked or deprecated,
                })

            elif obj_type == "x-mitre-tactic":
                tac_id = _extract_external_id(obj, "mitre-attack")
                if not tac_id:
                    continue
                short_name = obj.get("x_mitre_shortname", "")
                url = _extract_url(obj, "mitre-attack") or f"https://attack.mitre.org/tactics/{tac_id}/"
                tactics.append({
                    "tactic_id": tac_id,
                    "short_name": short_name,
                    "name": obj.get("name", ""),
                    "description": (obj.get("description", "") or "")[:3000],
                    "url": url,
                })

            elif obj_type == "course-of-action":
                mit_id = _extract_external_id(obj, "mitre-attack")
                if not mit_id:
                    continue
                url = _extract_url(obj, "mitre-attack") or f"https://attack.mitre.org/mitigations/{mit_id}/"
                mitigations.append({
                    "mitigation_id": mit_id,
                    "name": obj.get("name", ""),
                    "description": (obj.get("description", "") or "")[:3000],
                    "url": url,
                })

            elif obj_type == "relationship" and obj.get("relationship_type") == "mitigates":
                src_ref = obj.get("source_ref", "")
                tgt_ref = obj.get("target_ref", "")
                src_obj = id_map.get(src_ref, {})
                tgt_obj = id_map.get(tgt_ref, {})
                mit_id = _extract_external_id(src_obj, "mitre-attack")
                tech_id = _extract_external_id(tgt_obj, "mitre-attack")
                if mit_id and tech_id and not obj.get("revoked"):
                    mitigation_links.append({
                        "mitigation_id": mit_id,
                        "technique_id": tech_id,
                        "description": (obj.get("description", "") or "")[:2000],
                    })

        # Upsert to DB
        t_count = upsert_attack_techniques(techniques)
        tac_count = upsert_attack_tactics(tactics)
        m_count = upsert_attack_mitigations(mitigations)
        ml_count = upsert_attack_mitigation_links(mitigation_links)

        total = t_count + tac_count + m_count + ml_count
        duration = time.time() - t0
        save_intel_sync_log("ATT&CK", "success", total, duration)
        log.info(f"ATT&CK sync complete: {t_count} techniques, {tac_count} tactics, "
                 f"{m_count} mitigations, {ml_count} links in {duration:.1f}s")
        return {
            "techniques": t_count, "tactics": tac_count,
            "mitigations": m_count, "mitigation_links": ml_count,
        }
    except Exception as e:
        duration = time.time() - t0
        save_intel_sync_log("ATT&CK", "error", 0, duration, str(e))
        log.error(f"ATT&CK sync failed: {e}")
        raise


def sync_capec_cwe_map() -> int:
    """Download CAPEC STIX bundle, extract CWE→CAPEC→ATT&CK technique mappings."""
    t0 = time.time()
    try:
        log.info("CAPEC-CWE-MAP sync: downloading stix-capec.json...")
        resp = requests.get(CAPEC_URL, timeout=ATTACK_TIMEOUT)
        resp.raise_for_status()
        bundle = resp.json()
        objects = bundle.get("objects", [])

        mappings = []
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_capec_status") == "Deprecated":
                continue

            refs = obj.get("external_references", [])
            capec_id = None
            cwe_ids = []
            technique_ids = []

            for ref in refs:
                src = ref.get("source_name", "")
                ext_id = ref.get("external_id", "")
                if src == "capec" and ext_id:
                    capec_id = ext_id  # CAPEC-66
                elif src == "cwe" and ext_id:
                    cwe_ids.append(ext_id)  # CWE-89
                elif src == "ATTACK" and ext_id:
                    technique_ids.append(ext_id)  # T1190

            if not capec_id or not cwe_ids or not technique_ids:
                continue

            # Cross-product CWE × technique
            for cwe_id in cwe_ids:
                for tech_id in technique_ids:
                    mappings.append({
                        "cwe_id": cwe_id,
                        "capec_id": capec_id,
                        "technique_id": tech_id,
                    })

        count = upsert_cwe_attack_map(mappings)
        duration = time.time() - t0
        save_intel_sync_log("CAPEC-CWE-MAP", "success", count, duration)
        log.info(f"CAPEC-CWE-MAP sync complete: {count} mappings in {duration:.1f}s")
        return count
    except Exception as e:
        duration = time.time() - t0
        save_intel_sync_log("CAPEC-CWE-MAP", "error", 0, duration, str(e))
        log.error(f"CAPEC-CWE-MAP sync failed: {e}")
        raise


def sync_euvd(days_back: int = 30) -> int:
    """Sync ENISA EU Vulnerability Database entries."""
    t0 = time.time()
    try:
        to_date = datetime.utcnow().strftime("%Y-%m-%d")
        from_date = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%d")
        log.info(f"EUVD sync: fetching {from_date} to {to_date}...")

        total = 0
        page = 0
        page_size = 100

        while True:
            params = {
                "fromDate": from_date,
                "toDate": to_date,
                "page": page,
                "size": page_size,
            }
            resp = requests.get(EUVD_URL, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            items = data.get("items", [])

            if not items:
                break

            entries = []
            for item in items:
                euvd_id = item.get("id")
                if not euvd_id:
                    continue
                # Parse aliases — sometimes newline-separated string
                raw_aliases = item.get("aliases", "")
                if isinstance(raw_aliases, str):
                    aliases = [a.strip() for a in raw_aliases.split("\n") if a.strip()]
                elif isinstance(raw_aliases, list):
                    aliases = raw_aliases
                else:
                    aliases = []

                entries.append({
                    "euvd_id": euvd_id,
                    "description": (item.get("description", "") or "")[:5000],
                    "date_published": item.get("datePublished"),
                    "date_updated": item.get("dateUpdated"),
                    "base_score": item.get("baseScore"),
                    "base_score_version": item.get("baseScoreVersion"),
                    "base_score_vector": item.get("baseScoreVector"),
                    "aliases": aliases,
                    "epss": item.get("epss"),
                    "vendor": item.get("enisaIdVendor"),
                    "product": item.get("enisaIdProduct"),
                    "references": item.get("references"),
                })

            count = upsert_euvd_entries(entries)
            total += count

            # Check if more pages
            api_total = data.get("total", 0)
            fetched = (page + 1) * page_size
            if fetched >= api_total or len(items) < page_size:
                break

            page += 1
            time.sleep(0.5)  # Rate limit

        duration = time.time() - t0
        save_intel_sync_log("EUVD", "success", total, duration)
        log.info(f"EUVD sync complete: {total} entries in {duration:.1f}s")
        return total
    except Exception as e:
        duration = time.time() - t0
        save_intel_sync_log("EUVD", "error", 0, duration, str(e))
        log.error(f"EUVD sync failed: {e}")
        raise


def enrich_finding(cve_id: str) -> dict:
    """Get enrichment data for a CVE. Uses cache, falls back to NVD on-demand.
    Includes ATT&CK techniques (via CWE) and EUVD lookup."""
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

    # ATT&CK techniques via CWE→CAPEC→technique mapping
    cwe_id = result.get("cwe_id")
    if cwe_id:
        try:
            techniques = get_techniques_for_cwe(cwe_id)
            result["attack_techniques"] = techniques[:5]
        except Exception:
            result["attack_techniques"] = []
    else:
        result["attack_techniques"] = []

    # EUVD lookup
    try:
        euvd = get_euvd_by_cve(cve_id)
        if euvd:
            result["in_euvd"] = True
            result["euvd_id"] = euvd["euvd_id"]
            result["euvd_url"] = euvd["url"]
        else:
            result["in_euvd"] = False
    except Exception:
        result["in_euvd"] = False

    # MISP lookup
    try:
        from modules.database import get_misp_by_cve
        misp = get_misp_by_cve(cve_id)
        if misp:
            result["in_misp"] = True
            result["misp_event_count"] = misp["event_count"]
            result["misp_events"] = misp["events"][:3]
        else:
            result["in_misp"] = False
            result["misp_event_count"] = 0
            result["misp_events"] = []
    except Exception:
        result["in_misp"] = False
        result["misp_event_count"] = 0
        result["misp_events"] = []

    # URLhaus lookup (by CVE in host field — rare, but check)
    try:
        urlhaus = get_urlhaus_cache(cve_id)
        result["in_urlhaus"] = bool(urlhaus and urlhaus.get("urls_count", 0) > 0)
    except Exception:
        result["in_urlhaus"] = False

    return result


def enrich_target(target: str) -> dict:
    """Enrich a scan target (IP or hostname) with Shodan, URLhaus, GreyNoise.
    On-demand: fetches live data if not cached."""
    import ipaddress
    result = {}

    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        pass

    # Shodan InternetDB (IP only)
    if is_ip:
        try:
            shodan = get_shodan_cache(target)
            if not shodan:
                shodan = sync_shodan(target)
            if shodan:
                result["shodan"] = shodan
        except Exception:
            pass

    # URLhaus (IP or hostname)
    try:
        urlhaus = get_urlhaus_cache(target)
        if not urlhaus:
            urlhaus = sync_urlhaus(target)
        if urlhaus:
            result["urlhaus"] = urlhaus
            result["in_urlhaus"] = urlhaus.get("urls_count", 0) > 0
        else:
            result["in_urlhaus"] = False
    except Exception:
        result["in_urlhaus"] = False

    # GreyNoise (IP only)
    if is_ip:
        try:
            gn = get_greynoise_cache(target)
            if not gn:
                gn = sync_greynoise(target)
            if gn:
                result["greynoise"] = gn
                result["greynoise_classification"] = gn.get("classification", "unknown")
            else:
                result["greynoise_classification"] = "unknown"
        except Exception:
            result["greynoise_classification"] = "unknown"

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


# ── Targeted Retest ─────────────────────────────────────

# Map finding module → scan function import path
_MODULE_SCANNERS = {
    "nuclei":   "modules.nuclei_scan:scan",
    "nmap":     "modules.nmap_scan:scan",
    "testssl":  "modules.testssl_scan:scan",
    "sqlmap":   "modules.sqlmap_scan:scan",
    "nikto":    "modules.nikto_scan:scan",
    "zap":      "modules.zap_scan:zap_scan",
    "wpscan":   "modules.wpscan_scan:wpscan_scan",
    "wapiti":   "modules.wapiti_scan:wapiti_scan",
    "sslyze":   "modules.sslyze_scan:sslyze_scan",
    "gobuster": "modules.gobuster_scan:scan",
    "whatweb":  "modules.whatweb_scan:scan",
    "joomscan": "modules.joomscan_scan:joomscan_scan",
    "certipy":  "modules.certipy_scan:run_certipy",
}


def _import_scanner(module_path: str):
    """Dynamic import: 'modules.foo:scan' → function."""
    mod_path, func_name = module_path.rsplit(":", 1)
    import importlib
    mod = importlib.import_module(mod_path)
    return getattr(mod, func_name)


def _check_finding_in_results(result: dict, finding_name: str) -> tuple[bool, str]:
    """Check if a finding name appears in scan results. Returns (still_vulnerable, evidence)."""
    if not result or not isinstance(result, dict):
        return False, "Empty scan result"

    # Check raw output text for finding name
    raw_str = str(result).lower()
    finding_lower = finding_name.lower()

    # Direct name match in raw output
    if finding_lower in raw_str:
        return True, f"Finding '{finding_name}' still present in scan output"

    # Check findings/vulnerabilities lists
    for key in ["findings", "vulnerabilities", "results", "issues"]:
        items = result.get(key, [])
        if isinstance(items, list):
            for item in items:
                item_str = str(item).lower()
                if finding_lower in item_str:
                    return True, f"Finding matched in {key}: {str(item)[:200]}"

    # Check specific module result patterns
    if result.get("vulnerable"):
        return True, "Scanner reports target still vulnerable"

    # Check CVE patterns
    import re
    cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", finding_name, re.IGNORECASE)
    if cve_match:
        cve_id = cve_match.group(1).upper()
        if cve_id.lower() in raw_str:
            return True, f"{cve_id} still detected in scan output"

    return False, "Finding not detected in re-scan output"


def run_targeted_retest(finding_name: str, target: str, module: str) -> dict:
    """Run a targeted re-scan for a specific finding and check if it's still present."""
    t0 = time.time()

    # Select scanner
    scanner_path = _MODULE_SCANNERS.get(module)
    if not scanner_path:
        # Fallback: nuclei generic scan
        scanner_path = "modules.nuclei_scan:scan"

    try:
        scanner_fn = _import_scanner(scanner_path)
    except Exception as e:
        return {
            "still_vulnerable": False,
            "evidence": f"Could not load scanner for module '{module}': {e}",
            "scanner_used": scanner_path,
            "duration": round(time.time() - t0, 2),
            "error": True,
        }

    # Run scan
    try:
        result = scanner_fn(target)
    except Exception as e:
        return {
            "still_vulnerable": False,
            "evidence": f"Scanner execution failed: {e}",
            "scanner_used": scanner_path,
            "duration": round(time.time() - t0, 2),
            "error": True,
        }

    # Analyze results
    still_vulnerable, evidence = _check_finding_in_results(result, finding_name)

    return {
        "still_vulnerable": still_vulnerable,
        "evidence": evidence,
        "scanner_used": scanner_path,
        "duration": round(time.time() - t0, 2),
        "error": False,
    }


# ── Shodan InternetDB ────────────────────────────────────────────

def sync_shodan(ip: str) -> dict | None:
    """Fetch IP data from Shodan InternetDB (free, no API key).
    Returns cached dict or None on error."""
    t0 = time.time()
    try:
        resp = requests.get(f"{SHODAN_INTERNETDB_URL}/{ip}", timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            # No data for this IP — cache empty result
            data = {"ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
            upsert_shodan_cache(ip, data)
            return data
        resp.raise_for_status()
        data = resp.json()
        result = {
            "ports": data.get("ports", []),
            "cpes": data.get("cpes", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "vulns": data.get("vulns", []),
        }
        upsert_shodan_cache(ip, result)
        duration = time.time() - t0
        log.info(f"Shodan InternetDB: {ip} — {len(result['ports'])} ports, {len(result['vulns'])} vulns in {duration:.1f}s")
        return result
    except Exception as exc:
        log.warning(f"Shodan InternetDB lookup failed for {ip}: {exc}")
        return None


# ── URLhaus ───────────────────────────────────────────────────────

def sync_urlhaus(host: str) -> dict | None:
    """Lookup host in URLhaus (free, no API key).
    Works for both IP and domain."""
    t0 = time.time()
    try:
        resp = requests.post(
            f"{URLHAUS_API_URL}/host/",
            data={"host": host},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") == "no_results":
            result = {"urls_count": 0, "blacklisted": False, "tags": [], "urls": []}
            upsert_urlhaus_cache(host, result)
            return result

        urls_raw = data.get("urls", [])
        result = {
            "urls_count": int(data.get("urls_online", 0) or len(urls_raw)),
            "blacklisted": data.get("blacklists", {}).get("surbl", "") != "" or
                           data.get("blacklists", {}).get("spamhaus_dbl", "") != "",
            "tags": list(set(t for u in urls_raw for t in (u.get("tags") or []) if t)),
            "urls": [
                {"url": u.get("url", ""), "status": u.get("url_status", ""),
                 "threat": u.get("threat", ""), "date_added": u.get("date_added", "")}
                for u in urls_raw[:20]
            ],
        }
        upsert_urlhaus_cache(host, result)
        duration = time.time() - t0
        log.info(f"URLhaus: {host} — {result['urls_count']} URLs, blacklisted={result['blacklisted']} in {duration:.1f}s")
        return result
    except Exception as exc:
        log.warning(f"URLhaus lookup failed for {host}: {exc}")
        return None


def sync_urlhaus_batch(hosts: list[str]) -> dict:
    """Batch sync URLhaus for multiple hosts. Used by Celery beat."""
    t0 = time.time()
    results = {"synced": 0, "errors": 0}
    for host in hosts:
        try:
            sync_urlhaus(host)
            results["synced"] += 1
        except Exception:
            results["errors"] += 1
        time.sleep(0.5)  # rate limit courtesy
    duration = time.time() - t0
    save_intel_sync_log("URLhaus", "success", results["synced"], duration)
    log.info(f"URLhaus batch: {results['synced']}/{len(hosts)} in {duration:.1f}s")
    return results


# ── GreyNoise Community ──────────────────────────────────────────

def sync_greynoise(ip: str) -> dict | None:
    """Lookup IP in GreyNoise Community API (free, no API key)."""
    t0 = time.time()
    try:
        resp = requests.get(
            f"{GREYNOISE_API_URL}/{ip}",
            headers={"Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            # IP not found — cache as unknown
            data = {"noise": False, "riot": False, "classification": "unknown",
                    "name": "N/A", "link": ""}
            upsert_greynoise_cache(ip, data)
            return data
        resp.raise_for_status()
        data = resp.json()
        result = {
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name": data.get("name", ""),
            "link": data.get("link", ""),
        }
        upsert_greynoise_cache(ip, result)
        duration = time.time() - t0
        log.info(f"GreyNoise: {ip} — {result['classification']}, noise={result['noise']}, riot={result['riot']} in {duration:.1f}s")
        return result
    except Exception as exc:
        log.warning(f"GreyNoise lookup failed for {ip}: {exc}")
        return None
