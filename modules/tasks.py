import os
from celery import Celery
from celery.schedules import crontab
from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan
from modules.whatweb_scan import scan as whatweb_scan
from modules.gobuster_scan import scan as gobuster_scan
from modules.testssl_scan import scan as testssl_scan
from modules.sqlmap_scan import scan as sqlmap_scan
from modules.nikto_scan import scan as nikto_scan
from modules.harvester_scan import scan as harvester_scan
from modules.exiftool_scan import scan as exiftool_scan
from modules.masscan_scan import scan as masscan_scan
# from modules.censys_scan import scan as censys_scan  # requires paid API plan - module ready
from modules.ipinfo_scan import scan as ipinfo_scan
from modules.enum4linux_scan import enum4linux_scan
from modules.abuseipdb_scan import scan as abuseipdb_scan
from modules.otx_scan import scan as otx_scan
from modules.llm_analyze import analyze_scan_results
from modules.exploit_chains import generate_exploit_chains
from modules.false_positive_filter import filter_false_positives
from modules.hacker_narrative import generate_hacker_narrative
from modules.mitre_attack import mitre_map
from modules.exploitdb_scan import exploitdb_scan
from modules.nvd_scan import nvd_scan
from modules.whois_scan import whois_scan
from modules.dnsrecon_scan import dnsrecon_scan
from modules.amass_scan import amass_scan
from modules.cwe_mapping import cwe_mapping
from modules.owasp_mapping import owasp_mapping
from modules.wpscan_scan import wpscan_scan
from modules.zap_scan import zap_scan
from modules.wapiti_scan import wapiti_scan
from modules.joomscan_scan import joomscan_scan
from modules.cmsmap_scan import cmsmap_scan
from modules.droopescan_scan import droopescan_scan
from modules.retirejs_scan import retirejs_scan
from modules.subfinder_scan import subfinder_scan
from modules.httpx_scan import httpx_scan
from modules.naabu_scan import naabu_scan
from modules.katana_scan import katana_scan
from modules.dnsx_scan import dnsx_scan
from modules.netdiscover_scan import netdiscover_scan
from modules.arpscan_scan import arpscan_scan
from modules.fping_scan import fping_scan
from modules.traceroute_scan import traceroute_scan
from modules.nbtscan_scan import nbtscan_scan
from modules.snmpwalk_scan import snmpwalk_scan
from modules.netexec_scan import netexec_scan
from modules.bloodhound_scan import bloodhound_scan
from modules.responder_scan import responder_scan
from modules.fierce_scan import fierce_scan
from modules.smbmap_scan import smbmap_scan
from modules.onesixtyone_scan import onesixtyone_scan
from modules.ikescan_scan import ikescan_scan
from modules.sslyze_scan import sslyze_scan
from modules.searchsploit_scan import searchsploit_scan
from modules.impacket_scan import impacket_scan
from modules.certipy_scan import run_certipy
from modules.osint_scan import osint_scan
from modules.database import (
    save_scan, get_due_schedules, update_schedule_run,
    get_all_cve_ids_from_findings, update_remediation_task,
    get_remediation_task_by_id, save_audit_log,
)
from modules.notify import send_scan_notification
from modules.scan_profiles import should_run_module, get_all_modules
from modules.ai_analysis import analyze_scan_results as ai_analyze, reflect_on_scan

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


def publish_progress(task_id: str, module: str, status: str, completed: int, total: int, message: str = ""):
    """Publikuje postęp skanu do Redis pub/sub."""
    try:
        import redis, json
        r = redis.from_url(REDIS_URL)
        data = {
            "task_id": task_id,
            "module": module,
            "status": status,
            "completed": completed,
            "total": total,
            "message": message,
            "timestamp": __import__('time').time()
        }
        r.publish(f"scan_progress:{task_id}", json.dumps(data))
    except Exception:
        pass

celery_app = Celery(
    "cyrber",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.beat_schedule = {
    "check-schedules-every-minute": {
        "task": "modules.tasks.run_due_schedules",
        "schedule": 60.0,
    },
    "intel-sync-daily": {
        "task": "modules.tasks.run_intel_sync",
        "schedule": crontab(hour=3, minute=0),
    },
    "attack-sync-weekly": {
        "task": "modules.tasks.run_attack_sync",
        "schedule": crontab(hour=4, minute=0, day_of_week=0),  # Sunday 04:00
    },
    "euvd-sync-daily": {
        "task": "modules.tasks.run_euvd_sync",
        "schedule": crontab(hour=3, minute=30),
    },
}

_SKIPPED = {"skipped": True, "reason": "not in profile", "findings": []}

def _skip():
    return dict(_SKIPPED)

@celery_app.task
def full_scan_task(target: str, profile: str = "STRAZNIK"):
    task_id = full_scan_task.request.id
    run = lambda mod: should_run_module(mod, profile)
    # Total = 42 scan modules + 8 post-processing = 50 steps
    total = 52
    completed = 0
    pp = lambda mod, st, msg="": publish_progress(task_id, mod, st, completed, total, msg)

    # ── Fundamentals (always run) ──
    pp("nmap", "started")
    nmap = nmap_scan(target)
    completed += 1; pp("nmap", "done", f"{len(nmap.get('ports', []))} ports")

    pp("ipinfo", "started")
    ipinfo = ipinfo_scan(target)
    completed += 1; pp("ipinfo", "done")

    # ── Profile-gated modules ──
    pp("nuclei", "started")
    nuclei = nuclei_scan(target) if run("nuclei") else _skip()
    nuclei_filtered = filter_false_positives(nuclei, target) if run("nuclei") else _skip()
    completed += 1; pp("nuclei", "done" if not nuclei.get("skipped") else "skipped")

    pp("zap", "started")
    zap = zap_scan(target) if run("zap") else _skip()
    completed += 1; pp("zap", "done" if not zap.get("skipped") else "skipped")

    pp("wapiti", "started")
    wapiti = wapiti_scan(target) if run("wapiti") else _skip()
    completed += 1; pp("wapiti", "done" if not wapiti.get("skipped") else "skipped")

    pp("joomscan", "started")
    joomscan = joomscan_scan(target) if run("joomscan") else _skip()
    completed += 1; pp("joomscan", "done" if not joomscan.get("skipped") else "skipped")

    pp("cmsmap", "started")
    cmsmap = cmsmap_scan(target) if run("cmsmap") else _skip()
    completed += 1; pp("cmsmap", "done" if not cmsmap.get("skipped") else "skipped")

    pp("droopescan", "started")
    droopescan = droopescan_scan(target) if run("droopescan") else _skip()
    completed += 1; pp("droopescan", "done" if not droopescan.get("skipped") else "skipped")

    pp("retirejs", "started")
    retirejs = retirejs_scan(target) if run("retirejs") else _skip()
    completed += 1; pp("retirejs", "done" if not retirejs.get("skipped") else "skipped")

    pp("whatweb", "started")
    whatweb = whatweb_scan(target) if run("whatweb") else _skip()
    completed += 1; pp("whatweb", "done" if not whatweb.get("skipped") else "skipped")

    pp("wpscan", "started")
    wpscan = wpscan_scan(target) if run("wpscan") else _skip()
    completed += 1; pp("wpscan", "done" if not wpscan.get("skipped") else "skipped")

    pp("gobuster", "started")
    gobuster = gobuster_scan(target) if run("gobuster") else _skip()
    completed += 1; pp("gobuster", "done" if not gobuster.get("skipped") else "skipped")

    pp("testssl", "started")
    testssl = testssl_scan(target) if run("testssl") else _skip()
    completed += 1; pp("testssl", "done" if not testssl.get("skipped") else "skipped")

    pp("sqlmap", "started")
    sqlmap = sqlmap_scan(target) if run("sqlmap") else _skip()
    completed += 1; pp("sqlmap", "done" if not sqlmap.get("skipped") else "skipped")

    pp("nikto", "started")
    nikto = nikto_scan(target) if run("nikto") else _skip()
    completed += 1; pp("nikto", "done" if not nikto.get("skipped") else "skipped")

    pp("harvester", "started")
    harvester = harvester_scan(target)
    completed += 1; pp("harvester", "done")

    pp("exiftool", "started")
    exiftool = exiftool_scan(target)
    completed += 1; pp("exiftool", "done", f"{exiftool.get('images_analyzed', 0)} images")

    pp("masscan", "started")
    masscan = masscan_scan(target) if run("masscan") else _skip()
    completed += 1; pp("masscan", "done" if not masscan.get("skipped") else "skipped")

    pp("abuseipdb", "started")
    abuseipdb = abuseipdb_scan(target)
    completed += 1; pp("abuseipdb", "done")

    pp("otx", "started")
    otx = otx_scan(target)
    completed += 1; pp("otx", "done")

    pp("whois", "started")
    whois = whois_scan(target) if run("whois") else _skip()
    completed += 1; pp("whois", "done" if not whois.get("skipped") else "skipped")

    pp("dnsrecon", "started")
    dnsrecon = dnsrecon_scan(target)
    completed += 1; pp("dnsrecon", "done")

    pp("amass", "started")
    amass = amass_scan(target) if run("amass") else _skip()
    completed += 1; pp("amass", "done" if not amass.get("skipped") else "skipped")

    pp("subfinder", "started")
    subfinder = subfinder_scan(target) if run("subfinder") else _skip()
    completed += 1; pp("subfinder", "done" if not subfinder.get("skipped") else "skipped")

    # Combine subdomains from amass + subfinder for httpx probing
    _httpx_subs = list(set(
        (amass.get("subdomains") or []) + (subfinder.get("subdomains") or [])
    ))

    pp("httpx", "started")
    httpx = httpx_scan(target, subdomains=_httpx_subs) if run("httpx") else _skip()
    completed += 1; pp("httpx", "done" if not httpx.get("skipped") else "skipped")

    pp("naabu", "started")
    naabu = naabu_scan(target, subdomains=_httpx_subs) if run("naabu") else _skip()
    completed += 1; pp("naabu", "done" if not naabu.get("skipped") else "skipped")

    pp("katana", "started")
    katana = katana_scan(target) if run("katana") else _skip()
    completed += 1; pp("katana", "done" if not katana.get("skipped") else "skipped")

    pp("dnsx", "started")
    dnsx = dnsx_scan(target, subdomains=_httpx_subs) if run("dnsx") else _skip()
    completed += 1; pp("dnsx", "done" if not dnsx.get("skipped") else "skipped")

    pp("netdiscover", "started")
    netdiscover = netdiscover_scan(target) if run("netdiscover") else _skip()
    completed += 1; pp("netdiscover", "done" if not netdiscover.get("skipped") else "skipped")

    pp("arpscan", "started")
    arpscan = arpscan_scan(target) if run("arpscan") else _skip()
    completed += 1; pp("arpscan", "done" if not arpscan.get("skipped") else "skipped")

    pp("fping", "started")
    fping = fping_scan(target) if run("fping") else _skip()
    completed += 1; pp("fping", "done" if not fping.get("skipped") else "skipped")

    pp("traceroute", "started")
    traceroute = traceroute_scan(target) if run("traceroute") else _skip()
    completed += 1; pp("traceroute", "done" if not traceroute.get("skipped") else "skipped")

    pp("nbtscan", "started")
    nbtscan = nbtscan_scan(target) if run("nbtscan") else _skip()
    completed += 1; pp("nbtscan", "done" if not nbtscan.get("skipped") else "skipped")

    pp("snmpwalk", "started")
    snmpwalk = snmpwalk_scan(target) if run("snmpwalk") else _skip()
    completed += 1; pp("snmpwalk", "done" if not snmpwalk.get("skipped") else "skipped")

    pp("netexec", "started")
    netexec = netexec_scan(target) if run("netexec") else _skip()
    completed += 1; pp("netexec", "done" if not netexec.get("skipped") else "skipped")

    pp("enum4linux", "started")
    enum4linux = enum4linux_scan(target) if run("enum4linux") else _skip()
    completed += 1; pp("enum4linux", "done" if not enum4linux.get("skipped") else "skipped")

    pp("bloodhound", "started")
    bloodhound = bloodhound_scan(target) if run("bloodhound") else _skip()
    completed += 1; pp("bloodhound", "done" if not bloodhound.get("skipped") else "skipped")

    pp("responder", "started")
    responder = responder_scan(target) if run("responder") else _skip()
    completed += 1; pp("responder", "done" if not responder.get("skipped") else "skipped")

    pp("fierce", "started")
    fierce = fierce_scan(target) if run("fierce") else _skip()
    completed += 1; pp("fierce", "done" if not fierce.get("skipped") else "skipped")

    pp("smbmap", "started")
    smbmap = smbmap_scan(target) if run("smbmap") else _skip()
    completed += 1; pp("smbmap", "done" if not smbmap.get("skipped") else "skipped")

    pp("onesixtyone", "started")
    onesixtyone = onesixtyone_scan(target) if run("onesixtyone") else _skip()
    completed += 1; pp("onesixtyone", "done" if not onesixtyone.get("skipped") else "skipped")

    pp("ikescan", "started")
    ikescan = ikescan_scan(target) if run("ikescan") else _skip()
    completed += 1; pp("ikescan", "done" if not ikescan.get("skipped") else "skipped")

    pp("sslyze", "started")
    sslyze = sslyze_scan(target) if run("sslyze") else _skip()
    completed += 1; pp("sslyze", "done" if not sslyze.get("skipped") else "skipped")
    scan_data = {
        "target": target,
        "ports": nmap.get("ports", []),
        "nuclei": nuclei_filtered,
        "whatweb": whatweb,
        "gobuster": gobuster,
        "testssl": testssl,
        "sqlmap": sqlmap,
        "nikto": nikto,
        "harvester": harvester,
        "exiftool": exiftool,
        "masscan": masscan,
        "ipinfo": ipinfo,
        "abuseipdb": abuseipdb,
        "otx": otx,
    }
    edb = exploitdb_scan(scan_data)
    nvd = nvd_scan(scan_data)
    result = analyze_scan_results(scan_data)
    result["profile"] = profile
    result["ports"] = nmap.get("ports", [])
    result["whatweb"] = whatweb
    result["gobuster"] = gobuster
    result["testssl"] = testssl
    result["sqlmap"] = sqlmap
    result["nuclei"] = nuclei_filtered
    result["nikto"] = nikto
    result["harvester"] = harvester
    result["exiftool"] = exiftool
    result["masscan"] = masscan
    result["ipinfo"] = ipinfo
    if not enum4linux.get("skipped"):
        result["enum4linux"] = enum4linux
    if not abuseipdb.get("skipped"):
        result["abuseipdb"] = abuseipdb
    if not otx.get("skipped"):
        result["otx"] = otx
    if edb.get("exploits"):
        result["exploitdb"] = edb
    if not nvd.get("skipped"):
        result["nvd"] = nvd
    if not whois.get("error") and not whois.get("skipped"):
        result["whois"] = whois
    if not dnsrecon.get("skipped"):
        result["dnsrecon"] = dnsrecon
    if not amass.get("skipped") and amass.get("total_count", 0) > 0:
        result["amass"] = amass
    if not wpscan.get("skipped"):
        result["wpscan"] = wpscan
    if not zap.get("skipped"):
        result["zap"] = zap
    if not wapiti.get("skipped"):
        result["wapiti"] = wapiti
    if not joomscan.get("skipped"):
        result["joomscan"] = joomscan
    if not cmsmap.get("skipped"):
        result["cmsmap"] = cmsmap
    if not droopescan.get("skipped"):
        result["droopescan"] = droopescan
    if not retirejs.get("skipped") and retirejs.get("libraries"):
        result["retirejs"] = retirejs
    if not subfinder.get("skipped") and subfinder.get("total_count", 0) > 0:
        result["subfinder"] = subfinder
    if not httpx.get("skipped") and httpx.get("total_results", 0) > 0:
        result["httpx"] = httpx
    if not naabu.get("skipped") and naabu.get("total_open_ports", 0) > 0:
        result["naabu"] = naabu
    if not katana.get("skipped") and katana.get("total_urls", 0) > 0:
        result["katana"] = katana
    if not dnsx.get("skipped") and dnsx.get("total_resolved", 0) > 0:
        result["dnsx"] = dnsx
    if not netdiscover.get("skipped") and netdiscover.get("total_hosts", 0) > 0:
        result["netdiscover"] = netdiscover
    if not arpscan.get("skipped") and arpscan.get("total_hosts", 0) > 0:
        result["arpscan"] = arpscan
    if not fping.get("skipped") and fping.get("total_alive", 0) > 0:
        result["fping"] = fping
    if not traceroute.get("skipped") and traceroute.get("total_hops", 0) > 0:
        result["traceroute"] = traceroute
    if not nbtscan.get("skipped") and nbtscan.get("total_hosts", 0) > 0:
        result["nbtscan"] = nbtscan
    if not snmpwalk.get("skipped") and snmpwalk.get("total_interfaces", 0) > 0:
        result["snmpwalk"] = snmpwalk
    if not netexec.get("skipped"):
        result["netexec"] = netexec
    if not bloodhound.get("skipped"):
        result["bloodhound"] = bloodhound
    if not responder.get("skipped") and responder.get("total_protocols", 0) > 0:
        result["responder"] = responder
    if not fierce.get("skipped") and fierce.get("total_subdomains", 0) > 0:
        result["fierce"] = fierce
    if not smbmap.get("skipped") and smbmap.get("total_shares", 0) > 0:
        result["smbmap"] = smbmap
    if not onesixtyone.get("skipped") and onesixtyone.get("total_found", 0) > 0:
        result["onesixtyone"] = onesixtyone
    if not ikescan.get("skipped") and ikescan.get("ike_detected"):
        result["ikescan"] = ikescan
    if not sslyze.get("skipped") and sslyze.get("total_accepted_ciphers", 0) > 0:
        result["sslyze"] = sslyze
    pp("searchsploit", "started")
    searchsploit = searchsploit_scan(target, result) if run("searchsploit") else _skip()
    if not searchsploit.get("skipped") and searchsploit.get("total_exploits", 0) > 0:
        result["searchsploit"] = searchsploit
    completed += 1; pp("searchsploit", "done" if not searchsploit.get("skipped") else "skipped")

    pp("impacket", "started")
    impacket = impacket_scan(target, result) if run("impacket") else _skip()
    if not impacket.get("skipped"):
        result["impacket"] = impacket
    completed += 1; pp("impacket", "done" if not impacket.get("skipped") else "skipped")

    pp("certipy", "started")
    certipy = run_certipy(target) if run("certipy") else _skip()
    if not certipy.get("skipped"):
        result["certipy"] = certipy
    completed += 1; pp("certipy", "done" if not certipy.get("skipped") else "skipped")

    # ── Post-processing ──
    pp("cwe_owasp", "started", "CWE + OWASP mapping")
    cwe = cwe_mapping(result)
    if cwe.get("total", 0) > 0:
        result["cwe"] = cwe
    owasp = owasp_mapping(result)
    if owasp.get("detected_count", 0) > 0:
        result["owasp"] = owasp
    result["fp_filter"] = nuclei_filtered.get("fp_filter", {}) if not nuclei_filtered.get("skipped") else {}
    completed += 1; pp("cwe_owasp", "done")

    pp("exploit_chains", "started", "Generating exploit chains")
    chains = generate_exploit_chains(result)
    result["exploit_chains"] = chains.get("exploit_chains", {})
    completed += 1; pp("exploit_chains", "done")

    pp("hacker_narrative", "started", "Generating hacker narrative")
    narrative = generate_hacker_narrative(result)
    result["hacker_narrative"] = narrative
    completed += 1; pp("hacker_narrative", "done")

    pp("mitre", "started", "MITRE ATT&CK mapping")
    mitre = mitre_map(result)
    result["mitre"] = mitre
    completed += 1; pp("mitre", "done")

    pp("ai_analysis", "started", "AI analysis — final report")
    result["ai_analysis"] = ai_analyze(result)
    completed += 1; pp("ai_analysis", "done")

    pp("reflection", "started", "Scan reflection")
    try:
        result["reflection"] = reflect_on_scan(result, profile)
    except Exception:
        result["reflection"] = {}
    completed += 1; pp("reflection", "done")

    pp("save", "started", "Saving results")
    save_scan(task_id, target, result, profile=profile)
    send_scan_notification(target, task_id, result)
    publish_progress(task_id, "complete", "done", completed, total, "Scan complete")
    return result

@celery_app.task(soft_time_limit=3600, time_limit=3660)
def osint_scan_task(target: str, search_type: str = "domain"):
    task_id = osint_scan_task.request.id
    result = osint_scan(target, search_type=search_type)
    save_scan(task_id, target, result, scan_type="osint")
    return result

from modules.agent import run_agent

@celery_app.task
def agent_scan_task(target: str):
    task_id = agent_scan_task.request.id
    result = run_agent(target)
    chains = generate_exploit_chains(result)
    result["exploit_chains"] = chains.get("exploit_chains", {})
    narrative = generate_hacker_narrative(result)
    result["hacker_narrative"] = narrative
    save_scan(task_id, target, result)
    send_scan_notification(target, task_id, result)
    return result

@celery_app.task
def run_due_schedules():
    schedules = get_due_schedules()
    for schedule in schedules:
        full_scan_task.delay(schedule.target)
        update_schedule_run(schedule.id)
    return {"triggered": len(schedules)}

@celery_app.task
def run_intel_sync():
    """Sync all intelligence feeds: KEV + EPSS + ATT&CK + CAPEC + EUVD."""
    from modules.intelligence_sync import sync_kev, sync_epss, sync_attack, sync_capec_cwe_map, sync_euvd
    results = {}
    try:
        results["kev"] = sync_kev()
    except Exception as e:
        results["kev_error"] = str(e)
    try:
        cve_ids = get_all_cve_ids_from_findings()
        results["epss"] = sync_epss(cve_ids)
        results["cve_ids_found"] = len(cve_ids)
    except Exception as e:
        results["epss_error"] = str(e)
    try:
        results["attack"] = sync_attack()
    except Exception as e:
        results["attack_error"] = str(e)
    try:
        results["capec_cwe_map"] = sync_capec_cwe_map()
    except Exception as e:
        results["capec_cwe_map_error"] = str(e)
    try:
        results["euvd"] = sync_euvd(days_back=7)
    except Exception as e:
        results["euvd_error"] = str(e)
    return results

@celery_app.task
def run_attack_sync():
    """Sync ATT&CK + CAPEC-CWE mapping. Runs weekly (Sunday 04:00)."""
    from modules.intelligence_sync import sync_attack, sync_capec_cwe_map
    results = {}
    try:
        results["attack"] = sync_attack()
    except Exception as e:
        results["attack_error"] = str(e)
    try:
        results["capec_cwe_map"] = sync_capec_cwe_map()
    except Exception as e:
        results["capec_cwe_map_error"] = str(e)
    return results

@celery_app.task
def run_euvd_sync():
    """Sync ENISA EUVD. Runs daily at 03:30."""
    from modules.intelligence_sync import sync_euvd
    return {"euvd": sync_euvd(days_back=7)}

@celery_app.task(bind=True, max_retries=1)
def retest_finding(self, remediation_id: int, finding_name: str,
                   target: str, module: str):
    """Run targeted re-scan for a single finding after it's marked as fixed."""
    from modules.intelligence_sync import run_targeted_retest
    from datetime import datetime

    # Mark as running
    update_remediation_task(remediation_id, retest_status="running")

    try:
        result = run_targeted_retest(finding_name, target, module or "nuclei")
    except Exception as e:
        update_remediation_task(
            remediation_id,
            retest_status="error",
            retest_result={"error": str(e)},
        )
        save_audit_log("system", "retest_error", f"rem={remediation_id} error={e}")
        raise

    if result.get("error") and not result.get("still_vulnerable"):
        # Scanner error — keep as fixed, mark retest error
        new_status = "fixed"
        retest_status = "error"
    elif result["still_vulnerable"]:
        new_status = "open"
        retest_status = "reopened"
    else:
        new_status = "verified"
        retest_status = "verified"

    update_remediation_task(
        remediation_id,
        status=new_status,
        retest_status=retest_status,
        retest_result=result,
    )
    save_audit_log("system", "retest_complete",
                   f"rem={remediation_id} result={retest_status}")
    return {"remediation_id": remediation_id, "retest_status": retest_status}
