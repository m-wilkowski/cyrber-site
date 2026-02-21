import os
from celery import Celery
from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan
from modules.whatweb_scan import scan as whatweb_scan
from modules.gobuster_scan import scan as gobuster_scan
from modules.testssl_scan import scan as testssl_scan
from modules.sqlmap_scan import scan as sqlmap_scan
from modules.nikto_scan import scan as nikto_scan
from modules.harvester_scan import scan as harvester_scan
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
from modules.osint_scan import osint_scan
from modules.database import save_scan, get_due_schedules, update_schedule_run
from modules.notify import send_scan_notification

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

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
}

@celery_app.task
def full_scan_task(target: str):
    task_id = full_scan_task.request.id
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    nuclei_filtered = filter_false_positives(nuclei, target)
    zap = zap_scan(target)
    wapiti = wapiti_scan(target)
    joomscan = joomscan_scan(target)
    cmsmap = cmsmap_scan(target)
    droopescan = droopescan_scan(target)
    retirejs = retirejs_scan(target)
    whatweb = whatweb_scan(target)
    wpscan = wpscan_scan(target)
    gobuster = gobuster_scan(target)
    testssl = testssl_scan(target)
    sqlmap = sqlmap_scan(target)
    nikto = nikto_scan(target)
    harvester = harvester_scan(target)
    masscan = masscan_scan(target)
    ipinfo = ipinfo_scan(target)
    abuseipdb = abuseipdb_scan(target)
    otx = otx_scan(target)
    whois = whois_scan(target)
    dnsrecon = dnsrecon_scan(target)
    amass = amass_scan(target)
    subfinder = subfinder_scan(target)
    # Combine subdomains from amass + subfinder for httpx probing
    _httpx_subs = list(set(
        (amass.get("subdomains") or []) + (subfinder.get("subdomains") or [])
    ))
    httpx = httpx_scan(target, subdomains=_httpx_subs)
    naabu = naabu_scan(target, subdomains=_httpx_subs)
    katana = katana_scan(target)
    dnsx = dnsx_scan(target, subdomains=_httpx_subs)
    netdiscover = netdiscover_scan(target)
    arpscan = arpscan_scan(target)
    fping = fping_scan(target)
    traceroute = traceroute_scan(target)
    nbtscan = nbtscan_scan(target)
    snmpwalk = snmpwalk_scan(target)
    netexec = netexec_scan(target)
    enum4linux = enum4linux_scan(target)
    bloodhound = bloodhound_scan(target)
    responder = responder_scan(target)
    fierce = fierce_scan(target)
    smbmap = smbmap_scan(target)
    onesixtyone = onesixtyone_scan(target)
    ikescan = ikescan_scan(target)
    sslyze = sslyze_scan(target)
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
        "masscan": masscan,
        "ipinfo": ipinfo,
        "abuseipdb": abuseipdb,
        "otx": otx,
    }
    edb = exploitdb_scan(scan_data)
    nvd = nvd_scan(scan_data)
    result = analyze_scan_results(scan_data)
    result["ports"] = nmap.get("ports", [])
    result["whatweb"] = whatweb
    result["gobuster"] = gobuster
    result["testssl"] = testssl
    result["sqlmap"] = sqlmap
    result["nuclei"] = nuclei_filtered
    result["nikto"] = nikto
    result["harvester"] = harvester
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
    if not whois.get("error"):
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
    searchsploit = searchsploit_scan(target, result)
    if not searchsploit.get("skipped") and searchsploit.get("total_exploits", 0) > 0:
        result["searchsploit"] = searchsploit
    cwe = cwe_mapping(result)
    if cwe.get("total", 0) > 0:
        result["cwe"] = cwe
    owasp = owasp_mapping(result)
    if owasp.get("detected_count", 0) > 0:
        result["owasp"] = owasp
    result["fp_filter"] = nuclei_filtered.get("fp_filter", {})
    chains = generate_exploit_chains(result)
    result["exploit_chains"] = chains.get("exploit_chains", {})
    narrative = generate_hacker_narrative(result)
    result["hacker_narrative"] = narrative
    mitre = mitre_map(result)
    result["mitre"] = mitre
    save_scan(task_id, target, result)
    send_scan_notification(target, task_id, result)
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
