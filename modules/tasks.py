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
from modules.enum4linux_scan import scan as enum4linux_scan
from modules.abuseipdb_scan import scan as abuseipdb_scan
from modules.llm_analyze import analyze_scan_results
from modules.exploit_chains import generate_exploit_chains
from modules.false_positive_filter import filter_false_positives
from modules.hacker_narrative import generate_hacker_narrative
from modules.mitre_attack import mitre_map
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
    whatweb = whatweb_scan(target)
    gobuster = gobuster_scan(target)
    testssl = testssl_scan(target)
    sqlmap = sqlmap_scan(target)
    nikto = nikto_scan(target)
    harvester = harvester_scan(target)
    masscan = masscan_scan(target)
    ipinfo = ipinfo_scan(target)
    enum4linux = enum4linux_scan(target)
    abuseipdb = abuseipdb_scan(target)
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
        "enum4linux": enum4linux,
        "abuseipdb": abuseipdb,
    }
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
