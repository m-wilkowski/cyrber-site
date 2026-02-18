import os
from celery import Celery
from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan
from modules.whatweb_scan import scan as whatweb_scan
from modules.gobuster_scan import scan as gobuster_scan
from modules.testssl_scan import scan as testssl_scan
from modules.llm_analyze import analyze_scan_results
from modules.database import init_db, save_scan

celery_app = Celery(
    "cyrber",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

init_db()

@celery_app.task
def full_scan_task(target: str):
    task_id = full_scan_task.request.id

    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    whatweb = whatweb_scan(target)
    gobuster = gobuster_scan(target)
    testssl = testssl_scan(target)

    scan_data = {
        "target": target,
        "ports": nmap.get("ports", []),
        "nuclei": nuclei,
        "whatweb": whatweb,
        "gobuster": gobuster,
        "testssl": testssl
    }

    result = analyze_scan_results(scan_data)
    result["whatweb"] = whatweb
    result["gobuster"] = gobuster
    result["testssl"] = testssl
    save_scan(task_id, target, result)
    return result
