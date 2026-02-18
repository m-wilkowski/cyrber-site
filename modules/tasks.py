import os
from celery import Celery
from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan
from modules.llm_analyze import analyze_scan_results

celery_app = Celery(
    "cyrber",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

@celery_app.task
def full_scan_task(target: str):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    scan_data = {
        "target": target,
        "ports": nmap.get("ports", []),
        "nuclei": nuclei
    }
    analysis = analyze_scan_results(scan_data)
    return analysis
