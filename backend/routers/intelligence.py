"""Intelligence sync, ATT&CK, MISP, threat intel lookups."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.deps import get_current_user, require_role, audit
from modules.database import (
    get_intel_sync_logs, get_intel_cache_counts,
    search_attack_techniques, get_attack_technique, get_attack_tactics,
    get_mitigations_for_technique, get_techniques_for_cwe, get_euvd_by_cve,
    get_scan_by_task_id,
)

router = APIRouter(tags=["intelligence"])


# ── Intel sync admin ──

@router.get("/admin/intel-sync/status")
async def intel_sync_status(current_user: dict = Depends(require_role("admin"))):
    logs = get_intel_sync_logs(limit=10)
    counts = get_intel_cache_counts()
    last_sync = {}
    for entry in logs:
        src = entry["source"]
        if src not in last_sync:
            last_sync[src] = entry["synced_at"]
    return {"logs": logs, "counts": counts, "last_sync": last_sync}


@router.post("/admin/intel-sync/run")
async def intel_sync_run(request: Request, current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_intel_sync
    result = run_intel_sync.delay()
    audit(request, current_user, "intel_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}


@router.post("/admin/intel-sync/attack")
async def intel_sync_attack(request: Request, current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_attack_sync
    result = run_attack_sync.delay()
    audit(request, current_user, "attack_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}


@router.post("/admin/intel-sync/euvd")
async def intel_sync_euvd(request: Request, current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_euvd_sync
    result = run_euvd_sync.delay()
    audit(request, current_user, "euvd_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}


@router.post("/admin/intel-sync/misp")
async def intel_sync_misp(request: Request, current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_misp_sync
    result = run_misp_sync.delay()
    audit(request, current_user, "misp_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}


@router.post("/admin/intel-sync/exploitdb")
async def intel_sync_exploitdb(request: Request, current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_exploitdb_sync
    result = run_exploitdb_sync.delay()
    audit(request, current_user, "exploitdb_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}


@router.post("/admin/intel-sync/malwarebazaar")
async def intel_sync_malwarebazaar(request: Request, current_user: dict = Depends(require_role("admin"))):
    from modules.tasks import run_malwarebazaar_sync
    result = run_malwarebazaar_sync.delay()
    audit(request, current_user, "malwarebazaar_sync_trigger", f"celery_task={result.id}")
    return {"ok": True, "task_id": result.id}


# ── MISP API ──

@router.post("/api/misp/export/{task_id}")
async def api_misp_export(
    task_id: str,
    request: Request,
    current_user: dict = Depends(require_role("admin", "operator")),
):
    from modules.misp_integration import export_scan_to_misp, is_misp_configured
    if not is_misp_configured():
        raise HTTPException(status_code=503, detail="MISP not configured")
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = export_scan_to_misp(scan, task_id)
    audit(request, current_user, "misp_export", f"task_id={task_id} event_id={result.get('event_id')}")
    return result


@router.get("/api/misp/search")
async def api_misp_search(
    value: str = Query(..., min_length=2),
    type: str = Query(None),
    limit: int = Query(20, le=100),
    current_user: dict = Depends(get_current_user),
):
    from modules.misp_integration import lookup_misp_indicator
    results = lookup_misp_indicator(value, attr_type=type)
    return results[:limit]


@router.get("/api/misp/events")
async def api_misp_events(
    q: str = Query("", min_length=0),
    limit: int = Query(20, le=100),
    current_user: dict = Depends(get_current_user),
):
    from modules.database import search_misp_events
    return search_misp_events(query=q, limit=limit)


# ── Shodan / URLhaus / GreyNoise ──

@router.get("/api/intel/shodan/lookup")
async def api_shodan_lookup(
    target: str = Query(..., min_length=4),
    current_user: dict = Depends(get_current_user),
):
    from modules.database import get_shodan_cache
    from modules.intelligence_sync import sync_shodan
    cached = get_shodan_cache(target)
    if cached:
        return cached
    result = sync_shodan(target)
    if not result:
        return {"ip": target, "ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
    return result


@router.get("/api/intel/urlhaus/lookup")
async def api_urlhaus_lookup(
    target: str = Query(..., min_length=2),
    current_user: dict = Depends(get_current_user),
):
    from modules.database import get_urlhaus_cache
    from modules.intelligence_sync import sync_urlhaus
    cached = get_urlhaus_cache(target)
    if cached:
        return cached
    result = sync_urlhaus(target)
    if not result:
        return {"host": target, "urls_count": 0, "blacklisted": False, "tags": [], "urls": []}
    return result


@router.get("/api/intel/greynoise/lookup")
async def api_greynoise_lookup(
    target: str = Query(..., min_length=4),
    current_user: dict = Depends(get_current_user),
):
    from modules.database import get_greynoise_cache
    from modules.intelligence_sync import sync_greynoise
    cached = get_greynoise_cache(target)
    if cached:
        return cached
    result = sync_greynoise(target)
    if not result:
        return {"ip": target, "noise": False, "riot": False, "classification": "unknown", "name": "N/A", "link": ""}
    return result


@router.get("/api/intel/target/enrich")
async def api_target_enrich(
    target: str = Query(..., min_length=2),
    current_user: dict = Depends(get_current_user),
):
    """Combined enrichment for a scan target (Shodan + URLhaus + GreyNoise)."""
    from modules.intelligence_sync import enrich_target
    return enrich_target(target)


# ── ExploitDB ──

@router.get("/api/intel/exploitdb/lookup")
async def api_exploitdb_lookup(
    cve_id: str = Query(..., pattern=r"^CVE-\d{4}-\d{4,7}$"),
    current_user: dict = Depends(get_current_user),
):
    from modules.database import get_exploitdb_by_cve
    results = get_exploitdb_by_cve(cve_id)
    return {"cve_id": cve_id, "count": len(results), "exploits": results}


@router.get("/api/intel/exploitdb/search")
async def api_exploitdb_search(
    q: str = Query(..., min_length=2),
    limit: int = Query(20, le=100),
    current_user: dict = Depends(get_current_user),
):
    from modules.database import search_exploitdb
    return search_exploitdb(query=q, limit=limit)


# ── MalwareBazaar ──

@router.get("/api/intel/malwarebazaar/lookup")
async def api_malwarebazaar_lookup(
    hash: str = Query(..., min_length=32),
    current_user: dict = Depends(get_current_user),
):
    from modules.database import get_malwarebazaar_by_hash
    from modules.intelligence_sync import lookup_malwarebazaar
    cached = get_malwarebazaar_by_hash(hash)
    if cached:
        return {"hash": hash, "found": True, **cached}
    result = lookup_malwarebazaar(hash)
    if not result:
        return {"hash": hash, "found": False}
    return {"hash": hash, "found": True, **result}


# ── ATT&CK ──

@router.get("/api/attack/techniques")
async def api_attack_techniques(
    q: str = "",
    tactic: str = "",
    limit: int = Query(50, le=200),
    current_user: dict = Depends(get_current_user),
):
    return search_attack_techniques(query=q, tactic=tactic, limit=limit)


@router.get("/api/attack/technique/{technique_id}")
async def api_attack_technique_detail(
    technique_id: str,
    current_user: dict = Depends(get_current_user),
):
    t = get_attack_technique(technique_id)
    if not t:
        raise HTTPException(status_code=404, detail="Technique not found")
    t["mitigations"] = get_mitigations_for_technique(technique_id)
    return t


@router.get("/api/attack/tactics")
async def api_attack_tactics(current_user: dict = Depends(get_current_user)):
    return get_attack_tactics()


@router.get("/api/attack/cwe/{cwe_id}")
async def api_attack_cwe(cwe_id: str, current_user: dict = Depends(get_current_user)):
    return get_techniques_for_cwe(cwe_id)


# ── EUVD ──

@router.get("/api/euvd/lookup")
async def api_euvd_lookup(
    cve_id: str = Query(..., pattern=r"^CVE-\d{4}-\d{4,7}$"),
    current_user: dict = Depends(get_current_user),
):
    result = get_euvd_by_cve(cve_id)
    if not result:
        return {"cve_id": cve_id, "found": False}
    result["found"] = True
    return result


# ── Finding enrich ──

@router.get("/api/finding/enrich")
async def finding_enrich(
    cve_id: str = Query(..., pattern=r"^CVE-\d{4}-\d{4,7}$"),
    current_user: dict = Depends(require_role("admin", "operator")),
):
    from modules.intelligence_sync import enrich_finding
    result = enrich_finding(cve_id)
    return result
