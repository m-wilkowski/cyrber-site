"""
Minimal FastAPI wrapper for garak LLM security scanner.
Runs inside a dedicated Docker container.
"""

import json
import logging
import os
import subprocess
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CYRBER Garak Scanner")
log = logging.getLogger("garak-server")

RESULTS_DIR = Path("/app/results")
RESULTS_DIR.mkdir(exist_ok=True)

# In-memory scan state
_scans: dict[str, dict] = {}
_lock = threading.Lock()


class ScanRequest(BaseModel):
    target_type: str = "openai"        # openai, rest, ollama, huggingface
    target_name: str = "gpt-4"         # model name
    probes: str = "encoding,dan,promptinject"  # comma-separated probe names
    probe_tags: str = ""                # e.g. "owasp:llm01"
    generations: int = 3
    api_key: str = ""                   # target API key (e.g. OpenAI)
    api_base: str = ""                  # custom API base URL


@app.get("/status")
async def health():
    try:
        proc = subprocess.run(
            ["python", "-m", "garak", "--version"],
            capture_output=True, text=True, timeout=15,
        )
        version = proc.stdout.strip() or proc.stderr.strip()
    except Exception:
        version = "unknown"
    running = sum(1 for s in _scans.values() if s["status"] == "running")
    return {"status": "ok", "version": version, "scans_running": running}


@app.get("/probes")
async def list_probes():
    try:
        proc = subprocess.run(
            ["python", "-m", "garak", "--list_probes"],
            capture_output=True, text=True, timeout=30,
        )
        probes = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("garak") and not line.startswith("probes:"):
                probes.append(line)
        return {"probes": probes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan")
async def start_scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())[:8]
    report_prefix = str(RESULTS_DIR / scan_id)

    cmd = [
        "python", "-m", "garak",
        "--target_type", req.target_type,
        "--target_name", req.target_name,
        "--generations", str(req.generations),
        "--report_prefix", report_prefix,
        "--narrow_output",
    ]

    if req.probes:
        cmd.extend(["--probes", req.probes])
    if req.probe_tags:
        cmd.extend(["--probe_tags", req.probe_tags])

    env = os.environ.copy()
    if req.api_key:
        # Map to appropriate env var based on target type
        key_map = {
            "openai": "OPENAI_API_KEY",
            "cohere": "COHERE_API_KEY",
            "replicate": "REPLICATE_API_TOKEN",
            "huggingface": "HF_INFERENCE_TOKEN",
        }
        env_var = key_map.get(req.target_type, "OPENAI_API_KEY")
        env[env_var] = req.api_key
    if req.api_base:
        env["OPENAI_API_BASE"] = req.api_base

    with _lock:
        _scans[scan_id] = {
            "status": "running",
            "target": f"{req.target_type}/{req.target_name}",
            "probes": req.probes,
            "report_prefix": report_prefix,
            "results": None,
            "error": None,
        }

    thread = threading.Thread(target=_run_scan, args=(scan_id, cmd, env), daemon=True)
    thread.start()

    return {"scan_id": scan_id, "status": "running"}


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = dict(scan)
    # If completed, try to load results from JSONL
    if result["status"] == "completed" and result["results"] is None:
        result["results"] = _load_results(scan["report_prefix"])
        with _lock:
            _scans[scan_id]["results"] = result["results"]

    return result


@app.get("/scans")
async def list_scans():
    with _lock:
        return [
            {"scan_id": sid, "status": s["status"], "target": s["target"]}
            for sid, s in _scans.items()
        ]


def _run_scan(scan_id: str, cmd: list, env: dict):
    """Execute garak CLI in background thread."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600, env=env,
        )
        with _lock:
            if proc.returncode == 0:
                _scans[scan_id]["status"] = "completed"
            else:
                _scans[scan_id]["status"] = "failed"
                _scans[scan_id]["error"] = proc.stderr[-500:] if proc.stderr else "Unknown error"
    except subprocess.TimeoutExpired:
        with _lock:
            _scans[scan_id]["status"] = "failed"
            _scans[scan_id]["error"] = "Scan timed out (600s)"
    except Exception as e:
        with _lock:
            _scans[scan_id]["status"] = "failed"
            _scans[scan_id]["error"] = str(e)


def _load_results(report_prefix: str) -> dict:
    """Parse garak JSONL report file into structured results."""
    report_file = f"{report_prefix}.report.jsonl"
    if not os.path.exists(report_file):
        return {"error": "Report file not found"}

    entries = []
    summary = {"total_probes": 0, "total_passed": 0, "total_failed": 0, "detectors": {}}

    with open(report_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            entry_type = entry.get("entry_type", "")

            if entry_type == "eval":
                probe = entry.get("probe", "")
                detector = entry.get("detector", "")
                passed = entry.get("passed", True)
                score = entry.get("score", 0.0)

                summary["total_probes"] += 1
                if passed:
                    summary["total_passed"] += 1
                else:
                    summary["total_failed"] += 1

                if detector not in summary["detectors"]:
                    summary["detectors"][detector] = {"passed": 0, "failed": 0}
                if passed:
                    summary["detectors"][detector]["passed"] += 1
                else:
                    summary["detectors"][detector]["failed"] += 1

                entries.append({
                    "probe": probe,
                    "detector": detector,
                    "passed": passed,
                    "score": score,
                    "prompt": entry.get("prompt", "")[:200],
                    "output": entry.get("output", "")[:200],
                })

    return {"summary": summary, "entries": entries[:100]}
