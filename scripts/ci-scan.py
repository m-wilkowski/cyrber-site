#!/usr/bin/env python3
"""CYRBER CI/CD scan orchestrator.

Usage:
    python scripts/ci-scan.py --target http://localhost:8888 --profile CI \
        --api-url http://localhost:8000 --username admin --password cyrber2024
"""

import argparse
import json
import os
import sys
import time

import requests


def parse_args():
    p = argparse.ArgumentParser(description="CYRBER CI scan orchestrator")
    p.add_argument("--target", required=True, help="Scan target URL or IP")
    p.add_argument("--profile", default="CI", help="Scan profile (default: CI)")
    p.add_argument("--api-url", default="http://localhost:8000", help="CYRBER API base URL")
    p.add_argument("--username", default="admin")
    p.add_argument("--password", default="cyrber2024")
    p.add_argument("--timeout", type=int, default=1800, help="Max wait seconds (default: 1800)")
    p.add_argument("--output-dir", default="ci-results", help="Output directory")
    p.add_argument("--gate-critical", type=int, default=0, help="Max critical findings before fail")
    p.add_argument("--gate-high", type=int, default=5, help="Max high findings before fail")
    p.add_argument("--defectdojo-url", default=None, help="DefectDojo URL for import")
    p.add_argument("--defectdojo-token", default=None, help="DefectDojo API token")
    p.add_argument("--defectdojo-engagement", type=int, default=None, help="DefectDojo engagement ID")
    return p.parse_args()


def login(api_url: str, username: str, password: str) -> str:
    """Authenticate and return JWT token."""
    r = requests.post(
        f"{api_url}/auth/login",
        json={"username": username, "password": password},
        timeout=30,
    )
    r.raise_for_status()
    token = r.json().get("token") or r.json().get("access_token")
    if not token:
        raise RuntimeError(f"Login failed: {r.json()}")
    return token


def start_scan(api_url: str, token: str, target: str, profile: str) -> str:
    """Start a scan and return task_id."""
    r = requests.post(
        f"{api_url}/scan/start",
        json={"target": target, "profile": profile},
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    task_id = data.get("task_id")
    if not task_id:
        raise RuntimeError(f"Scan start failed: {data}")
    print(f"[CYRBER] Scan started: task_id={task_id}")
    return task_id


def poll_status(api_url: str, token: str, task_id: str, timeout: int) -> dict:
    """Poll scan status until completed/failed or timeout."""
    headers = {"Authorization": f"Bearer {token}"}
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{api_url}/scan/status/{task_id}", headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        status = data.get("status", "unknown")
        if status == "completed":
            print(f"[CYRBER] Scan completed: {task_id}")
            return data
        if status == "failed":
            raise RuntimeError(f"Scan failed: {data.get('error', 'unknown')}")
        print(f"[CYRBER] Status: {status} — waiting...")
        time.sleep(5)
    raise TimeoutError(f"Scan timed out after {timeout}s")


def download_results(status_data: dict, output_dir: str) -> dict:
    """Save scan results JSON to output directory."""
    os.makedirs(output_dir, exist_ok=True)
    results = status_data.get("result", {})
    path = os.path.join(output_dir, "cyrber-results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[CYRBER] Results saved: {path}")
    return results


def apply_security_gate(results: dict, max_critical: int, max_high: int) -> bool:
    """Check severity counts against thresholds. Returns True if gate passes."""
    counts = results.get("severity_counts")
    if not counts:
        # Compute from findings if not pre-computed (non-CI profiles)
        counts = _count_severities(results)
        results["severity_counts"] = counts

    critical = counts.get("critical", 0)
    high = counts.get("high", 0)

    print(f"[CYRBER] Security Gate: critical={critical} (max {max_critical}), high={high} (max {max_high})")

    if critical > max_critical:
        print(f"[CYRBER] GATE FAILED: {critical} critical findings exceed threshold of {max_critical}")
        return False
    if high > max_high:
        print(f"[CYRBER] GATE FAILED: {high} high findings exceed threshold of {max_high}")
        return False

    print("[CYRBER] GATE PASSED")
    return True


def _count_severities(results: dict) -> dict:
    """Count severities from raw scan results (fallback)."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in results.get("nuclei", {}).get("findings", []):
        sev = f.get("info", {}).get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1

    for a in results.get("zap", {}).get("alerts", []):
        risk = a.get("risk", "Informational").lower()
        mapping = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}
        counts[mapping.get(risk, "info")] += 1

    for f in results.get("testssl", {}).get("findings", []):
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1

    if results.get("sqlmap", {}).get("vulnerable"):
        counts["critical"] += 1

    return counts


def write_github_outputs(task_id: str, gate_passed: bool, results: dict):
    """Write to GITHUB_OUTPUT and GITHUB_STEP_SUMMARY if running in GitHub Actions."""
    counts = results.get("severity_counts", {})
    findings = results.get("findings_count", sum(counts.values()))
    risk = results.get("risk_level", "UNKNOWN")

    # GITHUB_OUTPUT
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"task_id={task_id}\n")
            f.write(f"gate_passed={'true' if gate_passed else 'false'}\n")
            f.write(f"findings_count={findings}\n")
            f.write(f"risk_level={risk}\n")
            f.write(f"critical={counts.get('critical', 0)}\n")
            f.write(f"high={counts.get('high', 0)}\n")
            f.write(f"medium={counts.get('medium', 0)}\n")
            f.write(f"low={counts.get('low', 0)}\n")

    # GITHUB_STEP_SUMMARY
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write("## CYRBER Security Scan Results\n\n")
            f.write(f"**Target:** `{results.get('target', 'unknown')}`\n")
            f.write(f"**Risk Level:** {risk}\n")
            f.write(f"**Gate:** {'PASSED' if gate_passed else 'FAILED'}\n\n")
            f.write("| Severity | Count |\n|----------|-------|\n")
            for sev in ("critical", "high", "medium", "low", "info"):
                f.write(f"| {sev.capitalize()} | {counts.get(sev, 0)} |\n")
            f.write(f"\n**Total findings:** {findings}\n")


def import_to_defectdojo(sarif_path: str, url: str, token: str, engagement_id: int):
    """Upload SARIF to DefectDojo."""
    if not all([url, token, engagement_id]):
        return
    print(f"[CYRBER] Importing to DefectDojo: {url}")
    try:
        r = requests.post(
            f"{url.rstrip('/')}/api/v2/import-scan/",
            headers={"Authorization": f"Token {token}"},
            data={
                "engagement": engagement_id,
                "scan_type": "SARIF",
                "verified": False,
                "active": True,
            },
            files={"file": open(sarif_path, "rb")},
            timeout=60,
        )
        r.raise_for_status()
        print(f"[CYRBER] DefectDojo import OK: {r.json().get('test', 'unknown')}")
    except Exception as e:
        print(f"[CYRBER] DefectDojo import failed: {e}")


def main():
    args = parse_args()

    print(f"[CYRBER] CI Scan — target={args.target} profile={args.profile}")

    # 1. Login
    token = login(args.api_url, args.username, args.password)

    # 2. Start scan
    task_id = start_scan(args.api_url, token, args.target, args.profile)

    # 3. Poll until done
    status_data = poll_status(args.api_url, token, task_id, args.timeout)

    # 4. Download results
    results = download_results(status_data, args.output_dir)

    # 5. Convert to SARIF
    sys.path.insert(0, os.path.dirname(__file__))
    from sarif_convert import convert_to_sarif

    sarif = convert_to_sarif(results)
    sarif_path = os.path.join(args.output_dir, "cyrber.sarif")
    with open(sarif_path, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"[CYRBER] SARIF saved: {sarif_path}")

    # 6. Security gate
    gate_passed = apply_security_gate(results, args.gate_critical, args.gate_high)

    # 7. GitHub Actions outputs
    write_github_outputs(task_id, gate_passed, results)

    # 8. DefectDojo import
    if args.defectdojo_url:
        import_to_defectdojo(
            sarif_path, args.defectdojo_url,
            args.defectdojo_token, args.defectdojo_engagement,
        )

    # 9. Save severity counts for baseline comparison
    baseline_path = os.path.join(args.output_dir, "baseline.json")
    with open(baseline_path, "w") as f:
        json.dump({
            "task_id": task_id,
            "target": args.target,
            "severity_counts": results.get("severity_counts", {}),
            "findings_count": results.get("findings_count", 0),
            "risk_level": results.get("risk_level", "UNKNOWN"),
        }, f, indent=2)

    if not gate_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
