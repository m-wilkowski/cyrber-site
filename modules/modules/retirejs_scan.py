import subprocess
import json
import os
import re
import tempfile


def retirejs_scan(target: str) -> dict:
    """
    Scan target with Retire.js to detect vulnerable JavaScript libraries.

    Fetches the page HTML, extracts JS references, and checks them
    against the Retire.js vulnerability database.

    Returns:
        {
            "target": str,
            "libraries": list of {
                "component": str,
                "version": str,
                "detection": str,
                "vulnerabilities": list of {
                    "severity": str,
                    "summary": str,
                    "cve": list,
                    "info": list of URLs
                }
            },
            "summary": {
                "total_libs": int,
                "vulnerable_libs": int,
                "critical": int,
                "high": int,
                "medium": int,
                "low": int,
                "total_vulns": int
            }
        }
    """
    url = target if target.startswith("http") else f"http://{target}"

    # Download page to temp dir for retire to scan
    tmpdir = tempfile.mkdtemp(prefix="retirejs_")
    index_file = os.path.join(tmpdir, "index.html")

    try:
        # Fetch page content
        curl_result = subprocess.run(
            ["curl", "-sL", "-m", "15", "-o", index_file, url],
            capture_output=True, text=True, timeout=20,
        )
        if not os.path.exists(index_file) or os.path.getsize(index_file) == 0:
            _cleanup(tmpdir)
            return {"skipped": True, "reason": "Could not fetch target page"}

        # Also try to download referenced JS files
        _download_js_refs(url, index_file, tmpdir)

    except Exception:
        _cleanup(tmpdir)
        return {"skipped": True, "reason": "Failed to fetch target content"}

    # Run retire.js
    try:
        result = subprocess.run(
            ["retire", "--path", tmpdir, "--outputformat", "json",
             "--exitwith", "0"],
            capture_output=True, text=True, timeout=120,
        )
        raw_output = result.stdout or ""
    except FileNotFoundError:
        _cleanup(tmpdir)
        return {"skipped": True, "reason": "retire.js not installed"}
    except subprocess.TimeoutExpired:
        _cleanup(tmpdir)
        return {"skipped": True, "reason": "Retire.js timeout (120s)"}
    finally:
        _cleanup(tmpdir)

    if not raw_output.strip():
        return {
            "target": target,
            "libraries": [],
            "summary": _empty_summary(),
        }

    # Parse JSON output
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return {
            "target": target,
            "libraries": [],
            "summary": _empty_summary(),
        }

    libraries = []
    seen = set()

    results_list = data if isinstance(data, list) else data.get("data", [])

    for entry in results_list:
        file_results = entry.get("results", [])
        for res in file_results:
            component = res.get("component", "")
            version = res.get("version", "")
            detection = res.get("detection", "")

            key = f"{component}:{version}"
            if key in seen:
                continue
            seen.add(key)

            vulns_raw = res.get("vulnerabilities", [])
            vulns = []
            for v in vulns_raw:
                severity = v.get("severity", "medium").lower()
                # Normalize severity
                if severity in ("critical",):
                    severity = "critical"
                elif severity in ("high",):
                    severity = "high"
                elif severity in ("medium",):
                    severity = "medium"
                else:
                    severity = "low"

                identifiers = v.get("identifiers", {})
                cves = identifiers.get("CVE", []) or []
                summary_parts = identifiers.get("summary", identifiers.get("bug", ""))
                if isinstance(summary_parts, list):
                    summary_text = "; ".join(str(s) for s in summary_parts)
                else:
                    summary_text = str(summary_parts) if summary_parts else ""

                # If no summary, use issue title
                if not summary_text:
                    summary_text = v.get("title", v.get("info", [""])[0] if v.get("info") else "")

                info_urls = v.get("info", []) or []

                vulns.append({
                    "severity": severity,
                    "summary": summary_text,
                    "cve": cves,
                    "info": info_urls[:5],
                })

            libraries.append({
                "component": component,
                "version": version,
                "detection": detection,
                "vulnerabilities": vulns,
            })

    # Build summary
    total_libs = len(libraries)
    vulnerable_libs = sum(1 for lib in libraries if lib["vulnerabilities"])
    critical = 0
    high = 0
    medium = 0
    low = 0
    total_vulns = 0

    for lib in libraries:
        for v in lib["vulnerabilities"]:
            total_vulns += 1
            sev = v["severity"]
            if sev == "critical":
                critical += 1
            elif sev == "high":
                high += 1
            elif sev == "medium":
                medium += 1
            else:
                low += 1

    return {
        "target": target,
        "libraries": libraries,
        "summary": {
            "total_libs": total_libs,
            "vulnerable_libs": vulnerable_libs,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total_vulns": total_vulns,
        },
    }


def _empty_summary():
    return {
        "total_libs": 0,
        "vulnerable_libs": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total_vulns": 0,
    }


def _download_js_refs(base_url: str, html_file: str, tmpdir: str):
    """Extract and download JS file references from HTML."""
    try:
        with open(html_file, "r", errors="ignore") as f:
            html = f.read()
    except Exception:
        return

    # Find script src references
    js_refs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)

    for ref in js_refs[:20]:  # limit to 20 JS files
        if ref.startswith("//"):
            js_url = "https:" + ref
        elif ref.startswith("http"):
            js_url = ref
        elif ref.startswith("/"):
            # Absolute path
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            js_url = f"{parsed.scheme}://{parsed.netloc}{ref}"
        else:
            js_url = base_url.rstrip("/") + "/" + ref

        safe_name = re.sub(r'[^\w\-.]', '_', ref.split("/")[-1].split("?")[0])
        if not safe_name.endswith(".js"):
            safe_name += ".js"

        js_path = os.path.join(tmpdir, safe_name)
        try:
            subprocess.run(
                ["curl", "-sL", "-m", "8", "-o", js_path, js_url],
                capture_output=True, timeout=10,
            )
        except Exception:
            pass


def _cleanup(tmpdir: str):
    """Remove temp directory."""
    try:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass
