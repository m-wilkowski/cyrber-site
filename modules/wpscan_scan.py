import os
import json
import subprocess
import tempfile
import re


def wpscan_scan(target: str) -> dict:
    """
    WPScan — WordPress vulnerability scanner.
    First detects if target runs WordPress, then enumerates plugins, themes, users, vulns.
    """
    base = {"target": target, "skipped": False}

    # ── Check if WordPress ──
    if not _is_wordpress(target):
        return {"target": target, "skipped": True, "reason": "WordPress not detected"}

    # ── Ensure URL has scheme ──
    url = target if target.startswith("http") else f"http://{target}"

    # ── Build command ──
    output_file = tempfile.mktemp(suffix=".json", prefix="wpscan_")
    cmd = [
        "wpscan",
        "--url", url,
        "--format", "json",
        "--output", output_file,
        "--enumerate", "vp,vt,tt,cb,dbe,u,m",
        "--plugins-detection", "aggressive",
        "--no-banner",
        "--random-user-agent",
    ]

    api_token = os.environ.get("WPSCAN_API_TOKEN", "").strip()
    if api_token:
        cmd.extend(["--api-token", api_token])

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except FileNotFoundError:
        return {"target": target, "skipped": True, "reason": "wpscan not installed"}
    except subprocess.TimeoutExpired:
        return {"target": target, "skipped": True, "reason": "Timeout (180s)"}

    # ── Parse JSON output ──
    try:
        with open(output_file, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"target": target, "skipped": True, "reason": "Failed to parse WPScan output"}
    finally:
        try:
            os.unlink(output_file)
        except OSError:
            pass

    # ── Extract WordPress version ──
    wp_version_data = data.get("version", {}) or {}
    wp_version = wp_version_data.get("number", "unknown")
    wp_status = wp_version_data.get("status", "unknown")
    wp_vulns = wp_version_data.get("vulnerabilities", [])

    # ── Extract plugins ──
    plugins_raw = data.get("plugins", {}) or {}
    plugins = []
    for name, info in plugins_raw.items():
        plugin = {
            "name": name,
            "version": (info.get("version", {}) or {}).get("number", "unknown") if isinstance(info.get("version"), dict) else str(info.get("version", "unknown")),
            "vulnerabilities": [],
        }
        for v in info.get("vulnerabilities", []):
            plugin["vulnerabilities"].append({
                "title": v.get("title", ""),
                "type": v.get("vuln_type", ""),
                "fixed_in": v.get("fixed_in", ""),
                "references": list(v.get("references", {}).get("url", []))[:3],
            })
        plugins.append(plugin)

    # ── Extract themes ──
    themes_raw = data.get("themes", {}) or {}
    themes = []
    for name, info in themes_raw.items():
        theme = {
            "name": name,
            "version": (info.get("version", {}) or {}).get("number", "unknown") if isinstance(info.get("version"), dict) else str(info.get("version", "unknown")),
            "vulnerabilities": [],
        }
        for v in info.get("vulnerabilities", []):
            theme["vulnerabilities"].append({
                "title": v.get("title", ""),
                "type": v.get("vuln_type", ""),
                "fixed_in": v.get("fixed_in", ""),
            })
        themes.append(theme)

    # ── Extract users ──
    users_raw = data.get("users", {}) or {}
    users = []
    for username, info in users_raw.items():
        users.append({
            "username": username,
            "id": info.get("id", ""),
            "slug": info.get("slug", username),
        })

    # ── Interesting findings ──
    interesting = []
    for finding in data.get("interesting_findings", []):
        interesting.append({
            "type": finding.get("type", ""),
            "url": finding.get("url", ""),
            "description": finding.get("to_s", finding.get("description", "")),
        })

    # ── Count all vulnerabilities ──
    vuln_count = len(wp_vulns)
    for p in plugins:
        vuln_count += len(p["vulnerabilities"])
    for t in themes:
        vuln_count += len(t["vulnerabilities"])

    # ── TimThumb check ──
    timthumb = any(
        "timthumb" in f.get("type", "").lower() or "timthumb" in f.get("url", "").lower()
        for f in interesting
    )

    base.update({
        "wordpress_version": {
            "version": wp_version,
            "status": wp_status,
            "vulnerabilities": [{"title": v.get("title", ""), "fixed_in": v.get("fixed_in", "")} for v in wp_vulns],
        },
        "vulnerabilities_count": vuln_count,
        "plugins": plugins,
        "themes": themes,
        "users": users,
        "interesting_findings": interesting,
        "timthumb_vulns": timthumb,
        "plugins_count": len(plugins),
        "themes_count": len(themes),
        "users_count": len(users),
    })
    return base


def _is_wordpress(target: str) -> bool:
    """Quick check if target runs WordPress using HTTP headers/content."""
    url = target if target.startswith("http") else f"http://{target}"
    try:
        import requests
        r = requests.get(url, timeout=10, allow_redirects=True, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 CYRBER/1.0"})
        body = r.text.lower()
        headers_str = str(r.headers).lower()
        # Check common WordPress indicators
        wp_indicators = [
            "wp-content",
            "wp-includes",
            "wp-json",
            "/xmlrpc.php",
            "wordpress",
            "wp-login.php",
            "wp-admin",
            "wp-emoji",
        ]
        for indicator in wp_indicators:
            if indicator in body or indicator in headers_str:
                return True
        # Check meta generator tag
        if 'name="generator"' in body and "wordpress" in body:
            return True
        return False
    except Exception:
        # If we can't check, try running WPScan anyway
        return True
