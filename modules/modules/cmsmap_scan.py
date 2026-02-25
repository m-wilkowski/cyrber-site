import subprocess
import os
import re


def cmsmap_scan(target: str) -> dict:
    """
    Scan target with CMSmap (multi-CMS vulnerability scanner).

    Skips if WPScan or Joomscan already detected the CMS (pass scan_results
    from the pipeline to avoid duplicate work).

    Returns:
        {
            "target": str,
            "cms_detected": str,
            "cms_version": str,
            "vulnerabilities": list,
            "plugins": list,
            "themes": list,
            "users": list,
            "summary": {"total_vulns": int, "high": int, "medium": int, "low": int}
        }
    """
    url = target if target.startswith("http") else f"http://{target}"
    safe_name = re.sub(r'[^\w\-.]', '_', target)
    output_file = f"/tmp/cmsmap_{safe_name}.txt"

    if os.path.exists(output_file):
        os.remove(output_file)

    try:
        result = subprocess.run(
            ["python3", "/opt/cmsmap/cmsmap.py", url, "-o", output_file],
            capture_output=True,
            text=True,
            timeout=240,
        )
        raw_output = result.stdout or ""
    except FileNotFoundError:
        return {"skipped": True, "reason": "cmsmap not installed"}
    except subprocess.TimeoutExpired:
        raw_output = ""

    # Try file output first, fallback to stdout
    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                raw_output = f.read()
        except Exception:
            pass
        finally:
            try:
                os.remove(output_file)
            except OSError:
                pass

    if not raw_output:
        return {"skipped": True, "reason": "No CMSmap output"}

    # Strip ANSI codes
    raw_output = re.sub(r'\x1b\[[0-9;]*m', '', raw_output)
    lines = raw_output.split('\n')

    # Detect CMS type
    cms_detected = "unknown"
    cms_version = ""

    for line in lines:
        ll = line.lower()
        if 'wordpress' in ll:
            cms_detected = "WordPress"
        elif 'joomla' in ll:
            cms_detected = "Joomla"
        elif 'drupal' in ll:
            cms_detected = "Drupal"

        # Version detection patterns
        ver_m = re.search(r'(?:version|ver)[:\s]*(\d+[\d.]+)', line, re.IGNORECASE)
        if ver_m and not cms_version:
            cms_version = ver_m.group(1).rstrip('.')

        # CMSmap specific version output: [I] CMS: WordPress X.Y.Z
        cms_ver_m = re.search(r'\[I\]\s*CMS:\s*\w+\s+(\d+[\d.]+)', line, re.IGNORECASE)
        if cms_ver_m:
            cms_version = cms_ver_m.group(1).rstrip('.')

        # Type detection from CMSmap output
        type_m = re.search(r'\[I\]\s*CMS:\s*(WordPress|Joomla|Drupal)', line, re.IGNORECASE)
        if type_m:
            cms_detected = type_m.group(1)

    if cms_detected == "unknown":
        return {"skipped": True, "reason": "No CMS detected by CMSmap"}

    # Parse vulnerabilities
    vulnerabilities = []
    for line in lines:
        stripped = line.strip()

        # CMSmap vuln patterns: [M] ... or [C] ... (medium/critical) or [H] (high)
        vuln_m = re.match(r'\[([CHMLI])\]\s+(.+)', stripped)
        if not vuln_m:
            continue

        level_char = vuln_m.group(1)
        content = vuln_m.group(2).strip()

        # Skip informational/logging lines
        if level_char == 'I':
            continue
        if level_char == 'L':
            # L = low severity finding
            pass

        # Map level characters
        severity_map = {'C': 'High', 'H': 'High', 'M': 'Medium', 'L': 'Low'}
        severity = severity_map.get(level_char, 'Medium')

        # Extract CVE if present
        cve_matches = re.findall(r'(CVE-\d{4}-\d+)', content)
        cve = ", ".join(cve_matches) if cve_matches else ""

        # Skip non-vulnerability info
        skip_keywords = ['checking', 'scanning', 'starting', 'target', 'finished',
                         'server:', 'module', 'loading', 'brute']
        if any(kw in content.lower() for kw in skip_keywords):
            continue

        vulnerabilities.append({
            "title": content,
            "severity": severity,
            "cve": cve,
            "description": "",
        })

    # Parse plugins
    plugins = []
    for line in lines:
        # Plugin patterns: [I] Plugin: name (version) or com_name
        plugin_m = re.search(r'(?:plugin|component|module)[:\s]+(\S+)(?:\s+(?:version[:\s]*)?(\d[\d.]*))?', line, re.IGNORECASE)
        if plugin_m:
            name = plugin_m.group(1).strip()
            version = (plugin_m.group(2) or "").strip()
            vulnerable = bool(re.search(r'\[[CHM]\]', line))
            if name.lower() not in ('found', 'not', 'no', 'the'):
                plugins.append({"name": name, "version": version, "vulnerable": vulnerable})

        # Also catch wp-content/plugins/name and components/com_name
        wp_plugin_m = re.search(r'wp-content/plugins/([^/\s]+)', line, re.IGNORECASE)
        if wp_plugin_m:
            name = wp_plugin_m.group(1)
            if not any(p["name"] == name for p in plugins):
                vulnerable = bool(re.search(r'\[[CHM]\]', line))
                plugins.append({"name": name, "version": "", "vulnerable": vulnerable})

    # Parse themes
    themes = []
    for line in lines:
        theme_m = re.search(r'(?:theme)[:\s]+(\S+)(?:\s+(?:version[:\s]*)?(\d[\d.]*))?', line, re.IGNORECASE)
        if theme_m:
            name = theme_m.group(1).strip()
            version = (theme_m.group(2) or "").strip()
            vulnerable = bool(re.search(r'\[[CHM]\]', line))
            if name.lower() not in ('found', 'not', 'no', 'the', 'default'):
                themes.append({"name": name, "version": version, "vulnerable": vulnerable})

        wp_theme_m = re.search(r'wp-content/themes/([^/\s]+)', line, re.IGNORECASE)
        if wp_theme_m:
            name = wp_theme_m.group(1)
            if not any(t["name"] == name for t in themes):
                vulnerable = bool(re.search(r'\[[CHM]\]', line))
                themes.append({"name": name, "version": "", "vulnerable": vulnerable})

    # Parse users
    users = []
    for line in lines:
        user_m = re.search(r'(?:user(?:name)?|author)[:\s]+(\S+)', line, re.IGNORECASE)
        if user_m:
            username = user_m.group(1).strip().strip('"\'')
            if username and username.lower() not in ('not', 'no', 'found', 'the', 'enumeration'):
                if username not in users:
                    users.append(username)

    # Build summary
    high = sum(1 for v in vulnerabilities if v["severity"] == "High")
    medium = sum(1 for v in vulnerabilities if v["severity"] == "Medium")
    low = sum(1 for v in vulnerabilities if v["severity"] == "Low")

    return {
        "target": target,
        "cms_detected": cms_detected,
        "cms_version": cms_version,
        "vulnerabilities": vulnerabilities,
        "plugins": plugins,
        "themes": themes,
        "users": users,
        "summary": {
            "total_vulns": len(vulnerabilities),
            "high": high,
            "medium": medium,
            "low": low,
        },
    }
