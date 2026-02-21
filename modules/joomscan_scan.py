import subprocess
import os
import re


def _detect_joomla(target: str) -> bool:
    """Quick check if target runs Joomla via HTTP response markers."""
    url = target if target.startswith("http") else f"http://{target}"
    try:
        result = subprocess.run(
            ["curl", "-sL", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", url + "/administrator/"],
            capture_output=True, text=True, timeout=15,
        )
        if result.stdout.strip() in ("200", "301", "302", "303"):
            return True
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["curl", "-sL", "-m", "10", url],
            capture_output=True, text=True, timeout=15,
        )
        body = result.stdout.lower()
        if "joomla" in body or "/media/jui/" in body or "com_content" in body:
            return True
    except Exception:
        pass
    return False


def joomscan_scan(target: str) -> dict:
    """
    Scan target with OWASP Joomscan (Joomla vulnerability scanner).

    Returns:
        {
            "target": str,
            "joomla_version": str,
            "vulnerabilities": list,
            "components": list,
            "admin_url": str,
            "backup_files": list,
            "config_files": list,
            "summary": {"total_vulns": int, "components_count": int}
        }
    """
    url = target if target.startswith("http") else f"http://{target}"

    # Check Joomla presence first
    if not _detect_joomla(target):
        return {"skipped": True, "reason": "Joomla not detected"}

    safe_name = re.sub(r'[^\w\-.]', '_', target)
    output_file = f"/tmp/joomscan_{safe_name}.txt"

    if os.path.exists(output_file):
        os.remove(output_file)

    try:
        result = subprocess.run(
            ["joomscan", "--url", url, "--output", output_file],
            capture_output=True,
            text=True,
            timeout=180,
        )
        raw_output = result.stdout or ""
    except FileNotFoundError:
        return {"skipped": True, "reason": "joomscan not installed"}
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
        return {"skipped": True, "reason": "No Joomscan output"}

    # Strip ANSI codes
    raw_output = re.sub(r'\x1b\[[0-9;]*m', '', raw_output)

    # Parse Joomla version
    joomla_version = ""
    ver_m = re.search(r'\[!\]\s*(?:Joomla\s+)?[Vv]ersion\s*[:\-]?\s*(\S+)', raw_output, re.IGNORECASE)
    if not ver_m:
        ver_m = re.search(r'Joomla[! ]*(\d+\.\d+[\.\d]*)', raw_output, re.IGNORECASE)
    if ver_m:
        joomla_version = ver_m.group(1).strip().rstrip('.')

    # Parse admin URL
    admin_url = ""
    admin_m = re.search(r'(?:admin|administrator)\s*(?:page|panel|url|login)?\s*[:\-]\s*(https?://\S+)', raw_output, re.IGNORECASE)
    if not admin_m:
        admin_m = re.search(r'(https?://\S*/administrator/?\S*)', raw_output, re.IGNORECASE)
    if admin_m:
        admin_url = admin_m.group(1).strip()

    # Parse vulnerabilities
    vulnerabilities = []
    # Pattern: lines containing vulnerability indicators
    vuln_patterns = [
        # [++] Title / CVE / exploit info blocks
        re.compile(r'\[\+\+\]\s*(.+)', re.IGNORECASE),
        re.compile(r'\[!\]\s*(?:vulnerability|vuln|exploit|CVE)[:\s]+(.+)', re.IGNORECASE),
    ]

    # Scan for vulnerability sections
    lines = raw_output.split('\n')
    in_vuln_section = False
    current_vuln = None

    for line in lines:
        stripped = line.strip()

        # Detect vulnerability section markers
        if re.search(r'(?:vulnerabilit|exploit|CVE-\d{4})', stripped, re.IGNORECASE):
            in_vuln_section = True

        # CVE patterns
        cve_m = re.findall(r'(CVE-\d{4}-\d+)', stripped)

        # Explicit vulnerability lines
        vuln_m = re.match(r'\[\+\+?\]\s*(.+)', stripped)
        if vuln_m:
            title = vuln_m.group(1).strip()
            # Skip non-vulnerability info lines
            if any(skip in title.lower() for skip in ['checking', 'scanning', 'fetching', 'target', 'server', 'started', 'finished']):
                continue

            severity = "Medium"
            if cve_m or any(kw in title.lower() for kw in ['rce', 'remote code', 'sql injection', 'sqli', 'command injection']):
                severity = "High"
            elif any(kw in title.lower() for kw in ['xss', 'cross-site', 'csrf', 'open redirect', 'lfi', 'rfi', 'file inclusion']):
                severity = "High"
            elif any(kw in title.lower() for kw in ['information disclosure', 'info leak', 'directory listing']):
                severity = "Low"

            vuln_url = ""
            url_m = re.search(r'(https?://\S+)', stripped)
            if url_m:
                vuln_url = url_m.group(1)

            vulnerabilities.append({
                "title": title,
                "severity": severity,
                "url": vuln_url,
                "description": " ".join(cve_m) if cve_m else "",
            })

    # Parse components
    components = []
    comp_pattern = re.compile(r'(?:com_(\w+))', re.IGNORECASE)
    found_components = set()
    for line in lines:
        for comp_m in comp_pattern.finditer(line):
            comp_name = comp_m.group(1)
            if comp_name.lower() not in found_components:
                found_components.add(comp_name.lower())
                ver = ""
                ver_m2 = re.search(r'(?:version|ver)[:\s]*(\d[\d.]+)', line, re.IGNORECASE)
                if ver_m2:
                    ver = ver_m2.group(1)
                components.append({"name": f"com_{comp_name}", "version": ver})

    # Parse backup files
    backup_files = []
    backup_exts = ('.bak', '.old', '.zip', '.tar', '.gz', '.sql', '.dump', '.backup', '.swp', '.save')
    for line in lines:
        url_m = re.search(r'(https?://\S+)', line)
        if url_m:
            found_url = url_m.group(1).rstrip(')')
            if any(found_url.lower().endswith(ext) for ext in backup_exts):
                if found_url not in backup_files:
                    backup_files.append(found_url)
        # Also detect mentions of backup/config patterns
        if re.search(r'(?:backup|\.bak|\.old|\.save|\.swp)', line, re.IGNORECASE) and 'http' in line:
            url_m2 = re.search(r'(https?://\S+)', line)
            if url_m2 and url_m2.group(1) not in backup_files:
                found_url = url_m2.group(1).rstrip(')')
                if found_url not in backup_files:
                    backup_files.append(found_url)

    # Parse config files
    config_files = []
    config_patterns = ['configuration.php', 'config.php', 'htaccess', 'web.config', '.env',
                       'configuration.php.bak', 'configuration.php.old', 'robots.txt']
    for line in lines:
        for cfg in config_patterns:
            if cfg.lower() in line.lower():
                url_m = re.search(r'(https?://\S+)', line)
                if url_m:
                    found_url = url_m.group(1).rstrip(')')
                    if found_url not in config_files:
                        config_files.append(found_url)
                elif cfg not in config_files:
                    config_files.append(cfg)

    # Deduplicate
    config_files = list(dict.fromkeys(config_files))
    backup_files = list(dict.fromkeys(backup_files))

    return {
        "target": target,
        "joomla_version": joomla_version,
        "vulnerabilities": vulnerabilities,
        "components": components,
        "admin_url": admin_url,
        "backup_files": backup_files,
        "config_files": config_files,
        "summary": {
            "total_vulns": len(vulnerabilities),
            "components_count": len(components),
        },
    }
