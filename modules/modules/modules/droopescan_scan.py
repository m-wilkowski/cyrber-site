import subprocess
import json
import re


def droopescan_scan(target: str) -> dict:
    """
    Scan target with Droopescan (multi-CMS plugin/theme scanner).

    Supports: Drupal, Joomla, WordPress, SilverStripe, Moodle.

    Returns:
        {
            "target": str,
            "cms_detected": str,
            "cms_version": list of possible versions,
            "plugins": list of {name, url},
            "themes": list of {name, url},
            "interesting_urls": list of {url, description},
            "possible_version_count": int,
            "summary": {"plugins_count": int, "themes_count": int, "interesting_count": int}
        }
    """
    url = target if target.startswith("http") else f"http://{target}"

    try:
        result = subprocess.run(
            ["droopescan", "scan", "-u", url, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=240,
        )
        raw_output = result.stdout or ""
        raw_stderr = result.stderr or ""
    except FileNotFoundError:
        return {"skipped": True, "reason": "droopescan not installed"}
    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "Droopescan timeout (240s)"}

    if not raw_output.strip():
        # Check stderr for CMS not found
        if "not identified" in raw_stderr.lower() or "could not" in raw_stderr.lower():
            return {"skipped": True, "reason": "No supported CMS detected"}
        return {"skipped": True, "reason": "No Droopescan output"}

    # Try JSON parse
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        # Fallback: parse text output
        return _parse_text_output(target, raw_output)

    # JSON output format handling
    # Droopescan may return a single object or a list
    if isinstance(data, list):
        if not data:
            return {"skipped": True, "reason": "No CMS detected by Droopescan"}
        data = data[0]

    cms_detected = data.get("host", {}).get("cms", "unknown") if isinstance(data.get("host"), dict) else "unknown"
    if cms_detected == "unknown":
        # Try to detect from keys
        for key in ["drupal", "joomla", "wordpress", "silverstripe", "moodle"]:
            if key in str(data).lower():
                cms_detected = key.capitalize()
                break

    # Parse versions
    version_data = data.get("version", {}) or {}
    versions = []
    if isinstance(version_data, dict):
        for v in version_data.get("finds", version_data.get("possible_versions", [])):
            if isinstance(v, str):
                versions.append(v)
            elif isinstance(v, dict):
                versions.append(v.get("version", v.get("name", str(v))))
    elif isinstance(version_data, list):
        versions = [str(v) for v in version_data]

    # Parse plugins
    plugins_data = data.get("plugins", {}) or {}
    plugins = []
    if isinstance(plugins_data, dict):
        finds = plugins_data.get("finds", [])
        for p in finds:
            if isinstance(p, str):
                plugins.append({"name": p, "url": ""})
            elif isinstance(p, dict):
                plugins.append({
                    "name": p.get("name", p.get("plugin", "")),
                    "url": p.get("url", ""),
                })
    elif isinstance(plugins_data, list):
        for p in plugins_data:
            if isinstance(p, str):
                plugins.append({"name": p, "url": ""})
            elif isinstance(p, dict):
                plugins.append({"name": p.get("name", ""), "url": p.get("url", "")})

    # Parse themes
    themes_data = data.get("themes", {}) or {}
    themes = []
    if isinstance(themes_data, dict):
        finds = themes_data.get("finds", [])
        for t in finds:
            if isinstance(t, str):
                themes.append({"name": t, "url": ""})
            elif isinstance(t, dict):
                themes.append({
                    "name": t.get("name", t.get("theme", "")),
                    "url": t.get("url", ""),
                })
    elif isinstance(themes_data, list):
        for t in themes_data:
            if isinstance(t, str):
                themes.append({"name": t, "url": ""})
            elif isinstance(t, dict):
                themes.append({"name": t.get("name", ""), "url": t.get("url", "")})

    # Parse interesting URLs
    interesting_data = data.get("interesting urls", data.get("interesting_urls", {})) or {}
    interesting_urls = []
    if isinstance(interesting_data, dict):
        finds = interesting_data.get("finds", [])
        for u in finds:
            if isinstance(u, str):
                interesting_urls.append({"url": u, "description": ""})
            elif isinstance(u, dict):
                interesting_urls.append({
                    "url": u.get("url", ""),
                    "description": u.get("description", u.get("name", "")),
                })
    elif isinstance(interesting_data, list):
        for u in interesting_data:
            if isinstance(u, str):
                interesting_urls.append({"url": u, "description": ""})
            elif isinstance(u, dict):
                interesting_urls.append({"url": u.get("url", ""), "description": u.get("description", "")})

    if not plugins and not themes and not versions and not interesting_urls:
        return {"skipped": True, "reason": "No findings from Droopescan"}

    return {
        "target": target,
        "cms_detected": cms_detected,
        "cms_version": versions,
        "plugins": plugins,
        "themes": themes,
        "interesting_urls": interesting_urls,
        "possible_version_count": len(versions),
        "summary": {
            "plugins_count": len(plugins),
            "themes_count": len(themes),
            "interesting_count": len(interesting_urls),
        },
    }


def _parse_text_output(target: str, raw: str) -> dict:
    """Fallback parser for non-JSON droopescan output."""
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    lines = raw.split('\n')

    cms_detected = "unknown"
    versions = []
    plugins = []
    themes = []
    interesting_urls = []

    section = None
    for line in lines:
        stripped = line.strip()
        ll = stripped.lower()

        # CMS detection
        if 'drupal' in ll:
            cms_detected = "Drupal"
        elif 'joomla' in ll:
            cms_detected = "Joomla"
        elif 'wordpress' in ll:
            cms_detected = "WordPress"
        elif 'silverstripe' in ll:
            cms_detected = "SilverStripe"
        elif 'moodle' in ll:
            cms_detected = "Moodle"

        # Section headers
        if 'possible version' in ll:
            section = 'versions'
            continue
        elif 'plugin' in ll and ('found' in ll or ':' in stripped):
            section = 'plugins'
            continue
        elif 'theme' in ll and ('found' in ll or ':' in stripped):
            section = 'themes'
            continue
        elif 'interesting' in ll and ('url' in ll or 'found' in ll):
            section = 'interesting'
            continue
        elif not stripped or stripped.startswith('[') or stripped.startswith('---'):
            if not stripped:
                section = None
            continue

        # Parse items based on section
        if section == 'versions' and stripped:
            ver = stripped.lstrip('- ').strip()
            if ver and not ver.startswith('['):
                versions.append(ver)
        elif section == 'plugins' and stripped:
            name = stripped.lstrip('- ').strip()
            url_m = re.search(r'(https?://\S+)', name)
            p_url = url_m.group(1) if url_m else ""
            name = re.sub(r'https?://\S+', '', name).strip().rstrip('-').strip()
            if name:
                plugins.append({"name": name, "url": p_url})
        elif section == 'themes' and stripped:
            name = stripped.lstrip('- ').strip()
            url_m = re.search(r'(https?://\S+)', name)
            t_url = url_m.group(1) if url_m else ""
            name = re.sub(r'https?://\S+', '', name).strip().rstrip('-').strip()
            if name:
                themes.append({"name": name, "url": t_url})
        elif section == 'interesting' and stripped:
            entry = stripped.lstrip('- ').strip()
            url_m = re.search(r'(https?://\S+)', entry)
            i_url = url_m.group(1) if url_m else entry
            desc = re.sub(r'https?://\S+', '', entry).strip().rstrip('-').strip()
            interesting_urls.append({"url": i_url, "description": desc})

    if not plugins and not themes and not versions and not interesting_urls:
        return {"skipped": True, "reason": "No findings from Droopescan"}

    return {
        "target": target,
        "cms_detected": cms_detected,
        "cms_version": versions,
        "plugins": plugins,
        "themes": themes,
        "interesting_urls": interesting_urls,
        "possible_version_count": len(versions),
        "summary": {
            "plugins_count": len(plugins),
            "themes_count": len(themes),
            "interesting_count": len(interesting_urls),
        },
    }
