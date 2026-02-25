import subprocess
import shutil
import json
import re


def searchsploit_scan(target: str, scan_results: dict = None) -> dict:
    """
    Run SearchSploit (exploit-db CLI) to find known exploits for detected services.
    Extracts service versions from nmap, whatweb, httpx results and searches exploit-db.
    """
    ssploit = shutil.which("searchsploit")
    if not ssploit:
        return {"skipped": True, "reason": "searchsploit not installed"}

    if not scan_results:
        scan_results = {}

    services = _extract_services(target, scan_results)
    if not services:
        return {"skipped": True, "reason": "no services with versions detected"}

    all_exploits = []
    by_service = {}
    seen_ids = set()

    for svc in services:
        query = svc["query"]
        try:
            cmd = [ssploit, "--json", query]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.stdout.strip():
                data = _parse_output(proc.stdout)
                exploits = data.get("RESULTS_EXPLOIT", [])
                for ex in exploits:
                    edb_id = str(ex.get("EDB-ID", "")).strip()
                    if not edb_id or edb_id in seen_ids:
                        continue
                    seen_ids.add(edb_id)
                    title = ex.get("Title", "").strip()
                    path = ex.get("Path", "").strip()
                    date = ex.get("Date_Published", "").strip()
                    etype = _classify_type(path, title)
                    platform = _extract_platform(path)
                    entry = {
                        "edb_id": edb_id,
                        "title": title,
                        "path": path,
                        "type": etype,
                        "platform": platform,
                        "date": date,
                        "url": f"https://www.exploit-db.com/exploits/{edb_id}",
                        "service": svc["name"],
                    }
                    all_exploits.append(entry)
                    by_service.setdefault(svc["name"], []).append(entry)
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

    if not all_exploits:
        return {"skipped": True, "reason": "no exploits found for detected services"}

    remote_count = sum(1 for e in all_exploits if e["type"] == "remote")
    local_count = sum(1 for e in all_exploits if e["type"] == "local")
    dos_count = sum(1 for e in all_exploits if e["type"] == "dos")
    webapps_count = sum(1 for e in all_exploits if e["type"] == "webapps")

    critical_services = list(set(
        e["service"] for e in all_exploits if e["type"] == "remote"
    ))

    return {
        "target": target,
        "exploits": all_exploits,
        "by_service": by_service,
        "summary": {
            "total": len(all_exploits),
            "remote": remote_count,
            "local": local_count,
            "dos": dos_count,
            "webapps": webapps_count,
        },
        "critical_services": critical_services,
        "total_exploits": len(all_exploits),
        "services_scanned": len(services),
    }


def _parse_output(text: str) -> dict:
    """Parse searchsploit JSON output. Handle concatenated or malformed JSON."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try to find the first valid JSON object
    brace = text.find("{")
    if brace >= 0:
        depth = 0
        for i in range(brace, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[brace:i + 1])
                    except json.JSONDecodeError:
                        break
    return {}


def _extract_services(target: str, scan_results: dict) -> list:
    """Extract service+version pairs from scan results."""
    services = []
    seen_queries = set()

    # From nmap ports
    ports = scan_results.get("ports", [])
    for port in ports:
        product = port.get("product") or port.get("service", "")
        version = port.get("version", "")
        if product and version:
            query = f"{product} {version}"
            if query.lower() not in seen_queries:
                seen_queries.add(query.lower())
                services.append({
                    "name": f"{product}/{version} (port {port.get('port', '?')})",
                    "query": query,
                })
        elif product:
            # Try service name alone (e.g. "Apache" or "OpenSSH")
            if product.lower() not in seen_queries and len(product) > 2:
                seen_queries.add(product.lower())
                services.append({
                    "name": f"{product} (port {port.get('port', '?')})",
                    "query": product,
                })

    # From whatweb
    whatweb = scan_results.get("whatweb", {})
    if isinstance(whatweb, dict):
        techs = whatweb.get("technologies") or whatweb.get("plugins") or []
        if isinstance(techs, list):
            for tech in techs:
                if isinstance(tech, dict):
                    name = tech.get("name", "")
                    ver = tech.get("version", "")
                    if name and ver:
                        query = f"{name} {ver}"
                        if query.lower() not in seen_queries:
                            seen_queries.add(query.lower())
                            services.append({"name": f"{name}/{ver}", "query": query})

    # From httpx
    httpx = scan_results.get("httpx", {})
    if isinstance(httpx, dict):
        techs = httpx.get("technologies") or []
        if isinstance(techs, list):
            for tech in techs:
                if isinstance(tech, dict):
                    name = tech.get("name") or tech.get("technology", "")
                    ver = tech.get("version", "")
                    if name and ver:
                        query = f"{name} {ver}"
                        if query.lower() not in seen_queries:
                            seen_queries.add(query.lower())
                            services.append({"name": f"{name}/{ver}", "query": query})
                elif isinstance(tech, str) and "/" in tech:
                    parts = tech.split("/", 1)
                    query = f"{parts[0]} {parts[1]}"
                    if query.lower() not in seen_queries:
                        seen_queries.add(query.lower())
                        services.append({"name": tech, "query": query})

    return services


def _classify_type(path: str, title: str) -> str:
    """Classify exploit type from its path/title."""
    path_lower = path.lower()
    title_lower = title.lower()
    if "/remote/" in path_lower or "remote" in title_lower:
        return "remote"
    elif "/local/" in path_lower or "local privilege" in title_lower:
        return "local"
    elif "/dos/" in path_lower or "denial of service" in title_lower or "dos" in title_lower:
        return "dos"
    elif "/webapps/" in path_lower or "web application" in title_lower:
        return "webapps"
    elif "/shellcode/" in path_lower:
        return "shellcode"
    return "other"


def _extract_platform(path: str) -> str:
    """Extract platform from exploit path."""
    path_lower = path.lower()
    platforms = {
        "/linux/": "Linux",
        "/windows/": "Windows",
        "/unix/": "Unix",
        "/macos/": "macOS",
        "/osx/": "macOS",
        "/freebsd/": "FreeBSD",
        "/solaris/": "Solaris",
        "/php/": "PHP",
        "/java/": "Java",
        "/python/": "Python",
        "/ruby/": "Ruby",
        "/multiple/": "Multiple",
        "/hardware/": "Hardware",
        "/android/": "Android",
        "/ios/": "iOS",
        "/asp/": "ASP",
        "/cgi/": "CGI",
        "/cfm/": "ColdFusion",
        "/jsp/": "JSP",
    }
    for pattern, name in platforms.items():
        if pattern in path_lower:
            return name
    return "Unknown"
