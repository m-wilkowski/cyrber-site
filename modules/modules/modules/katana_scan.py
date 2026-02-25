import subprocess
import json
import re
import shutil
from urllib.parse import urlparse


def _clean_target(target: str) -> str:
    """Strip protocol, path, port from target."""
    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    return host.strip().lower()


def _ensure_url(target: str) -> str:
    """Ensure target has a protocol prefix."""
    if not target.startswith(('http://', 'https://')):
        return f"https://{target}"
    return target


def katana_scan(target: str) -> dict:
    """Run katana web crawler against target.

    Crawls the target website discovering endpoints, forms,
    JavaScript files, API routes, and other resources.

    Args:
        target: Domain name, hostname, or URL.

    Returns:
        Dict with crawling results.
    """
    host = _clean_target(target)
    if not host:
        return {"skipped": True, "reason": "empty target"}

    katana_bin = shutil.which("katana")
    if not katana_bin:
        return {"skipped": True, "reason": "katana not installed"}

    url = _ensure_url(target)

    try:
        cmd = [
            katana_bin,
            "-u", url,
            "-silent",
            "-json",
            "-depth", "3",
            "-crawl-duration", "120",
            "-rate-limit", "50",
            "-concurrency", "10",
            "-js-crawl",
            "-known-files", "all",
            "-form-fill",
            "-timeout", "10",
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )

        urls_found = set()
        endpoints = []
        js_files = []
        forms = []
        api_endpoints = []
        interesting_files = []
        sources = set()
        methods = {}

        output = proc.stdout.strip()
        if output:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)

                    req = rec.get("request", {})
                    resp = rec.get("response", {})
                    endpoint = req.get("endpoint", rec.get("endpoint", ""))
                    found_url = req.get("url", rec.get("url", endpoint))
                    method = req.get("method", rec.get("method", "GET"))
                    source = rec.get("source", "")
                    status = resp.get("status_code", rec.get("status_code", 0))
                    content_type = resp.get("content_type", "")
                    body_length = resp.get("body", "")
                    tag = rec.get("tag", "")

                    if not found_url:
                        continue

                    urls_found.add(found_url)

                    if source:
                        sources.add(source)

                    methods[method] = methods.get(method, 0) + 1

                    entry = {
                        "url": found_url,
                        "method": method,
                        "status_code": status,
                        "source": source,
                        "tag": tag,
                    }
                    if content_type:
                        entry["content_type"] = content_type

                    # Categorize
                    parsed = urlparse(found_url)
                    path_lower = parsed.path.lower()

                    if path_lower.endswith('.js') or 'javascript' in content_type.lower():
                        js_files.append(entry)
                    elif tag == "form" or "form" in source.lower():
                        forms.append(entry)
                    elif any(p in path_lower for p in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/json', '/xml']):
                        api_endpoints.append(entry)
                    elif any(path_lower.endswith(ext) for ext in ['.env', '.bak', '.sql', '.log', '.conf', '.config', '.xml', '.yml', '.yaml', '.json', '.git', '.svn', '.htaccess', '.htpasswd', '.DS_Store', '.swp']):
                        interesting_files.append(entry)
                    else:
                        endpoints.append(entry)

                except json.JSONDecodeError:
                    # Plain text fallback — one URL per line
                    if line.startswith('http'):
                        urls_found.add(line)
                        endpoints.append({"url": line, "method": "GET"})

        # Deduplicate by URL
        seen = set()
        def _dedup(lst):
            result = []
            for item in lst:
                u = item.get("url", "")
                if u and u not in seen:
                    seen.add(u)
                    result.append(item)
            return result

        endpoints = _dedup(endpoints)
        js_files = _dedup(js_files)
        forms = _dedup(forms)
        api_endpoints = _dedup(api_endpoints)
        interesting_files = _dedup(interesting_files)

        # Sort by URL
        endpoints.sort(key=lambda x: x.get("url", ""))
        js_files.sort(key=lambda x: x.get("url", ""))
        forms.sort(key=lambda x: x.get("url", ""))
        api_endpoints.sort(key=lambda x: x.get("url", ""))
        interesting_files.sort(key=lambda x: x.get("url", ""))

        return {
            "target": host,
            "total_urls": len(urls_found),
            "endpoints": endpoints,
            "js_files": js_files,
            "forms": forms,
            "api_endpoints": api_endpoints,
            "interesting_files": interesting_files,
            "sources": sorted(sources),
            "methods": methods,
            "summary": {
                "total_urls": len(urls_found),
                "endpoints": len(endpoints),
                "js_files": len(js_files),
                "forms": len(forms),
                "api_endpoints": len(api_endpoints),
                "interesting_files": len(interesting_files),
                "sources_count": len(sources),
            },
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "katana timeout (180s)"}
    except FileNotFoundError:
        return {"skipped": True, "reason": "katana not installed"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
