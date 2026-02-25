import subprocess
import json
import re
import shutil


def _clean_target(target: str) -> str:
    """Strip protocol, path, port from target."""
    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    return host.strip().lower()


def httpx_scan(target: str, subdomains: list = None) -> dict:
    """Run httpx HTTP probing against target and optional subdomain list.

    Probes hosts for live HTTP services, collecting status codes,
    titles, technologies, content length, web server, and TLS info.

    Args:
        target: Domain name or hostname.
        subdomains: Optional list of subdomains to probe (e.g. from subfinder/amass).

    Returns:
        Dict with HTTP probing results.
    """
    host = _clean_target(target)
    if not host:
        return {"skipped": True, "reason": "empty target"}

    httpx_bin = shutil.which("httpx")
    if not httpx_bin:
        return {"skipped": True, "reason": "httpx not installed"}

    # Build input list: target itself + any provided subdomains
    hosts = set()
    hosts.add(host)
    if subdomains:
        for s in subdomains:
            s = s.strip().lower()
            if s:
                hosts.add(s)

    input_text = "\n".join(sorted(hosts))

    try:
        cmd = [
            httpx_bin,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-web-server",
            "-method",
            "-follow-redirects",
            "-timeout", "10",
            "-retries", "1",
            "-threads", "25",
        ]

        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=300,
        )

        results = []
        technologies_all = set()
        servers_all = set()
        status_codes = {}

        output = proc.stdout.strip()
        if output:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)

                    url = rec.get("url", "")
                    status = rec.get("status_code", rec.get("status-code", 0))
                    title = rec.get("title", "")
                    tech = rec.get("tech", rec.get("technologies", []))
                    if isinstance(tech, str):
                        tech = [tech]
                    content_length = rec.get("content_length", rec.get("content-length", 0))
                    web_server = rec.get("webserver", rec.get("web_server", ""))
                    method = rec.get("method", "GET")
                    scheme = rec.get("scheme", "")
                    host_found = rec.get("host", rec.get("input", ""))
                    final_url = rec.get("final_url", "")
                    tls_data = rec.get("tls", rec.get("tls-grab", {}))
                    cdn = rec.get("cdn", False)
                    cdn_name = rec.get("cdn_name", rec.get("cdn-name", ""))

                    entry = {
                        "url": url,
                        "host": host_found,
                        "status_code": status,
                        "title": title,
                        "technologies": tech,
                        "content_length": content_length,
                        "web_server": web_server,
                        "method": method,
                        "scheme": scheme,
                    }

                    if final_url and final_url != url:
                        entry["redirect_url"] = final_url
                    if cdn or cdn_name:
                        entry["cdn"] = cdn_name or "detected"
                    if tls_data and isinstance(tls_data, dict):
                        tls_info = {}
                        if tls_data.get("tls_version"):
                            tls_info["version"] = tls_data["tls_version"]
                        if tls_data.get("cipher"):
                            tls_info["cipher"] = tls_data["cipher"]
                        if tls_data.get("subject_dn"):
                            tls_info["subject"] = tls_data["subject_dn"]
                        if tls_data.get("issuer_dn"):
                            tls_info["issuer"] = tls_data["issuer_dn"]
                        if tls_info:
                            entry["tls"] = tls_info

                    results.append(entry)

                    for t in tech:
                        technologies_all.add(t)
                    if web_server:
                        servers_all.add(web_server)

                    code_key = str(status)
                    status_codes[code_key] = status_codes.get(code_key, 0) + 1

                except json.JSONDecodeError:
                    continue

        # Sort: 200 first, then by status code
        results.sort(key=lambda r: (0 if r["status_code"] == 200 else 1, r["status_code"], r.get("url", "")))

        live_count = sum(1 for r in results if 200 <= r["status_code"] < 400)

        return {
            "target": host,
            "probed_hosts": len(hosts),
            "live_hosts": live_count,
            "total_results": len(results),
            "results": results,
            "technologies": sorted(technologies_all),
            "web_servers": sorted(servers_all),
            "status_codes": status_codes,
            "summary": {
                "probed": len(hosts),
                "live": live_count,
                "total": len(results),
                "technologies_count": len(technologies_all),
                "servers_count": len(servers_all),
            },
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "httpx timeout (300s)"}
    except FileNotFoundError:
        return {"skipped": True, "reason": "httpx not installed"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
