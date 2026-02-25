import subprocess
import json
import re
import shutil


def _clean_target(target: str) -> str:
    """Strip protocol, path, port from target."""
    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    return host.strip().lower()


def naabu_scan(target: str, subdomains: list = None) -> dict:
    """Run naabu fast port scan against target and optional subdomain list.

    Args:
        target: Domain name, hostname, or IP address.
        subdomains: Optional list of subdomains to scan (from subfinder/amass).

    Returns:
        Dict with port scanning results per host.
    """
    host = _clean_target(target)
    if not host:
        return {"skipped": True, "reason": "empty target"}

    naabu_bin = shutil.which("naabu")
    if not naabu_bin:
        return {"skipped": True, "reason": "naabu not installed"}

    # Build input list
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
            naabu_bin,
            "-silent",
            "-json",
            "-top-ports", "1000",
            "-rate", "1000",
            "-timeout", "5000",
            "-retries", "2",
            "-c", "25",
        ]

        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=360,
        )

        # Parse JSON lines output
        ports_by_host = {}
        all_ports = set()
        all_hosts_with_ports = set()

        output = proc.stdout.strip()
        if output:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    rec_host = rec.get("host", rec.get("ip", ""))
                    port = rec.get("port", 0)
                    protocol = rec.get("protocol", "tcp")

                    if rec_host and port:
                        if rec_host not in ports_by_host:
                            ports_by_host[rec_host] = []
                        ports_by_host[rec_host].append({
                            "port": port,
                            "protocol": protocol,
                        })
                        all_ports.add(port)
                        all_hosts_with_ports.add(rec_host)

                except json.JSONDecodeError:
                    # Fallback: plain text "host:port"
                    match = re.match(r'^(.+?):(\d+)$', line)
                    if match:
                        rec_host = match.group(1)
                        port = int(match.group(2))
                        if rec_host not in ports_by_host:
                            ports_by_host[rec_host] = []
                        ports_by_host[rec_host].append({
                            "port": port,
                            "protocol": "tcp",
                        })
                        all_ports.add(port)
                        all_hosts_with_ports.add(rec_host)

        # Sort ports per host
        for h in ports_by_host:
            ports_by_host[h].sort(key=lambda p: p["port"])

        # Build flat list for convenience
        flat_results = []
        for h in sorted(ports_by_host.keys()):
            for p in ports_by_host[h]:
                flat_results.append({
                    "host": h,
                    "port": p["port"],
                    "protocol": p["protocol"],
                })

        # Categorize well-known ports
        port_categories = {
            "web": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443],
            "mail": [25, 110, 143, 465, 587, 993, 995],
            "database": [3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984],
            "remote": [22, 23, 3389, 5900, 5901, 2222],
            "file": [21, 69, 445, 139, 2049, 873],
            "dns": [53],
        }
        categories_found = {}
        for cat, cat_ports in port_categories.items():
            found = sorted(all_ports & set(cat_ports))
            if found:
                categories_found[cat] = found

        return {
            "target": host,
            "scanned_hosts": len(hosts),
            "hosts_with_ports": len(all_hosts_with_ports),
            "total_open_ports": len(flat_results),
            "unique_ports": sorted(all_ports),
            "unique_ports_count": len(all_ports),
            "ports_by_host": ports_by_host,
            "results": flat_results,
            "categories": categories_found,
            "summary": {
                "scanned": len(hosts),
                "hosts_with_ports": len(all_hosts_with_ports),
                "total_open": len(flat_results),
                "unique_ports": len(all_ports),
                "categories_count": len(categories_found),
            },
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "naabu timeout (360s)"}
    except FileNotFoundError:
        return {"skipped": True, "reason": "naabu not installed"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
