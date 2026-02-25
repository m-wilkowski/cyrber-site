import subprocess
import json
import os
import re
import shutil


def _clean_target(target: str) -> str:
    """Strip protocol, path, port from target."""
    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    return host.strip().lower()


def subfinder_scan(target: str) -> dict:
    """Run subfinder passive subdomain enumeration against target.

    Args:
        target: Domain name or hostname.

    Returns:
        Dict with subdomain enumeration results.
    """
    host = _clean_target(target)
    if not host:
        return {"skipped": True, "reason": "empty target"}

    subfinder_bin = shutil.which("subfinder")
    if not subfinder_bin:
        return {"skipped": True, "reason": "subfinder not installed"}

    try:
        cmd = [
            subfinder_bin,
            "-d", host,
            "-silent",
            "-json",
            "-timeout", "5",
            "-t", "50",
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        subdomains = set()
        sources = set()
        ip_addresses = set()

        output = proc.stdout.strip()
        if output:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    host_found = rec.get("host", "")
                    if host_found:
                        subdomains.add(host_found.lower())
                    source = rec.get("source", "")
                    if source:
                        sources.add(source)
                    # Some subfinder JSON includes ip field
                    ip = rec.get("ip", "")
                    if ip:
                        ip_addresses.add(ip)
                except json.JSONDecodeError:
                    # Plain text mode fallback — one subdomain per line
                    if line and '.' in line and not line.startswith('{'):
                        subdomains.add(line.lower())

        # If JSON didn't yield results, try plain text from stderr or re-run
        if not subdomains and proc.stderr:
            for line in proc.stderr.strip().splitlines():
                line = line.strip()
                if line and '.' in line and not line.startswith('['):
                    subdomains.add(line.lower())

        return {
            "target": host,
            "subdomains": sorted(subdomains),
            "sources": sorted(sources),
            "ip_addresses": sorted(ip_addresses),
            "total_count": len(subdomains),
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "subfinder timeout (300s)"}
    except FileNotFoundError:
        return {"skipped": True, "reason": "subfinder not installed"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
