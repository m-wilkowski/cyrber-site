import subprocess
import json
import os
import re
import tempfile
import shutil


def _clean_target(target: str) -> str:
    """Strip protocol, path, port from target."""
    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    return host.strip().lower()


def amass_scan(target: str) -> dict:
    """Run amass passive enum against target and parse results.

    Args:
        target: Domain name or hostname.

    Returns:
        Dict with subdomain enumeration results.
    """
    host = _clean_target(target)
    if not host:
        return {"skipped": True, "reason": "empty target"}

    amass_bin = shutil.which("amass")
    if not amass_bin:
        return {"skipped": True, "reason": "amass not installed"}

    json_out = os.path.join(tempfile.gettempdir(), f"amass_{host}.json")

    # Remove stale output
    try:
        if os.path.isfile(json_out):
            os.remove(json_out)
    except OSError:
        pass

    try:
        cmd = [
            amass_bin, "enum",
            "-passive",
            "-d", host,
            "-json", json_out,
            "-timeout", "3",
        ]

        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=240,
        )

        # Parse JSON output — one JSON object per line
        subdomains = set()
        ip_addresses = set()
        asns = set()
        sources = set()

        if os.path.isfile(json_out):
            try:
                with open(json_out, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        # Extract subdomain name
                        name = rec.get("name", "")
                        if name:
                            subdomains.add(name.lower())

                        # Extract IP addresses from addresses list
                        addresses = rec.get("addresses", [])
                        if isinstance(addresses, list):
                            for addr in addresses:
                                ip = addr.get("ip", "") if isinstance(addr, dict) else ""
                                if ip:
                                    ip_addresses.add(ip)
                                asn = addr.get("asn", 0) if isinstance(addr, dict) else 0
                                if asn:
                                    asns.add(asn)

                        # Extract source
                        source = rec.get("source", "") or rec.get("sources", "")
                        if isinstance(source, list):
                            sources.update(source)
                        elif source:
                            sources.add(source)

            except IOError:
                pass
            finally:
                try:
                    os.remove(json_out)
                except OSError:
                    pass

        return {
            "target": host,
            "subdomains": sorted(subdomains),
            "ip_addresses": sorted(ip_addresses),
            "asns": sorted(asns),
            "sources": sorted(sources),
            "total_count": len(subdomains),
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "amass timeout (240s)"}
    except FileNotFoundError:
        return {"skipped": True, "reason": "amass not installed"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
    finally:
        try:
            if os.path.isfile(json_out):
                os.remove(json_out)
        except OSError:
            pass
