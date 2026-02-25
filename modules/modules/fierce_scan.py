import subprocess
import shutil
import re


def fierce_scan(target: str) -> dict:
    """
    Run Fierce DNS reconnaissance against a domain.
    Fierce performs DNS zone transfer attempts, subdomain brute-forcing,
    and nearby IP range scanning to map a target's DNS footprint.
    """
    fierce_bin = shutil.which("fierce")
    if not fierce_bin:
        return {"skipped": True, "reason": "fierce not installed"}

    # Fierce works on domains, extract hostname
    host = target.strip()
    for prefix in ["http://", "https://", "ftp://"]:
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0].split(":")[0]

    if not host or host.replace(".", "").isdigit():
        return {"skipped": True, "reason": "Fierce requires a domain name, not an IP address"}

    result = {
        "target": host,
        "subdomains": [],
        "zone_transfer": {"attempted": False, "successful": False, "nameservers": []},
        "nearby_ips": [],
        "nameservers": [],
        "wildcard": None,
        "total_subdomains": 0,
        "total_nearby": 0,
        "total_nameservers": 0,
    }

    try:
        cmd = [fierce_bin, "--domain", host]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )
        output = proc.stdout + "\n" + proc.stderr
        _parse_fierce_output(output, result)
    except subprocess.TimeoutExpired:
        result["error"] = "Fierce scan timed out after 180s"
    except Exception as e:
        result["error"] = str(e)

    return result


def _parse_fierce_output(output: str, result: dict):
    """Parse fierce text output into structured data."""
    lines = output.splitlines()
    subdomains = {}
    nameservers = []
    nearby = []
    zone_transfer_attempted = False
    zone_transfer_success = False
    zt_nameservers = []
    wildcard = None

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1

        if not line:
            continue

        # Nameservers section
        # "NS: ns1.example.com. ns2.example.com."
        ns_match = re.match(r"^NS:\s+(.+)", line)
        if ns_match:
            for ns in ns_match.group(1).split():
                ns_clean = ns.strip().rstrip(".")
                if ns_clean and ns_clean not in nameservers:
                    nameservers.append(ns_clean)
            continue

        # SOA record
        # "SOA: ns1.example.com. (admin@example.com)"
        soa_match = re.match(r"^SOA:\s+(\S+)", line)
        if soa_match:
            soa_ns = soa_match.group(1).rstrip(".")
            if soa_ns and soa_ns not in nameservers:
                nameservers.append(soa_ns)
            continue

        # Zone transfer attempts
        # "Trying zone transfer first..."
        if "zone transfer" in line.lower():
            zone_transfer_attempted = True
            continue

        # Zone transfer results
        # "Unsuccessful in zone transfer"
        if "unsuccessful" in line.lower() and "zone transfer" in line.lower():
            zone_transfer_attempted = True
            zone_transfer_success = False
            continue

        if "successful" in line.lower() and "zone transfer" in line.lower():
            zone_transfer_attempted = True
            zone_transfer_success = True
            continue

        # Zone transfer nameserver
        zt_ns_match = re.match(r"^Trying:\s+(\S+)", line)
        if zt_ns_match:
            ns_name = zt_ns_match.group(1).rstrip(".")
            if ns_name:
                zt_nameservers.append(ns_name)
            continue

        # Wildcard detection
        # "Wildcard: 1.2.3.4"
        wc_match = re.match(r"^Wildcard:\s+(\S+)", line)
        if wc_match:
            wildcard = wc_match.group(1)
            continue

        # Found subdomain entries
        # "Found: subdomain.example.com. (1.2.3.4)"
        found_match = re.match(r"^Found:\s+(\S+?)\.?\s+\((\d+\.\d+\.\d+\.\d+)\)", line)
        if found_match:
            name = found_match.group(1).rstrip(".")
            ip = found_match.group(2)
            if name not in subdomains:
                subdomains[name] = {"name": name, "ip": ip, "source": "brute"}
            continue

        # Fierce output format: "hostname.example.com. 1.2.3.4"
        # or "1.2.3.4 hostname.example.com."
        sub_match = re.match(r"^(\S+?\.?\s+)(\d+\.\d+\.\d+\.\d+)\s*$", line)
        if sub_match:
            name = sub_match.group(1).strip().rstrip(".")
            ip = sub_match.group(2)
            if name and "." in name and name not in subdomains:
                subdomains[name] = {"name": name, "ip": ip, "source": "dns"}
            continue

        sub_match2 = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+(\S+)$", line)
        if sub_match2:
            ip = sub_match2.group(1)
            name = sub_match2.group(2).rstrip(".")
            if name and "." in name and name not in subdomains:
                subdomains[name] = {"name": name, "ip": ip, "source": "dns"}
            continue

        # Nearby IPs section
        # "Nearby:" header followed by IP entries
        if line.startswith("Nearby:") or "nearby" in line.lower():
            continue

        # Nearby IP entries: "1.2.3.4    hostname"
        nearby_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+(.+)", line)
        if nearby_match:
            ip = nearby_match.group(1)
            hostname = nearby_match.group(2).strip().rstrip(".")
            if hostname and not hostname.startswith("-"):
                entry = {"ip": ip, "hostname": hostname}
                if entry not in nearby:
                    nearby.append(entry)
            continue

    result["subdomains"] = list(subdomains.values())
    result["total_subdomains"] = len(subdomains)
    result["nameservers"] = nameservers
    result["total_nameservers"] = len(nameservers)
    result["nearby_ips"] = nearby[:100]
    result["total_nearby"] = len(nearby)
    result["wildcard"] = wildcard
    result["zone_transfer"] = {
        "attempted": zone_transfer_attempted,
        "successful": zone_transfer_success,
        "nameservers": zt_nameservers,
    }
