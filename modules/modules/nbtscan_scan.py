import subprocess
import shutil
import ipaddress
import re


def nbtscan_scan(target: str) -> dict:
    """NetBIOS name scan using nbtscan for Windows network enumeration."""
    if not shutil.which("nbtscan"):
        return {"skipped": True, "reason": "nbtscan not installed"}

    # Determine target range
    try:
        network = ipaddress.ip_network(target, strict=False)
        scan_target = str(network)
    except ValueError:
        try:
            ipaddress.ip_address(target)
            scan_target = target
        except ValueError:
            # Hostname — scan single host
            scan_target = target

    try:
        result = subprocess.run(
            ["nbtscan", "-v", "-s", "\t", scan_target],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout.strip()
        if not output:
            return {
                "hosts": [],
                "total_hosts": 0,
                "network_range": scan_target,
                "workgroups": [],
                "servers": [],
            }

        hosts = []
        workgroups = set()
        servers = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Skip header/info lines
            if line.startswith("Doing NBT name scan") or \
               line.startswith("IP address") or \
               line.startswith("-"):
                continue

            # nbtscan -v -s \t output: IP\tNetBIOS_Name\tService\tMAC
            # or verbose: IP\tName\tNumber_type\tService
            parts = line.split("\t")
            if len(parts) < 2:
                parts = re.split(r'\s{2,}', line)
            if len(parts) < 2:
                continue

            ip_addr = parts[0].strip()
            # Validate IP
            try:
                ipaddress.ip_address(ip_addr)
            except ValueError:
                continue

            netbios_name = parts[1].strip() if len(parts) > 1 else ""
            service_or_type = parts[2].strip() if len(parts) > 2 else ""
            mac = ""

            # Find MAC address (XX-XX-XX-XX-XX-XX pattern)
            for p in parts:
                p = p.strip()
                if re.match(r'^[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}$', p):
                    mac = p
                    break

            # Detect services from NetBIOS suffix codes
            services = []
            is_server = False
            is_dc = False
            workgroup = ""

            svc_lower = service_or_type.lower()
            if "<00>" in line or "workstation" in svc_lower:
                services.append("Workstation")
            if "<20>" in line or "file server" in svc_lower or "server" in svc_lower:
                services.append("File Server")
                is_server = True
            if "<1c>" in line or "domain controller" in svc_lower:
                services.append("Domain Controller")
                is_dc = True
            if "<1b>" in line or "master browser" in svc_lower:
                services.append("Master Browser")
            if "<1d>" in line:
                services.append("Master Browser")
            if "<1e>" in line or "browser" in svc_lower:
                services.append("Browser Election")
            if "<03>" in line or "messenger" in svc_lower:
                services.append("Messenger")

            # Extract workgroup/domain
            if len(parts) > 3:
                for p in parts[1:]:
                    p = p.strip()
                    if p and p != netbios_name and not re.match(r'^[0-9a-fA-F]{2}[-:]', p) and \
                       p not in ["<00>", "<20>", "<1c>", "<1b>", "<1d>", "<1e>", "<03>"] and \
                       not p.startswith("<"):
                        workgroup = p
                        break

            if workgroup:
                workgroups.add(workgroup)

            host_entry = {
                "ip": ip_addr,
                "netbios_name": netbios_name,
                "mac": mac,
                "services": services if services else ["Unknown"],
                "workgroup": workgroup,
                "is_server": is_server,
                "is_dc": is_dc,
            }

            # Deduplicate by IP (keep richest entry)
            existing = next((h for h in hosts if h["ip"] == ip_addr), None)
            if existing:
                existing["services"] = list(set(existing["services"] + services))
                if not existing["netbios_name"] and netbios_name:
                    existing["netbios_name"] = netbios_name
                if not existing["mac"] and mac:
                    existing["mac"] = mac
                if not existing["workgroup"] and workgroup:
                    existing["workgroup"] = workgroup
                existing["is_server"] = existing["is_server"] or is_server
                existing["is_dc"] = existing["is_dc"] or is_dc
            else:
                hosts.append(host_entry)

        servers = [h for h in hosts if h.get("is_server") or h.get("is_dc")]
        dcs = [h for h in hosts if h.get("is_dc")]

        return {
            "hosts": hosts,
            "total_hosts": len(hosts),
            "network_range": scan_target,
            "workgroups": sorted(workgroups),
            "servers": [{"ip": s["ip"], "name": s["netbios_name"], "services": s["services"]} for s in servers],
            "domain_controllers": [{"ip": d["ip"], "name": d["netbios_name"]} for d in dcs],
            "total_servers": len(servers),
            "total_dcs": len(dcs),
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "nbtscan timeout (120s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
