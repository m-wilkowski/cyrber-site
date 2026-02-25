import subprocess
import shutil
import ipaddress
import re


def netdiscover_scan(target: str) -> dict:
    """Network discovery scan using netdiscover ARP scanner."""
    if not shutil.which("netdiscover"):
        return {"skipped": True, "reason": "netdiscover not installed"}

    # Determine CIDR range
    try:
        network = ipaddress.ip_network(target, strict=False)
        cidr = str(network)
    except ValueError:
        # Single IP or hostname — try to parse as IP and use /24
        try:
            ip = ipaddress.ip_address(target)
            cidr = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            return {"skipped": True, "reason": f"Cannot determine network range for: {target}"}

    try:
        result = subprocess.run(
            ["netdiscover", "-r", cidr, "-P", "-N", "-c", "3"],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout.strip()
        if not output:
            return {
                "hosts": [],
                "total_hosts": 0,
                "network_range": cidr,
            }

        hosts = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # netdiscover -P format: IP  MAC  Count  Len  Vendor
            # or sometimes: IP  MAC  Count  Len  Vendor/Hostname
            parts = re.split(r'\s{2,}', line)
            if len(parts) < 2:
                continue
            ip_addr = parts[0].strip()
            # Validate it looks like an IP
            try:
                ipaddress.ip_address(ip_addr)
            except ValueError:
                continue

            mac = parts[1].strip() if len(parts) > 1 else ""
            # Count and Len are columns 2,3; Vendor is column 4+
            vendor = parts[4].strip() if len(parts) > 4 else (parts[2].strip() if len(parts) > 2 else "")
            # Sometimes vendor includes hostname after /
            hostname = ""
            if "/" in vendor:
                vendor_parts = vendor.split("/", 1)
                vendor = vendor_parts[0].strip()
                hostname = vendor_parts[1].strip()

            hosts.append({
                "ip": ip_addr,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
            })

        return {
            "hosts": hosts,
            "total_hosts": len(hosts),
            "network_range": cidr,
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "netdiscover timeout (60s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
