import subprocess
import shutil
import ipaddress
import re


def arpscan_scan(target: str) -> dict:
    """ARP scan using arp-scan for local network host discovery."""
    if not shutil.which("arp-scan"):
        return {"skipped": True, "reason": "arp-scan not installed"}

    # Determine CIDR range
    try:
        network = ipaddress.ip_network(target, strict=False)
        cidr = str(network)
    except ValueError:
        try:
            ip = ipaddress.ip_address(target)
            cidr = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            return {"skipped": True, "reason": f"Cannot determine network range for: {target}"}

    try:
        result = subprocess.run(
            ["arp-scan", "--localnet" if cidr.endswith("/24") else cidr,
             "--retry=2", "--timeout=500", "--plain"],
            capture_output=True, text=True, timeout=60
        )
        # arp-scan also outputs to stderr for interface info; combine
        output = result.stdout.strip()
        if not output:
            return {
                "hosts": [],
                "total_hosts": 0,
                "network_range": cidr,
                "duplicates": [],
            }

        hosts = []
        duplicates = []
        seen_ips = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Skip summary lines
            if line.startswith("Starting") or line.startswith("Interface") or \
               line.startswith("Ending") or "packets received" in line or \
               "responded" in line:
                continue

            # arp-scan plain output: IP\tMAC\tVendor
            parts = line.split("\t")
            if len(parts) < 2:
                parts = re.split(r'\s{2,}', line)
            if len(parts) < 2:
                continue

            ip_addr = parts[0].strip()
            try:
                ipaddress.ip_address(ip_addr)
            except ValueError:
                continue

            mac = parts[1].strip() if len(parts) > 1 else ""
            vendor = parts[2].strip() if len(parts) > 2 else ""

            # Detect duplicates (same IP, different MAC)
            if ip_addr in seen_ips:
                if mac != seen_ips[ip_addr]["mac"]:
                    duplicates.append({
                        "ip": ip_addr,
                        "mac_1": seen_ips[ip_addr]["mac"],
                        "vendor_1": seen_ips[ip_addr]["vendor"],
                        "mac_2": mac,
                        "vendor_2": vendor,
                    })
                continue

            seen_ips[ip_addr] = {"mac": mac, "vendor": vendor}
            hosts.append({
                "ip": ip_addr,
                "mac": mac,
                "vendor": vendor,
            })

        return {
            "hosts": hosts,
            "total_hosts": len(hosts),
            "network_range": cidr,
            "duplicates": duplicates,
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "arp-scan timeout (60s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
