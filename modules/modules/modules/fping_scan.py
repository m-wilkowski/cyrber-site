import subprocess
import shutil
import ipaddress
import re


def fping_scan(target: str) -> dict:
    """Fast ICMP ping sweep using fping for host reachability discovery."""
    if not shutil.which("fping"):
        return {"skipped": True, "reason": "fping not installed"}

    # Build target list: CIDR range or single host
    try:
        network = ipaddress.ip_network(target, strict=False)
        cidr = str(network)
        use_generate = True
    except ValueError:
        # Single hostname or IP
        cidr = target
        use_generate = False

    try:
        if use_generate:
            cmd = ["fping", "-a", "-g", cidr, "-q", "-r", "1", "-t", "200"]
        else:
            cmd = ["fping", "-a", "-q", "-r", "1", "-t", "200", target]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        # fping -a prints alive hosts to stdout, unreachable to stderr
        alive_output = result.stdout.strip()
        unreachable_output = result.stderr.strip()

        alive_hosts = []
        if alive_output:
            for line in alive_output.splitlines():
                ip_str = line.strip()
                if ip_str:
                    alive_hosts.append(ip_str)

        unreachable_hosts = []
        if unreachable_output:
            for line in unreachable_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                # fping stderr format: "IP is unreachable" or "ICMP Host Unreachable from IP for ICMP ..."
                match = re.match(r'^(\S+)\s+is\s+unreachable', line)
                if match:
                    unreachable_hosts.append(match.group(1))

        # Run detailed latency scan on alive hosts
        latency_data = []
        if alive_hosts:
            latency_cmd = ["fping", "-c", "3", "-q"] + alive_hosts
            latency_result = subprocess.run(
                latency_cmd, capture_output=True, text=True, timeout=60
            )
            # fping -c output goes to stderr:
            # host : xmt/rcv/%loss = 3/3/0%, min/avg/max = 0.12/0.15/0.20
            for line in latency_result.stderr.splitlines():
                line = line.strip()
                if not line:
                    continue
                match = re.match(
                    r'^(\S+)\s+:\s+xmt/rcv/%loss\s+=\s+(\d+)/(\d+)/(\d+)%'
                    r'(?:,\s+min/avg/max\s+=\s+([\d.]+)/([\d.]+)/([\d.]+))?',
                    line
                )
                if match:
                    host = match.group(1)
                    sent = int(match.group(2))
                    recv = int(match.group(3))
                    loss = int(match.group(4))
                    min_ms = float(match.group(5)) if match.group(5) else None
                    avg_ms = float(match.group(6)) if match.group(6) else None
                    max_ms = float(match.group(7)) if match.group(7) else None

                    status = "stable"
                    if loss > 0 and loss < 100:
                        status = "unstable"
                    elif loss >= 100:
                        status = "down"

                    entry = {
                        "ip": host,
                        "sent": sent,
                        "recv": recv,
                        "loss_pct": loss,
                        "status": status,
                    }
                    if avg_ms is not None:
                        entry["min_ms"] = min_ms
                        entry["avg_ms"] = avg_ms
                        entry["max_ms"] = max_ms
                    latency_data.append(entry)

        # Compute summary stats
        alive_count = len(alive_hosts)
        unreachable_count = len(unreachable_hosts)
        total_scanned = alive_count + unreachable_count
        avg_latencies = [d["avg_ms"] for d in latency_data if d.get("avg_ms") is not None]
        unstable_count = sum(1 for d in latency_data if d.get("status") == "unstable")

        return {
            "alive_hosts": alive_hosts,
            "unreachable_hosts": unreachable_hosts[:50],
            "latency": latency_data,
            "total_alive": alive_count,
            "total_unreachable": unreachable_count,
            "total_scanned": total_scanned,
            "unstable_count": unstable_count,
            "network_range": cidr,
            "avg_latency_ms": round(sum(avg_latencies) / len(avg_latencies), 2) if avg_latencies else None,
            "max_latency_ms": round(max(avg_latencies), 2) if avg_latencies else None,
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "fping timeout (120s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
