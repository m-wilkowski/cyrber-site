import subprocess
import shutil
import re
import socket


def traceroute_scan(target: str) -> dict:
    """Network path analysis using traceroute."""
    if not shutil.which("traceroute"):
        return {"skipped": True, "reason": "traceroute not installed"}

    # Resolve hostname to get destination IP
    dest_ip = None
    try:
        dest_ip = socket.gethostbyname(target)
    except socket.gaierror:
        dest_ip = target

    try:
        result = subprocess.run(
            ["traceroute", "-n", "-m", "30", "-w", "2", "-q", "2", target],
            capture_output=True, text=True, timeout=90
        )
        output = result.stdout.strip()
        if not output:
            return {"skipped": True, "reason": "no output from traceroute"}

        hops = []
        lines = output.splitlines()

        for line in lines:
            line = line.strip()
            # Skip header line: "traceroute to ..."
            if line.lower().startswith("traceroute to"):
                continue
            if not line:
                continue

            # Format: "N  IP  rtt1 ms  rtt2 ms" or "N  * * *"
            match = re.match(r'^\s*(\d+)\s+(.+)$', line)
            if not match:
                continue

            hop_num = int(match.group(1))
            rest = match.group(2).strip()

            # Parse probes from the rest of the line
            # Each probe: IP rtt ms  or  * (timeout)
            probe_ips = []
            rtts = []
            timeout_count = 0

            # Split tokens
            tokens = rest.split()
            i = 0
            while i < len(tokens):
                token = tokens[i]
                if token == "*":
                    timeout_count += 1
                    i += 1
                elif re.match(r'^\d+\.\d+\.\d+\.\d+$', token):
                    probe_ips.append(token)
                    # Next token(s) should be rtt + "ms"
                    if i + 1 < len(tokens) and tokens[i + 1] != "ms":
                        try:
                            rtts.append(float(tokens[i + 1]))
                            i += 2
                            if i < len(tokens) and tokens[i] == "ms":
                                i += 1
                            continue
                        except ValueError:
                            pass
                    elif i + 2 < len(tokens) and tokens[i + 2] == "ms":
                        try:
                            rtts.append(float(tokens[i + 1]))
                        except ValueError:
                            pass
                        i += 3
                        continue
                    i += 1
                else:
                    # Could be an RTT value
                    try:
                        rtts.append(float(token))
                        i += 1
                        if i < len(tokens) and tokens[i] == "ms":
                            i += 1
                        continue
                    except ValueError:
                        pass
                    i += 1

            # Determine primary IP for this hop
            ip = probe_ips[0] if probe_ips else None
            avg_rtt = round(sum(rtts) / len(rtts), 2) if rtts else None
            min_rtt = round(min(rtts), 2) if rtts else None
            max_rtt = round(max(rtts), 2) if rtts else None

            hop_entry = {
                "hop": hop_num,
                "ip": ip,
                "avg_rtt_ms": avg_rtt,
                "min_rtt_ms": min_rtt,
                "max_rtt_ms": max_rtt,
                "loss": timeout_count > 0,
            }

            if len(set(probe_ips)) > 1:
                hop_entry["alternate_ips"] = list(set(probe_ips))

            hops.append(hop_entry)

        # Compute summary
        total_hops = len(hops)
        reached = any(
            h.get("ip") == dest_ip for h in hops
        ) if dest_ip else False
        timeout_hops = sum(1 for h in hops if h.get("ip") is None)
        loss_hops = sum(1 for h in hops if h.get("loss"))
        all_rtts = [h["avg_rtt_ms"] for h in hops if h.get("avg_rtt_ms") is not None]
        avg_rtt_total = round(sum(all_rtts) / len(all_rtts), 2) if all_rtts else None
        max_rtt_total = round(max(all_rtts), 2) if all_rtts else None

        # Detect potential issues
        issues = []
        for h in hops:
            if h.get("ip") is None:
                issues.append(f"Hop {h['hop']}: timeout (filtered/dropped)")
            elif h.get("avg_rtt_ms") and h["avg_rtt_ms"] > 100:
                issues.append(f"Hop {h['hop']} ({h['ip']}): high latency {h['avg_rtt_ms']}ms")
            if h.get("alternate_ips"):
                issues.append(f"Hop {h['hop']}: load balancing detected ({len(h['alternate_ips'])} IPs)")

        return {
            "hops": hops,
            "total_hops": total_hops,
            "destination": target,
            "destination_ip": dest_ip,
            "reached": reached,
            "timeout_hops": timeout_hops,
            "loss_hops": loss_hops,
            "avg_rtt_ms": avg_rtt_total,
            "max_rtt_ms": max_rtt_total,
            "issues": issues[:20],
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "traceroute timeout (90s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
