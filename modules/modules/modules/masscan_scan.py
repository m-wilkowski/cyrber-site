import subprocess
import json
import tempfile
import os


def scan(target: str, ports: str = "1-65535", rate: int = 1000) -> dict:
    """Run Masscan fast port scanner against target."""
    # Strip protocol/path — masscan needs IP or CIDR
    host = target
    if host.startswith("http"):
        host = host.split("://")[1].split("/")[0].split(":")[0]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["masscan", host, "-p", ports, "--rate", str(rate),
             "-oJ", tmp_path, "--wait", "3"],
            capture_output=True, text=True, timeout=300
        )

        open_ports = []
        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            try:
                with open(tmp_path, "r") as f:
                    raw = f.read().strip()

                # Masscan JSON: array with trailing commas, sometimes malformed
                # Fix: strip trailing comma before closing bracket
                raw = raw.rstrip().rstrip(",")
                if not raw.endswith("]"):
                    raw += "]"
                if not raw.startswith("["):
                    raw = "[" + raw

                data = json.loads(raw)
                for entry in data:
                    for port_info in entry.get("ports", []):
                        open_ports.append({
                            "port": port_info.get("port"),
                            "protocol": port_info.get("proto", "tcp"),
                            "status": port_info.get("status", "open"),
                            "ip": entry.get("ip", host),
                        })
            except (json.JSONDecodeError, KeyError):
                open_ports = _parse_stdout(result.stdout, host)
        else:
            open_ports = _parse_stdout(result.stdout, host)

        # Sort by port number and deduplicate
        seen = set()
        unique_ports = []
        for p in sorted(open_ports, key=lambda x: x["port"]):
            key = (p["ip"], p["port"], p["protocol"])
            if key not in seen:
                seen.add(key)
                unique_ports.append(p)

        return {
            "target": target,
            "ports_count": len(unique_ports),
            "ports": unique_ports,
            "findings_count": len(unique_ports),
        }

    except subprocess.TimeoutExpired:
        return {"target": target, "ports_count": 0, "ports": [],
                "findings_count": 0, "error": "Timeout (300s)"}
    except FileNotFoundError:
        return {"target": target, "ports_count": 0, "ports": [],
                "findings_count": 0, "error": "masscan not installed"}
    except Exception as e:
        return {"target": target, "ports_count": 0, "ports": [],
                "findings_count": 0, "error": str(e)}
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _parse_stdout(stdout: str, default_host: str) -> list:
    """Fallback parser for masscan text output."""
    import re
    ports = []
    for line in stdout.splitlines():
        # Masscan output: "Discovered open port 80/tcp on 192.168.1.1"
        m = re.match(
            r'Discovered open port (\d+)/(tcp|udp) on (\S+)', line.strip())
        if m:
            ports.append({
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "status": "open",
                "ip": m.group(3),
            })
    return ports
