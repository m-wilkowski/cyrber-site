import subprocess
import re

def parse_nmap_output(output: str) -> list:
    ports = []
    for line in output.split('\n'):
        match = re.match(
            r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)', line
        )
        if match:
            ports.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
                "version": match.group(5).strip()
            })
    return ports

def scan(target: str) -> dict:
    result = subprocess.run(
        ["nmap", "-sV", "--open", target],
        capture_output=True,
        text=True,
        timeout=120
    )
    ports = parse_nmap_output(result.stdout)
    return {
        "target": target,
        "ports": ports,
        "raw": result.stdout,
        "errors": result.stderr
    }
