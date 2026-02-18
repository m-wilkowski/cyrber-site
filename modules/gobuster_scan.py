import subprocess
import re

def scan(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> dict:
    url = target if target.startswith("http") else f"http://{target}"
    try:
        result = subprocess.run(
            ["gobuster", "dir", "-u", url, "-w", wordlist, "--no-progress", "-q"],
            capture_output=True, text=True, timeout=120
        )
        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: /path (Status: 200) [Size: 1234]
            m = re.match(r'^(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?', line)
            if m:
                findings.append({
                    "path": m.group(1),
                    "status": int(m.group(2)),
                    "size": int(m.group(3)) if m.group(3) else None
                })
        return {"target": target, "findings_count": len(findings), "findings": findings}
    except subprocess.TimeoutExpired:
        return {"target": target, "error": "Timeout", "findings": []}
    except Exception as e:
        return {"target": target, "error": str(e), "findings": []}
