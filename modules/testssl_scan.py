import subprocess
import json
import os

TESTSSL = os.path.expanduser("~/bin/testssl.sh")

def scan(target: str) -> dict:
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    cmd = [TESTSSL, "--jsonfile", "/dev/stdout", "--quiet", "--fast", host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        findings = []
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "OK": 0}

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, list):
                    for item in data:
                        sev = item.get("severity", "INFO")
                        if severity_map.get(sev, 0) >= 1:
                            findings.append({
                                "id": item.get("id", ""),
                                "finding": item.get("finding", ""),
                                "severity": sev,
                                "cve": item.get("cve", "")
                            })
            except json.JSONDecodeError:
                continue

        return {"target": target, "findings_count": len(findings), "findings": findings}
    except subprocess.TimeoutExpired:
        return {"target": target, "error": "Timeout", "findings": []}
    except Exception as e:
        return {"target": target, "error": str(e), "findings": []}
