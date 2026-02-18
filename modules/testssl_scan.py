import subprocess
import json
import os
import tempfile
import socket

TESTSSL = os.path.expanduser("~/testssl.sh/testssl.sh")

def scan(target: str) -> dict:
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        sock = socket.create_connection((host, 443), timeout=5)
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"target": target, "error": "Port 443 not open", "findings": []}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmpfile = f.name

    try:
        subprocess.run(
            [TESTSSL, "--jsonfile", tmpfile, "--quiet", host],
            capture_output=True, text=True, timeout=300
        )

        findings = []
        if os.path.exists(tmpfile):
            with open(tmpfile) as f:
                content = f.read().strip()
            # Napraw nieprawidłowy JSON - usuń trailing commas
            data = json.loads(content)
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            for item in data:
                sev = item.get("severity", "INFO")
                if sev in severity_order:
                    findings.append({
                        "id": item.get("id", ""),
                        "finding": item.get("finding", ""),
                        "severity": sev,
                        "cve": item.get("cve", "")
                    })

        return {"target": target, "findings_count": len(findings), "findings": findings}

    except subprocess.TimeoutExpired:
        return {"target": target, "error": "Timeout", "findings": []}
    except json.JSONDecodeError as e:
        return {"target": target, "error": f"JSON parse error: {e}", "findings": []}
    except Exception as e:
        return {"target": target, "error": str(e), "findings": []}
    finally:
        if os.path.exists(tmpfile):
            os.unlink(tmpfile)
