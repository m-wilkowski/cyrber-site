import subprocess
import re
import os

SQLMAP_PATH = os.getenv("SQLMAP_PATH", "/opt/sqlmap/sqlmap.py")

def scan(target: str) -> dict:
    url = target if target.startswith("http") else f"http://{target}"
    try:
        result = subprocess.run(
            [
                "python3", SQLMAP_PATH,
                "-u", url,
                "--batch",
                "--level=1",
                "--risk=1",
                "--timeout=30",
                "--retries=1",
                "--output-dir=/tmp/sqlmap",
                "--forms",
                "--crawl=2"
            ],
            capture_output=True, text=True, timeout=180
        )
        output = result.stdout + result.stderr
        findings = []

        if "is vulnerable" in output:
            for line in output.splitlines():
                if "is vulnerable" in line or "Parameter:" in line or "Type:" in line:
                    line = line.strip()
                    if line:
                        findings.append(line)

        injectable_params = []
        for line in output.splitlines():
            m = re.search(r"Parameter '(.+?)' is vulnerable", line)
            if m:
                injectable_params.append(m.group(1))

        vulnerable = len(findings) > 0

        return {
            "target": target,
            "vulnerable": vulnerable,
            "injectable_params": injectable_params,
            "findings_count": len(injectable_params),
            "findings": findings,
            "raw_summary": output[-3000:] if len(output) > 3000 else output
        }
    except subprocess.TimeoutExpired:
        return {"target": target, "error": "Timeout", "vulnerable": False, "findings": []}
    except Exception as e:
        return {"target": target, "error": str(e), "vulnerable": False, "findings": []}
