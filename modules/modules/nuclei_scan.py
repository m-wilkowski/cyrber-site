import subprocess
import json
import os

NUCLEI_PATH = os.environ.get("NUCLEI_PATH", "/usr/local/bin/nuclei")

def scan(target: str, tags: str = "apache,ssh,linux,php,mysql") -> dict:
    result = subprocess.run(
        [
            NUCLEI_PATH,
            "-u", target,
            "-tags", tags,
            "-jsonl",
            "-silent"
        ],
        capture_output=True,
        text=True,
        timeout=300
    )
    
    findings = []
    for line in result.stdout.strip().split('\n'):
        if line:
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    
    return {
        "target": target,
        "findings_count": len(findings),
        "findings": findings
    }
