import subprocess
import json
import re
import tempfile
import os


def scan(target: str) -> dict:
    """Run Nikto web vulnerability scanner against target."""
    url = target if target.startswith("http") else f"http://{target}"

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["nikto", "-h", url, "-Format", "json", "-output", tmp_path, "-Tuning", "x6"],
            capture_output=True, text=True, timeout=300
        )

        findings = []
        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            try:
                with open(tmp_path, "r") as f:
                    data = json.load(f)

                # Nikto JSON: can be a single object or list
                hosts = data if isinstance(data, list) else [data]
                for host in hosts:
                    for vuln in host.get("vulnerabilities", []):
                        findings.append({
                            "id": vuln.get("id", ""),
                            "method": vuln.get("method", "GET"),
                            "url": vuln.get("url", ""),
                            "description": vuln.get("msg", ""),
                            "osvdb": vuln.get("OSVDB", ""),
                        })
            except (json.JSONDecodeError, KeyError):
                # Fallback: parse stdout
                findings = _parse_stdout(result.stdout)
        else:
            findings = _parse_stdout(result.stdout)

        return {
            "target": target,
            "findings_count": len(findings),
            "findings": findings
        }

    except subprocess.TimeoutExpired:
        return {"target": target, "findings_count": 0, "findings": [],
                "error": "Timeout (300s)"}
    except FileNotFoundError:
        return {"target": target, "findings_count": 0, "findings": [],
                "error": "nikto not installed"}
    except Exception as e:
        return {"target": target, "findings_count": 0, "findings": [],
                "error": str(e)}
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _parse_stdout(stdout: str) -> list:
    """Fallback parser for Nikto text output."""
    findings = []
    for line in stdout.splitlines():
        # Nikto output lines start with "+ " for findings
        m = re.match(r'^\+\s+(.+)', line.strip())
        if m:
            msg = m.group(1).strip()
            # Skip informational/banner lines
            if msg.startswith("Target") or msg.startswith("Start") or msg.startswith("End"):
                continue
            osvdb = ""
            om = re.search(r'OSVDB-(\d+)', msg)
            if om:
                osvdb = om.group(1)
            findings.append({
                "id": osvdb or "",
                "method": "",
                "url": "",
                "description": msg,
                "osvdb": osvdb,
            })
    return findings
