import subprocess
import json
import re
import tempfile
import os


def scan(target: str) -> dict:
    """Run theHarvester OSINT scanner for subdomains and emails."""
    # theHarvester expects a domain, strip protocol/path
    domain = target
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0].split(':')[0]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "anubis,crtsh,dnsdumpster,hackertarget,rapiddns,urlscan",
             "-f", tmp_path],
            capture_output=True, text=True, timeout=180
        )

        emails = []
        subdomains = []
        ips = []

        # Try JSON output first
        json_path = tmp_path
        # theHarvester appends .json to the filename
        if not os.path.exists(json_path) or os.path.getsize(json_path) == 0:
            json_path = tmp_path + ".json"

        if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
            try:
                with open(json_path, "r") as f:
                    data = json.load(f)
                emails = data.get("emails", [])
                subdomains = data.get("hosts", [])
                ips = data.get("ips", [])
            except (json.JSONDecodeError, KeyError):
                emails, subdomains, ips = _parse_stdout(result.stdout)
        else:
            emails, subdomains, ips = _parse_stdout(result.stdout)

        # Deduplicate
        emails = sorted(set(emails))
        subdomains = sorted(set(subdomains))
        ips = sorted(set(ips))

        return {
            "target": domain,
            "emails_count": len(emails),
            "emails": emails,
            "subdomains_count": len(subdomains),
            "subdomains": subdomains,
            "ips_count": len(ips),
            "ips": ips,
            "findings_count": len(emails) + len(subdomains),
        }

    except subprocess.TimeoutExpired:
        return {"target": domain, "findings_count": 0, "emails": [],
                "subdomains": [], "ips": [], "error": "Timeout (180s)"}
    except FileNotFoundError:
        return {"target": domain, "findings_count": 0, "emails": [],
                "subdomains": [], "ips": [], "error": "theHarvester not installed"}
    except Exception as e:
        return {"target": domain, "findings_count": 0, "emails": [],
                "subdomains": [], "ips": [], "error": str(e)}
    finally:
        for p in [tmp_path, tmp_path + ".json", tmp_path + ".xml"]:
            if os.path.exists(p):
                os.unlink(p)


def _parse_stdout(stdout: str) -> tuple:
    """Fallback parser for theHarvester text output."""
    emails = []
    subdomains = []
    ips = []

    section = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("["):
            if "Emails" in line:
                section = "emails"
            elif "Hosts" in line or "host" in line.lower():
                section = "hosts"
            elif "IPs" in line:
                section = "ips"
            continue

        if section == "emails" and "@" in line:
            emails.append(line)
        elif section == "hosts" and "." in line:
            # Could be "subdomain:ip" or just "subdomain"
            host = line.split(":")[0].strip()
            if host:
                subdomains.append(host)
        elif section == "ips":
            ip_match = re.match(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
            if ip_match:
                ips.append(ip_match.group(1))

    return emails, subdomains, ips
