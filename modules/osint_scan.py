"""Deep OSINT scanner — multi-source intelligence gathering.

Search types: domain, email, phone, person, username.
Domain mode runs 20-40 min with all engines.
"""

import os
import re
import json
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus

import requests

from modules.whois_scan import whois_scan

# ── API keys ──
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")

# ── Timeouts ──
HARVESTER_TIMEOUT = 600
AMASS_TIMEOUT = 900
DNSRECON_TIMEOUT = 600
SHERLOCK_TIMEOUT = 300
MAIGRET_TIMEOUT = 300
HOLEHE_TIMEOUT = 300
METAGOOFIL_TIMEOUT = 300
API_TIMEOUT = 30


def _clean_target(target: str) -> str:
    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    return host.strip().lower()


# ═══════════════════════════════════════════════════════════════
#  DOMAIN DEEP SCAN COMPONENTS
# ═══════════════════════════════════════════════════════════════

def _harvester_deep(host: str) -> dict:
    """theHarvester with ALL engines (600s timeout)."""
    sources = (
        "anubis,baidu,bing,bingapi,crtsh,dnsdumpster,"
        "duckduckgo,hackertarget,hunter,otx,rapiddns,"
        "securityTrails,threatminer,urlscan,yahoo"
    )
    tmp = tempfile.mktemp(prefix="cyrber_harv_")
    try:
        result = subprocess.run(
            ["theHarvester", "-d", host, "-b", sources, "-f", tmp],
            capture_output=True, text=True, timeout=HARVESTER_TIMEOUT
        )
        json_path = tmp + ".json"
        if os.path.exists(json_path):
            with open(json_path) as f:
                data = json.load(f)
            emails = [e for e in (data.get("emails", []) or []) if "@" in str(e)]
            hosts = data.get("hosts", []) or []
            ips = data.get("ips", []) or []
            return {"emails": emails, "subdomains": hosts, "ips": ips}
        # Fallback: parse stdout
        emails, hosts, ips = [], [], []
        section = None
        for line in (result.stdout or "").split("\n"):
            line = line.strip()
            if "Emails found" in line:
                section = "emails"
            elif "Hosts found" in line:
                section = "hosts"
            elif "IPs found" in line:
                section = "ips"
            elif line and section == "emails" and "@" in line:
                emails.append(line)
            elif line and section == "hosts":
                hosts.append(line.split(":")[0])
            elif line and section == "ips":
                ips.append(line)
        return {"emails": emails, "subdomains": hosts, "ips": ips}
    except subprocess.TimeoutExpired:
        return {"error": f"theHarvester timeout ({HARVESTER_TIMEOUT}s)"}
    except FileNotFoundError:
        return {"error": "theHarvester not installed"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        for ext in [".json", ".xml", ""]:
            try:
                os.remove(tmp + ext)
            except OSError:
                pass


def _amass_active(host: str) -> dict:
    """Amass active enumeration (900s timeout)."""
    amass_bin = shutil.which("amass")
    if not amass_bin:
        return {"skipped": True, "reason": "amass not installed"}
    json_out = tempfile.mktemp(prefix="cyrber_amass_", suffix=".json")
    try:
        subprocess.run(
            [amass_bin, "enum", "-active", "-d", host, "-json", json_out, "-timeout", "12"],
            capture_output=True, text=True, timeout=AMASS_TIMEOUT
        )
        subdomains = set()
        ip_addresses = set()
        asns = set()
        sources = set()
        if os.path.exists(json_out):
            with open(json_out) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    name = rec.get("name", "")
                    if name:
                        subdomains.add(name.lower())
                    for addr in (rec.get("addresses", []) or []):
                        ip = addr.get("ip", "")
                        if ip:
                            ip_addresses.add(ip)
                        asn = addr.get("asn", 0)
                        if asn:
                            asns.add(asn)
                    src = rec.get("source", "") or rec.get("sources", "")
                    if src:
                        sources.add(src)
        return {
            "subdomains": sorted(subdomains),
            "ip_addresses": sorted(ip_addresses),
            "asns": sorted(asns),
            "sources": sorted(sources),
            "total_count": len(subdomains),
        }
    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": f"amass timeout ({AMASS_TIMEOUT}s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
    finally:
        try:
            os.remove(json_out)
        except OSError:
            pass


def _dnsrecon_brute(host: str) -> dict:
    """DNSRecon with std + brute-force (600s timeout per run)."""
    dnsrecon_bin = shutil.which("dnsrecon")
    if not dnsrecon_bin:
        for path in ["/usr/local/bin/dnsrecon", "/opt/dnsrecon/dnsrecon.py"]:
            if os.path.exists(path):
                dnsrecon_bin = path
                break
    if not dnsrecon_bin:
        return {"skipped": True, "reason": "dnsrecon not installed"}

    records = []
    # Run std enumeration (SOA, NS, A, AAAA, MX, SRV) then brute-force
    for scan_type in ["std", "brt"]:
        json_out = tempfile.mktemp(prefix=f"cyrber_dns_{scan_type}_", suffix=".json")
        try:
            cmd = [dnsrecon_bin, "-d", host, "-t", scan_type, "-j", json_out]
            if scan_type == "std":
                cmd += ["-a"]  # include AXFR attempt
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=DNSRECON_TIMEOUT)
            # dnsrecon may exit non-zero but still produce partial JSON output
            _ = proc.returncode
            if os.path.exists(json_out):
                with open(json_out) as f:
                    records.extend(json.load(f))
        except subprocess.TimeoutExpired:
            pass  # continue with next scan type
        except Exception:
            pass
        finally:
            try:
                os.remove(json_out)
            except OSError:
                pass

    if not records:
        return {"skipped": True, "reason": "no dnsrecon output"}

    try:

        a_records, mx_records, ns_set, txt_records, srv_records = [], [], set(), [], []
        subdomains = set()
        zone_transfer = False
        spf_configured = False
        dmarc_configured = False

        for rec in records:
            rtype = rec.get("type", "")
            name = rec.get("name", "")
            if rtype in ("A", "AAAA"):
                a_records.append({"hostname": name, "ip": rec.get("address", ""), "type": rtype})
                if name and name != host and name.endswith("." + host):
                    subdomains.add(name.lower())
            elif rtype == "MX":
                mx_records.append({"exchange": rec.get("exchange", name), "priority": rec.get("priority", 0)})
            elif rtype == "NS":
                ns_set.add(rec.get("target", name))
            elif rtype == "TXT":
                val = rec.get("strings", "") or rec.get("target", "")
                if "v=spf1" in str(val).lower():
                    txt_records.append({"type": "SPF", "value": val})
                    spf_configured = True
                elif "v=dmarc1" in str(val).lower():
                    txt_records.append({"type": "DMARC", "value": val})
                    dmarc_configured = True
                elif "v=dkim" in str(val).lower():
                    txt_records.append({"type": "DKIM", "value": val})
                else:
                    txt_records.append({"type": "TXT", "value": val})
            elif rtype == "SRV":
                srv_records.append({"service": name, "target": rec.get("target", ""),
                                    "port": rec.get("port", 0), "priority": rec.get("priority", 0)})
            elif rtype == "info" and "Transfer" in rec.get("zone_transfer", ""):
                zone_transfer = True

        mx_records.sort(key=lambda x: x.get("priority", 0))
        return {
            "a_records": a_records, "mx_records": mx_records,
            "ns_records": sorted(ns_set), "txt_records": txt_records,
            "srv_records": srv_records, "subdomains": sorted(subdomains),
            "zone_transfer": zone_transfer,
            "spf_configured": spf_configured, "dmarc_configured": dmarc_configured,
            "total_records": len(records),
        }
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


def _crtsh_query(host: str) -> dict:
    """Query crt.sh Certificate Transparency logs."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{host}&output=json",
            timeout=API_TIMEOUT, headers={"User-Agent": "CYRBER-OSINT"}
        )
        if r.status_code != 200:
            return {"skipped": True, "reason": f"crt.sh HTTP {r.status_code}"}
        certs = r.json()
        subdomains = set()
        for cert in certs:
            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(host) and name != host:
                    subdomains.add(name)
        return {"subdomains": sorted(subdomains), "total_certs": len(certs)}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


def _virustotal_passive_dns(host: str) -> dict:
    """VirusTotal passive DNS and subdomains."""
    if not VIRUSTOTAL_API_KEY:
        return {"skipped": True, "reason": "VIRUSTOTAL_API_KEY not configured"}
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        # Subdomains
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{host}/subdomains?limit=40",
            headers=headers, timeout=API_TIMEOUT
        )
        subdomains = set()
        if r.status_code == 200:
            for item in r.json().get("data", []):
                subdomains.add(item.get("id", ""))
        # Resolutions (passive DNS)
        r2 = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{host}/resolutions?limit=40",
            headers=headers, timeout=API_TIMEOUT
        )
        ips = set()
        if r2.status_code == 200:
            for item in r2.json().get("data", []):
                attrs = item.get("attributes", {})
                ip = attrs.get("ip_address", "")
                if ip:
                    ips.add(ip)
        return {"subdomains": sorted(subdomains), "ips": sorted(ips)}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


def _shodan_host(host: str) -> dict:
    """Shodan host lookup for IP intelligence."""
    if not SHODAN_API_KEY:
        return {"skipped": True, "reason": "SHODAN_API_KEY not configured"}
    try:
        import socket
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {"skipped": True, "reason": f"Cannot resolve {host}"}

        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}",
            timeout=API_TIMEOUT
        )
        if r.status_code == 404:
            return {"ip": ip, "ports": [], "vulns": []}
        r.raise_for_status()
        data = r.json()
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        hostnames = data.get("hostnames", [])
        return {
            "ip": ip,
            "ports": sorted(ports),
            "vulns": vulns[:20],
            "hostnames": hostnames,
            "org": data.get("org", ""),
            "os": data.get("os", ""),
            "isp": data.get("isp", ""),
            "country": data.get("country_name", ""),
        }
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


def _securitytrails_subdomains(host: str) -> dict:
    """SecurityTrails subdomain enumeration."""
    if not SECURITYTRAILS_API_KEY:
        return {"skipped": True, "reason": "SECURITYTRAILS_API_KEY not configured"}
    try:
        headers = {"APIKEY": SECURITYTRAILS_API_KEY, "Content-Type": "application/json"}
        r = requests.get(
            f"https://api.securitytrails.com/v1/domain/{host}/subdomains?children_only=false",
            headers=headers, timeout=API_TIMEOUT
        )
        if r.status_code == 401:
            return {"skipped": True, "reason": "SecurityTrails API key invalid"}
        r.raise_for_status()
        data = r.json()
        subs = [f"{s}.{host}" for s in (data.get("subdomains", []) or [])]
        return {"subdomains": sorted(subs), "total": len(subs)}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


def _metagoofil_scan(host: str) -> dict:
    """Search for documents (PDF/DOC/XLS) exposed on the domain."""
    try:
        result = subprocess.run(
            ["metagoofil", "-d", host, "-t", "pdf,doc,docx,xls,xlsx,ppt,pptx",
             "-l", "100", "-o", "/tmp/metagoofil_" + host, "-n", "20"],
            capture_output=True, text=True, timeout=METAGOOFIL_TIMEOUT
        )
        lines = (result.stdout or "").split("\n")
        documents = []
        users = set()
        for line in lines:
            line = line.strip()
            if line.startswith("[*]") and ("http" in line.lower() or "." in line):
                documents.append(line.replace("[*]", "").strip())
            if "User:" in line or "Author:" in line or "Creator:" in line:
                user = line.split(":", 1)[-1].strip()
                if user and len(user) > 1 and len(user) < 80:
                    users.add(user)
        return {"documents": documents[:30], "users": sorted(users), "total_docs": len(documents)}
    except FileNotFoundError:
        return {"skipped": True, "reason": "metagoofil not installed"}
    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": f"metagoofil timeout ({METAGOOFIL_TIMEOUT}s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


def _google_dorks(host: str) -> dict:
    """Automated Google dork queries via theHarvester/search engines."""
    dorks = [
        f"site:{host} filetype:pdf",
        f"site:{host} inurl:admin",
        f'site:{host} "email" OR "contact"',
        f'"@{host}" -site:{host}',
        f"site:{host} filetype:sql OR filetype:env OR filetype:log",
        f"site:{host} inurl:login OR inurl:signin",
    ]
    results = []
    for dork in dorks:
        results.append({"query": dork, "status": "prepared"})
    return {"dorks": results, "total": len(dorks)}


# ═══════════════════════════════════════════════════════════════
#  EMAIL SCAN COMPONENTS
# ═══════════════════════════════════════════════════════════════

def _hibp_lookup(email: str) -> dict:
    """HaveIBeenPwned breach check."""
    if not HIBP_API_KEY:
        return {"skipped": True, "reason": "HIBP_API_KEY not configured"}
    try:
        headers = {"hibp-api-key": HIBP_API_KEY, "user-agent": "CYRBER-OSINT"}
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers, params={"truncateResponse": "false"}, timeout=15
        )
        if r.status_code == 404:
            return {"breaches": [], "total": 0}
        if r.status_code == 401:
            return {"skipped": True, "reason": "HIBP API key invalid"}
        r.raise_for_status()
        breaches = r.json()
        return {
            "breaches": [
                {"name": b.get("Name", ""), "domain": b.get("Domain", ""),
                 "breach_date": b.get("BreachDate", ""), "data_classes": b.get("DataClasses", []),
                 "pwn_count": b.get("PwnCount", 0), "is_verified": b.get("IsVerified", False)}
                for b in breaches
            ],
            "total": len(breaches),
        }
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


def _hibp_pastes(email: str) -> dict:
    """HaveIBeenPwned paste check."""
    if not HIBP_API_KEY:
        return {"skipped": True}
    try:
        headers = {"hibp-api-key": HIBP_API_KEY, "user-agent": "CYRBER-OSINT"}
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
            headers=headers, timeout=15
        )
        if r.status_code == 404:
            return {"pastes": [], "total": 0}
        r.raise_for_status()
        pastes = r.json()
        return {
            "pastes": [
                {"source": p.get("Source", ""), "title": p.get("Title", ""),
                 "date": p.get("Date", ""), "email_count": p.get("EmailCount", 0)}
                for p in pastes
            ],
            "total": len(pastes),
        }
    except Exception:
        return {"skipped": True}


def _holehe_check(email: str) -> dict:
    """Check email registration across 120+ platforms using holehe."""
    try:
        result = subprocess.run(
            ["holehe", email, "--no-color", "--only-used"],
            capture_output=True, text=True, timeout=HOLEHE_TIMEOUT
        )
        lines = (result.stdout or "").split("\n")
        platforms = []
        for line in lines:
            line = line.strip()
            if "[+]" in line:
                # Parse platform name from holehe output
                parts = line.replace("[+]", "").strip().split()
                if parts:
                    platforms.append({"platform": parts[0], "registered": True})
        return {"platforms": platforms, "total": len(platforms)}
    except FileNotFoundError:
        return {"skipped": True, "reason": "holehe not installed"}
    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": f"holehe timeout ({HOLEHE_TIMEOUT}s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


def _emailrep_check(email: str) -> dict:
    """EmailRep.io reputation check (free, no key)."""
    try:
        r = requests.get(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": "CYRBER-OSINT", "Accept": "application/json"},
            timeout=API_TIMEOUT
        )
        if r.status_code != 200:
            return {"skipped": True, "reason": f"emailrep HTTP {r.status_code}"}
        data = r.json()
        return {
            "reputation": data.get("reputation", ""),
            "suspicious": data.get("suspicious", False),
            "references": data.get("references", 0),
            "details": {
                "blacklisted": data.get("details", {}).get("blacklisted", False),
                "malicious_activity": data.get("details", {}).get("malicious_activity", False),
                "credentials_leaked": data.get("details", {}).get("credentials_leaked", False),
                "data_breach": data.get("details", {}).get("data_breach", False),
                "profiles": data.get("details", {}).get("profiles", []),
                "domain_exists": data.get("details", {}).get("domain_exists", True),
                "deliverable": data.get("details", {}).get("deliverable", None),
                "free_provider": data.get("details", {}).get("free_provider", False),
                "spoofable": data.get("details", {}).get("spoofable", False),
            },
        }
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


def _hunter_verify(email: str) -> dict:
    """Hunter.io email verification."""
    if not HUNTER_API_KEY:
        return {"skipped": True, "reason": "HUNTER_API_KEY not configured"}
    try:
        r = requests.get(
            "https://api.hunter.io/v2/email-verifier",
            params={"email": email, "api_key": HUNTER_API_KEY},
            timeout=API_TIMEOUT
        )
        if r.status_code != 200:
            return {"skipped": True, "reason": f"hunter.io HTTP {r.status_code}"}
        data = r.json().get("data", {})
        return {
            "result": data.get("result", ""),
            "score": data.get("score", 0),
            "smtp_server": data.get("smtp_server", False),
            "smtp_check": data.get("smtp_check", False),
            "mx_records": data.get("mx_records", False),
        }
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


# ═══════════════════════════════════════════════════════════════
#  USERNAME / PERSON SCAN COMPONENTS
# ═══════════════════════════════════════════════════════════════

def _sherlock_lookup(username: str) -> dict:
    """Sherlock username search (300s timeout)."""
    try:
        tmp_dir = tempfile.mkdtemp(prefix="cyrber_sherlock_")
        result = subprocess.run(
            ["sherlock", username, "--timeout", "15", "--print-found",
             "--no-color", "--output", os.path.join(tmp_dir, "results.txt")],
            capture_output=True, text=True, timeout=SHERLOCK_TIMEOUT
        )
        lines = (result.stdout or "").split("\n")
        found = []
        for line in lines:
            line = line.strip()
            if line.startswith("[+]"):
                parts = line[3:].strip().split(": ", 1)
                if len(parts) == 2:
                    found.append({"platform": parts[0].strip(), "url": parts[1].strip()})
            elif line.startswith("http://") or line.startswith("https://"):
                found.append({"platform": "", "url": line})
        return {"accounts": found, "total": len(found)}
    except FileNotFoundError:
        return {"skipped": True, "reason": "sherlock not installed"}
    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": f"sherlock timeout ({SHERLOCK_TIMEOUT}s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
    finally:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


def _maigret_lookup(username: str) -> dict:
    """Maigret username search (300s timeout)."""
    try:
        json_out = tempfile.mktemp(prefix="cyrber_maigret_", suffix=".json")
        result = subprocess.run(
            ["maigret", username, "--timeout", "15", "--json", "ndjson",
             "-o", json_out, "--no-color"],
            capture_output=True, text=True, timeout=MAIGRET_TIMEOUT
        )
        found = []
        if os.path.exists(json_out):
            with open(json_out) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        if rec.get("status") and rec["status"].get("status") == "Claimed":
                            found.append({
                                "platform": rec.get("siteName", ""),
                                "url": rec.get("url_user", ""),
                                "tags": rec.get("tags", []),
                            })
                    except json.JSONDecodeError:
                        continue
        else:
            # Fallback: parse stdout
            for line in (result.stdout or "").split("\n"):
                line = line.strip()
                if "[+]" in line:
                    parts = line.replace("[+]", "").strip().split(" - ", 1)
                    if len(parts) == 2:
                        found.append({"platform": parts[0].strip(), "url": parts[1].strip()})
        return {"accounts": found, "total": len(found)}
    except FileNotFoundError:
        return {"skipped": True, "reason": "maigret not installed"}
    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": f"maigret timeout ({MAIGRET_TIMEOUT}s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
    finally:
        try:
            os.remove(json_out)
        except OSError:
            pass


def _github_user(username: str) -> dict:
    """GitHub API user + repos + commit emails."""
    try:
        headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "CYRBER-OSINT"}
        r = requests.get(f"https://api.github.com/users/{username}", headers=headers, timeout=API_TIMEOUT)
        if r.status_code == 404:
            return {"found": False}
        if r.status_code != 200:
            return {"skipped": True, "reason": f"GitHub HTTP {r.status_code}"}
        user = r.json()
        # Get repos
        r2 = requests.get(f"https://api.github.com/users/{username}/repos?sort=updated&per_page=10",
                          headers=headers, timeout=API_TIMEOUT)
        repos = r2.json() if r2.status_code == 200 else []
        # Extract commit emails from recent repos
        commit_emails = set()
        for repo in repos[:3]:
            repo_name = repo.get("full_name", "")
            if not repo_name:
                continue
            r3 = requests.get(f"https://api.github.com/repos/{repo_name}/commits?per_page=5",
                              headers=headers, timeout=API_TIMEOUT)
            if r3.status_code == 200:
                for commit in r3.json():
                    c = commit.get("commit", {})
                    for field in ["author", "committer"]:
                        email = c.get(field, {}).get("email", "")
                        if email and "@" in email and "noreply" not in email:
                            commit_emails.add(email.lower())

        return {
            "found": True,
            "login": user.get("login", ""),
            "name": user.get("name", ""),
            "bio": user.get("bio", ""),
            "company": user.get("company", ""),
            "location": user.get("location", ""),
            "email": user.get("email", ""),
            "public_repos": user.get("public_repos", 0),
            "followers": user.get("followers", 0),
            "created_at": user.get("created_at", ""),
            "repos": [{"name": r.get("name", ""), "language": r.get("language", ""),
                        "stars": r.get("stargazers_count", 0)} for r in repos[:10]],
            "commit_emails": sorted(commit_emails),
        }
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


def _phoneinfoga_scan(phone: str) -> dict:
    """PhoneInfoga phone number scan."""
    try:
        result = subprocess.run(
            ["phoneinfoga", "scan", "-n", phone],
            capture_output=True, text=True, timeout=60
        )
        lines = (result.stdout or "").split("\n")
        info = {}
        for line in lines:
            line = line.strip()
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                val = val.strip()
                if val:
                    info[key] = val
        return {"info": info} if info else {"skipped": True, "reason": "no output"}
    except FileNotFoundError:
        return {"skipped": True, "reason": "phoneinfoga not installed"}
    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "phoneinfoga timeout"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}


# ═══════════════════════════════════════════════════════════════
#  SCAN ORCHESTRATORS
# ═══════════════════════════════════════════════════════════════

def _domain_scan(host: str) -> dict:
    """Deep domain OSINT scan (20-40 min)."""
    results = {}
    # Phase 1: parallel heavy scans
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(_harvester_deep, host): "harvester",
            executor.submit(_amass_active, host): "amass",
            executor.submit(_dnsrecon_brute, host): "dnsrecon",
            executor.submit(whois_scan, host): "whois",
            executor.submit(_crtsh_query, host): "crtsh",
            executor.submit(_metagoofil_scan, host): "metagoofil",
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = {"error": str(e)}

    # Phase 2: API-based lookups (parallel)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures2 = {
            executor.submit(_virustotal_passive_dns, host): "virustotal",
            executor.submit(_shodan_host, host): "shodan",
            executor.submit(_securitytrails_subdomains, host): "securitytrails",
        }
        for future in as_completed(futures2):
            key = futures2[future]
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = {"error": str(e)}

    # Google dorks (prepared, not executed)
    results["google_dorks"] = _google_dorks(host)

    # ── Aggregate ──
    harv = results.get("harvester") or {}
    whois_data = results.get("whois") or {}
    dns = results.get("dnsrecon") or {}
    amass_data = results.get("amass") or {}
    crtsh = results.get("crtsh") or {}
    vt = results.get("virustotal") or {}
    shodan = results.get("shodan") or {}
    st = results.get("securitytrails") or {}
    metagoofil = results.get("metagoofil") or {}
    dorks = results.get("google_dorks") or {}

    module_errors = []
    data_sources = []

    def _track(name, data, error_key="error", skip_key="skipped"):
        if data.get(error_key):
            module_errors.append(f"{name}: {data[error_key]}")
        elif data.get(skip_key):
            module_errors.append(f"{name}: {data.get('reason', 'skipped')}")
        else:
            return True
        return False

    # Emails
    emails = set()
    for e in (harv.get("emails", []) or []):
        if "@" in str(e):
            emails.add(str(e).lower().strip())

    # Subdomains (from ALL sources)
    subdomains = set()
    for src_data, sub_key in [
        (harv, "subdomains"), (amass_data, "subdomains"), (dns, "subdomains"),
        (crtsh, "subdomains"), (vt, "subdomains"), (st, "subdomains"),
    ]:
        for s in (src_data.get(sub_key, []) or []):
            if s:
                subdomains.add(str(s).lower().strip())
    for rec in (dns.get("a_records", []) or []):
        hostname = rec.get("hostname", "")
        if hostname and hostname != host and hostname.endswith("." + host):
            subdomains.add(hostname.lower())

    # IP addresses (from ALL sources)
    ip_addresses = set()
    for ip in (harv.get("ips", []) or []):
        if ip:
            ip_addresses.add(str(ip))
    for ip in (amass_data.get("ip_addresses", []) or []):
        if ip:
            ip_addresses.add(str(ip))
    for rec in (dns.get("a_records", []) or []):
        ip = rec.get("ip", "")
        if ip:
            ip_addresses.add(str(ip))
    for ip in (vt.get("ips", []) or []):
        if ip:
            ip_addresses.add(str(ip))

    # DNS records
    dns_records = {}
    if not dns.get("skipped"):
        dns_records = {
            "a_records": dns.get("a_records", []),
            "mx_records": dns.get("mx_records", []),
            "ns_records": dns.get("ns_records", []),
            "txt_records": dns.get("txt_records", []),
            "srv_records": dns.get("srv_records", []),
        }

    # WHOIS
    whois_info = {}
    if not whois_data.get("error"):
        whois_info = whois_data

    # Data sources tracking
    if _track("theHarvester", harv):
        data_sources.append({"source": "theHarvester (deep)", "emails": len(harv.get("emails", []) or []),
                             "subdomains": len(harv.get("subdomains", []) or [])})
    if _track("Amass (active)", amass_data, skip_key="skipped"):
        data_sources.append({"source": "Amass (active)", "subdomains": amass_data.get("total_count", 0)})
    if _track("DNSRecon (brute)", dns, skip_key="skipped"):
        data_sources.append({"source": "DNSRecon (brute)", "records": dns.get("total_records", 0)})
    if not whois_data.get("error"):
        data_sources.append({"source": "WHOIS", "type": whois_data.get("type", "")})
    if _track("crt.sh", crtsh, skip_key="skipped"):
        data_sources.append({"source": "crt.sh", "subdomains": len(crtsh.get("subdomains", [])),
                             "certs": crtsh.get("total_certs", 0)})
    if _track("VirusTotal", vt, skip_key="skipped"):
        data_sources.append({"source": "VirusTotal", "subdomains": len(vt.get("subdomains", [])),
                             "ips": len(vt.get("ips", []))})
    if _track("Shodan", shodan, skip_key="skipped"):
        data_sources.append({"source": "Shodan", "ports": len(shodan.get("ports", [])),
                             "vulns": len(shodan.get("vulns", []))})
    if _track("SecurityTrails", st, skip_key="skipped"):
        data_sources.append({"source": "SecurityTrails", "subdomains": st.get("total", 0)})
    if _track("Metagoofil", metagoofil, skip_key="skipped"):
        data_sources.append({"source": "Metagoofil", "documents": metagoofil.get("total_docs", 0),
                             "users": len(metagoofil.get("users", []))})

    # Risk indicators
    risk_indicators = []
    if dns.get("zone_transfer"):
        risk_indicators.append({"id": "zone_transfer", "severity": "critical",
            "title": "DNS Zone Transfer Possible",
            "description": "Full DNS zone data exposed to unauthorized queries."})
    if dns.get("spf_configured") is False:
        risk_indicators.append({"id": "no_spf", "severity": "high",
            "title": "No SPF Record",
            "description": "Domain lacks SPF record — vulnerable to email spoofing."})
    if dns.get("dmarc_configured") is False:
        risk_indicators.append({"id": "no_dmarc", "severity": "high",
            "title": "No DMARC Record",
            "description": "Domain lacks DMARC record — no email authentication policy."})
    if whois_data.get("soon_expiring"):
        risk_indicators.append({"id": "expiring_domain", "severity": "medium",
            "title": "Domain Expiring Soon",
            "description": f"Domain expires in {whois_data.get('days_until_expiry', '?')} days."})
    if whois_data.get("is_expired"):
        risk_indicators.append({"id": "expired_domain", "severity": "critical",
            "title": "Domain Expired",
            "description": "Domain registration has expired — risk of takeover."})
    if shodan.get("vulns"):
        risk_indicators.append({"id": "shodan_vulns", "severity": "high",
            "title": f"Shodan: {len(shodan['vulns'])} known CVEs on host",
            "description": f"CVEs: {', '.join(shodan['vulns'][:5])}"})
    if shodan.get("ports") and len(shodan["ports"]) > 15:
        risk_indicators.append({"id": "many_ports", "severity": "medium",
            "title": f"{len(shodan['ports'])} open ports detected by Shodan",
            "description": "High number of exposed services increases attack surface."})
    if metagoofil.get("users"):
        risk_indicators.append({"id": "leaked_metadata", "severity": "medium",
            "title": f"Document metadata exposes {len(metagoofil['users'])} user(s)",
            "description": f"Usernames: {', '.join(list(metagoofil['users'])[:5])}"})
    if whois_data.get("privacy_protected"):
        risk_indicators.append({"id": "privacy_protected", "severity": "info",
            "title": "WHOIS Privacy Protected",
            "description": "Domain registrant uses privacy protection service."})

    return {
        "target": host,
        "search_type": "domain",
        "emails": sorted(emails),
        "subdomains": sorted(subdomains),
        "ip_addresses": sorted(ip_addresses),
        "dns_records": dns_records,
        "whois_info": whois_info,
        "shodan": shodan if not shodan.get("skipped") else None,
        "metagoofil": metagoofil if not metagoofil.get("skipped") else None,
        "google_dorks": dorks,
        "data_sources": data_sources,
        "risk_indicators": risk_indicators,
        "module_errors": module_errors,
        "summary": {
            "total_emails": len(emails),
            "total_subdomains": len(subdomains),
            "total_ips": len(ip_addresses),
            "risk_count": len(risk_indicators),
            "sources_count": len(data_sources),
            "errors_count": len(module_errors),
        },
    }


def _email_scan(email: str) -> dict:
    """Deep email OSINT scan."""
    email = email.strip().lower()
    domain = email.split("@")[-1] if "@" in email else ""

    results = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(_hibp_lookup, email): "hibp",
            executor.submit(_hibp_pastes, email): "pastes",
            executor.submit(_holehe_check, email): "holehe",
            executor.submit(_emailrep_check, email): "emailrep",
            executor.submit(_hunter_verify, email): "hunter",
        }
        if domain:
            futures[executor.submit(_harvester_deep, domain)] = "harvester"
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = {"error": str(e)}

    hibp = results.get("hibp") or {}
    pastes = results.get("pastes") or {}
    holehe = results.get("holehe") or {}
    emailrep = results.get("emailrep") or {}
    hunter = results.get("hunter") or {}
    harv = results.get("harvester") or {}

    module_errors = []
    data_sources = []
    risk_indicators = []

    # HIBP
    breaches = hibp.get("breaches", [])
    if hibp.get("skipped"):
        module_errors.append(f"HIBP: {hibp.get('reason', 'skipped')}")
    else:
        data_sources.append({"source": "HaveIBeenPwned", "breaches": len(breaches)})
        if breaches:
            risk_indicators.append({
                "id": "email_breached", "severity": "high",
                "title": f"Email found in {len(breaches)} data breach(es)",
                "description": "This email has been compromised in known data breaches."})

    paste_list = pastes.get("pastes", [])
    if paste_list:
        risk_indicators.append({
            "id": "email_pasted", "severity": "medium",
            "title": f"Email found in {len(paste_list)} paste(s)",
            "description": "This email was found in public paste dumps."})

    # Holehe
    platforms = holehe.get("platforms", [])
    if holehe.get("skipped"):
        module_errors.append(f"Holehe: {holehe.get('reason', 'skipped')}")
    else:
        data_sources.append({"source": "Holehe", "platforms": len(platforms)})
        if len(platforms) > 10:
            risk_indicators.append({
                "id": "high_registration", "severity": "medium",
                "title": f"Email registered on {len(platforms)} platforms",
                "description": "High registration count increases social engineering attack surface."})

    # EmailRep
    if emailrep.get("skipped"):
        module_errors.append(f"EmailRep: {emailrep.get('reason', 'skipped')}")
    else:
        data_sources.append({"source": "EmailRep.io", "reputation": emailrep.get("reputation", "")})
        if emailrep.get("suspicious"):
            risk_indicators.append({
                "id": "suspicious_email", "severity": "high",
                "title": "Email flagged as suspicious by EmailRep",
                "description": f"Reputation: {emailrep.get('reputation', 'unknown')}"})
        if emailrep.get("details", {}).get("spoofable"):
            risk_indicators.append({
                "id": "email_spoofable", "severity": "medium",
                "title": "Email domain is spoofable",
                "description": "Domain configuration allows email spoofing."})

    # Hunter.io
    if hunter.get("skipped"):
        module_errors.append(f"Hunter.io: {hunter.get('reason', 'skipped')}")
    else:
        data_sources.append({"source": "Hunter.io", "score": hunter.get("score", 0)})

    # theHarvester related emails
    related_emails = set()
    if harv.get("error"):
        module_errors.append(f"theHarvester: {harv['error']}")
    else:
        for e in (harv.get("emails", []) or []):
            if "@" in str(e):
                related_emails.add(str(e).lower().strip())
        related_emails.discard(email)
        if domain:
            data_sources.append({"source": "theHarvester", "emails": len(harv.get("emails", []) or [])})

    return {
        "target": email,
        "search_type": "email",
        "email": email,
        "domain": domain,
        "breaches": breaches,
        "pastes": paste_list,
        "holehe_platforms": platforms,
        "emailrep": emailrep if not emailrep.get("skipped") else None,
        "hunter": hunter if not hunter.get("skipped") else None,
        "related_emails": sorted(related_emails),
        "data_sources": data_sources,
        "risk_indicators": risk_indicators,
        "module_errors": module_errors,
        "summary": {
            "total_breaches": len(breaches),
            "total_pastes": len(paste_list),
            "total_platforms": len(platforms),
            "total_related_emails": len(related_emails),
            "risk_count": len(risk_indicators),
            "sources_count": len(data_sources),
            "errors_count": len(module_errors),
        },
    }


def _username_scan(username: str) -> dict:
    """Deep username OSINT scan."""
    username = username.strip().lstrip("@")

    results = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(_sherlock_lookup, username): "sherlock",
            executor.submit(_maigret_lookup, username): "maigret",
            executor.submit(_github_user, username): "github",
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = {"error": str(e)}

    sherlock = results.get("sherlock") or {}
    maigret = results.get("maigret") or {}
    github = results.get("github") or {}

    module_errors = []
    data_sources = []
    risk_indicators = []

    # Merge accounts from sherlock + maigret (deduplicate by URL)
    seen_urls = set()
    all_accounts = []
    for src_name, src_data in [("Sherlock", sherlock), ("Maigret", maigret)]:
        if src_data.get("skipped"):
            module_errors.append(f"{src_name}: {src_data.get('reason', 'skipped')}")
        else:
            for acc in src_data.get("accounts", []):
                url = acc.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    acc["source"] = src_name
                    all_accounts.append(acc)
            data_sources.append({"source": src_name, "accounts": len(src_data.get("accounts", []))})

    if github.get("skipped"):
        module_errors.append(f"GitHub: {github.get('reason', 'skipped')}")
    elif github.get("found"):
        data_sources.append({"source": "GitHub API", "repos": github.get("public_repos", 0)})
        # Add commit emails as risk indicator
        commit_emails = github.get("commit_emails", [])
        if commit_emails:
            risk_indicators.append({
                "id": "commit_emails_exposed", "severity": "medium",
                "title": f"{len(commit_emails)} email(s) exposed in git commits",
                "description": f"Emails: {', '.join(commit_emails[:5])}"})

    if len(all_accounts) > 15:
        risk_indicators.append({
            "id": "high_exposure", "severity": "medium",
            "title": f"Username found on {len(all_accounts)} platforms",
            "description": "High online presence increases attack surface."})

    return {
        "target": username,
        "search_type": "username",
        "username": username,
        "accounts": all_accounts,
        "github": github if github.get("found") else None,
        "data_sources": data_sources,
        "risk_indicators": risk_indicators,
        "module_errors": module_errors,
        "summary": {
            "total_accounts": len(all_accounts),
            "github_repos": github.get("public_repos", 0) if github.get("found") else 0,
            "risk_count": len(risk_indicators),
            "sources_count": len(data_sources),
            "errors_count": len(module_errors),
        },
    }


def _person_scan(query: str) -> dict:
    """Deep person OSINT scan."""
    query = query.strip()
    parts = query.lower().split()
    username_guess = parts[0] + parts[-1] if len(parts) >= 2 else parts[0] if parts else "unknown"

    results = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(_harvester_deep, f'"{query}"'): "harvester",
            executor.submit(_sherlock_lookup, username_guess): "sherlock",
            executor.submit(_maigret_lookup, username_guess): "maigret",
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = {"error": str(e)}

    harv = results.get("harvester") or {}
    sherlock = results.get("sherlock") or {}
    maigret = results.get("maigret") or {}

    module_errors = []
    data_sources = []

    emails = set()
    if harv.get("error"):
        module_errors.append(f"theHarvester: {harv['error']}")
    else:
        for e in (harv.get("emails", []) or []):
            if "@" in str(e):
                emails.add(str(e).lower().strip())
        data_sources.append({"source": "theHarvester (deep)", "emails": len(emails)})

    hosts = set()
    for h in (harv.get("subdomains", []) or []):
        if h:
            hosts.add(str(h).lower().strip())

    # Merge accounts
    seen_urls = set()
    accounts = []
    for src_name, src_data in [("Sherlock", sherlock), ("Maigret", maigret)]:
        if src_data.get("skipped"):
            module_errors.append(f"{src_name}: {src_data.get('reason', 'skipped')}")
        else:
            for acc in src_data.get("accounts", []):
                url = acc.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    accounts.append(acc)
            data_sources.append({"source": src_name, "accounts": len(src_data.get("accounts", []))})

    # Google dork suggestions
    dorks = [
        {"query": f'"{query}" site:linkedin.com', "status": "prepared"},
        {"query": f'"{query}" site:facebook.com', "status": "prepared"},
        {"query": f'"{query}" site:twitter.com', "status": "prepared"},
        {"query": f'"{query}" email OR contact', "status": "prepared"},
    ]

    return {
        "target": query,
        "search_type": "person",
        "person_name": query,
        "username_guess": username_guess,
        "emails": sorted(emails),
        "associated_hosts": sorted(hosts),
        "accounts": accounts,
        "google_dorks": {"dorks": dorks, "total": len(dorks)},
        "data_sources": data_sources,
        "risk_indicators": [],
        "module_errors": module_errors,
        "summary": {
            "total_emails": len(emails),
            "total_hosts": len(hosts),
            "total_accounts": len(accounts),
            "risk_count": 0,
            "sources_count": len(data_sources),
            "errors_count": len(module_errors),
        },
    }


def _phone_scan(phone: str) -> dict:
    """Phone number OSINT scan."""
    phone = re.sub(r'[^\d+]', '', phone.strip())

    data_sources = []
    risk_indicators = []
    module_errors = []
    phone_info = {"number": phone}

    # Country code detection
    country_codes = {
        "+48": "Poland", "+1": "United States / Canada", "+44": "United Kingdom",
        "+49": "Germany", "+33": "France", "+34": "Spain", "+39": "Italy",
        "+31": "Netherlands", "+46": "Sweden", "+47": "Norway", "+45": "Denmark",
        "+358": "Finland", "+372": "Estonia", "+371": "Latvia", "+370": "Lithuania",
        "+420": "Czech Republic", "+421": "Slovakia", "+36": "Hungary",
        "+43": "Austria", "+41": "Switzerland", "+32": "Belgium",
        "+351": "Portugal", "+30": "Greece", "+7": "Russia",
        "+81": "Japan", "+82": "South Korea", "+86": "China",
        "+91": "India", "+61": "Australia", "+55": "Brazil",
    }
    if phone.startswith("+"):
        for code, country in sorted(country_codes.items(), key=lambda x: -len(x[0])):
            if phone.startswith(code):
                phone_info["country"] = country
                phone_info["country_code"] = code
                break

    results = {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(_phoneinfoga_scan, phone): "phoneinfoga",
        }
        # Numverify
        if NUMVERIFY_API_KEY:
            def _numverify():
                try:
                    r = requests.get("http://apilayer.net/api/validate",
                                     params={"access_key": NUMVERIFY_API_KEY, "number": phone}, timeout=10)
                    if r.status_code == 200:
                        return r.json()
                except Exception as e:
                    return {"error": str(e)}
                return {}
            futures[executor.submit(_numverify)] = "numverify"

        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = {"error": str(e)}

    # Numverify
    nv = results.get("numverify") or {}
    if NUMVERIFY_API_KEY:
        if nv.get("error"):
            module_errors.append(f"Numverify: {nv['error']}")
        elif nv.get("valid") is not None:
            phone_info.update({
                "valid": nv.get("valid", False),
                "country": nv.get("country_name", phone_info.get("country", "")),
                "location": nv.get("location", ""),
                "carrier": nv.get("carrier", ""),
                "line_type": nv.get("line_type", ""),
            })
            data_sources.append({"source": "Numverify", "type": "phone_validation"})
    else:
        module_errors.append("Numverify: API key not configured")

    # PhoneInfoga
    pinfoga = results.get("phoneinfoga") or {}
    if pinfoga.get("skipped"):
        module_errors.append(f"PhoneInfoga: {pinfoga.get('reason', 'skipped')}")
    elif pinfoga.get("info"):
        phone_info.update(pinfoga["info"])
        data_sources.append({"source": "PhoneInfoga"})

    return {
        "target": phone,
        "search_type": "phone",
        "phone_info": phone_info,
        "data_sources": data_sources,
        "risk_indicators": risk_indicators,
        "module_errors": module_errors,
        "summary": {
            "valid": phone_info.get("valid"),
            "country": phone_info.get("country", "Unknown"),
            "risk_count": len(risk_indicators),
            "sources_count": len(data_sources),
            "errors_count": len(module_errors),
        },
    }


# ═══════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def osint_scan(target: str, search_type: str = "domain") -> dict:
    """Run deep OSINT reconnaissance.

    Args:
        target: Search query (domain, email, phone, name, username).
        search_type: One of: domain, email, phone, person, username.

    Returns:
        Dict with OSINT results.
    """
    if not target or not target.strip():
        return {"error": "empty target"}

    search_type = (search_type or "domain").lower().strip()

    if search_type == "email":
        return _email_scan(target)
    elif search_type == "username":
        return _username_scan(target)
    elif search_type == "person":
        return _person_scan(target)
    elif search_type == "phone":
        return _phone_scan(target)
    else:
        host = _clean_target(target)
        if not host:
            return {"error": "empty target"}
        return _domain_scan(host)
