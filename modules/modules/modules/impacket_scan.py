import subprocess
import shutil
import re


def impacket_scan(target: str, scan_results: dict = None) -> dict:
    """
    Run Impacket tools for Active Directory attack simulation.
    Automatically selects tools based on context from previous scan results:
    - GetUserSPNs.py: Kerberoasting (if bloodhound detected has_spn)
    - GetNPUsers.py: AS-REP Roasting (if bloodhound detected no_preauth)
    - secretsdump.py: null session dump (if netexec detected null session)
    - lookupsid.py: SID enumeration (if port 445 is open)
    """
    # Check for any impacket tool
    lookupsid = shutil.which("lookupsid.py") or shutil.which("impacket-lookupsid")
    getuserspns = shutil.which("GetUserSPNs.py") or shutil.which("impacket-GetUserSPNs")
    getnpusers = shutil.which("GetNPUsers.py") or shutil.which("impacket-GetNPUsers")
    secretsdump = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")

    if not any([lookupsid, getuserspns, getnpusers, secretsdump]):
        return {"skipped": True, "reason": "impacket tools not installed"}

    if not scan_results:
        scan_results = {}

    host = target.strip()
    for prefix in ["http://", "https://", "ftp://"]:
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0].split(":")[0]

    result = {
        "target": host,
        "kerberoastable_hashes": [],
        "asreproastable_hashes": [],
        "sid_enumeration": [],
        "secrets": [],
        "vulnerabilities": [],
        "operations_run": [],
        "summary": {
            "total_hashes": 0,
            "kerberoastable": 0,
            "asreproastable": 0,
            "sids_found": 0,
            "secrets_found": 0,
        },
    }

    port_445_open = _is_port_open(scan_results, 445)
    port_88_open = _is_port_open(scan_results, 88)
    bloodhound = scan_results.get("bloodhound", {})
    netexec = scan_results.get("netexec", {})
    enum4linux = scan_results.get("enum4linux", {})

    # Determine domain from context
    domain = _extract_domain(scan_results, host)

    # 1. SID Enumeration — always when port 445 open
    if port_445_open and lookupsid:
        sids = _run_lookupsid(lookupsid, host, domain)
        result["sid_enumeration"] = sids
        result["summary"]["sids_found"] = len(sids)
        result["operations_run"].append("lookupsid")
        if sids:
            result["vulnerabilities"].append({
                "title": f"SID Enumeration — {len(sids)} accounts discovered",
                "severity": "medium",
                "description": f"Successfully enumerated {len(sids)} SIDs via null/guest session. "
                               f"Attackers can map the entire domain user/group structure.",
                "mitre": "T1087.002",
                "remediation": "Restrict anonymous SID enumeration via Group Policy: "
                               "Network access: Do not allow anonymous enumeration of SAM accounts.",
            })

    # 2. Kerberoasting — if bloodhound detected SPN users or port 88 open
    has_spn_users = _has_spn_users(bloodhound)
    if (has_spn_users or port_88_open) and getuserspns:
        hashes = _run_kerberoast(getuserspns, host, domain)
        result["kerberoastable_hashes"] = hashes
        result["summary"]["kerberoastable"] = len(hashes)
        result["summary"]["total_hashes"] += len(hashes)
        result["operations_run"].append("GetUserSPNs")
        if hashes:
            result["vulnerabilities"].append({
                "title": f"Kerberoasting — {len(hashes)} service accounts vulnerable",
                "severity": "critical",
                "description": f"Found {len(hashes)} accounts with SPNs whose TGS tickets can be "
                               f"requested and cracked offline. Usernames: "
                               f"{', '.join(h['username'] for h in hashes[:5])}"
                               + ("..." if len(hashes) > 5 else ""),
                "mitre": "T1558.003",
                "remediation": "Use Group Managed Service Accounts (gMSA), enforce strong passwords "
                               "(25+ chars) on service accounts, limit SPN assignments.",
            })

    # 3. AS-REP Roasting — if bloodhound detected no_preauth users
    has_no_preauth = _has_no_preauth_users(bloodhound)
    if (has_no_preauth or port_88_open) and getnpusers:
        hashes = _run_asreproast(getnpusers, host, domain)
        result["asreproastable_hashes"] = hashes
        result["summary"]["asreproastable"] = len(hashes)
        result["summary"]["total_hashes"] += len(hashes)
        result["operations_run"].append("GetNPUsers")
        if hashes:
            result["vulnerabilities"].append({
                "title": f"AS-REP Roasting — {len(hashes)} accounts without pre-authentication",
                "severity": "critical",
                "description": f"Found {len(hashes)} accounts with Kerberos pre-authentication disabled. "
                               f"Their AS-REP can be cracked offline. Usernames: "
                               f"{', '.join(h['username'] for h in hashes[:5])}"
                               + ("..." if len(hashes) > 5 else ""),
                "mitre": "T1558.004",
                "remediation": "Enable Kerberos pre-authentication for all accounts. "
                               "Review and enforce strong password policies.",
            })

    # 4. Secrets dump — if null session detected
    has_null_session = _has_null_session(netexec, enum4linux)
    if has_null_session and secretsdump:
        secrets = _run_secretsdump(secretsdump, host, domain)
        result["secrets"] = secrets
        result["summary"]["secrets_found"] = len(secrets)
        result["operations_run"].append("secretsdump")
        if secrets:
            result["vulnerabilities"].append({
                "title": f"Credential Dump — {len(secrets)} secrets extracted",
                "severity": "critical",
                "description": f"Successfully dumped {len(secrets)} credential entries via null session. "
                               f"This includes password hashes that can be cracked or used in pass-the-hash attacks.",
                "mitre": "T1003.002",
                "remediation": "Disable null sessions, enforce SMB signing, restrict anonymous access "
                               "to SAM and LSA secrets.",
            })

    if not result["operations_run"]:
        return {"skipped": True, "reason": "no applicable Impacket operations (no SMB/Kerberos services detected)"}

    result["total_vulnerabilities"] = len(result["vulnerabilities"])
    result["total_operations"] = len(result["operations_run"])
    return result


def _is_port_open(scan_results: dict, port: int) -> bool:
    """Check if a specific port is open in nmap results."""
    ports = scan_results.get("ports", [])
    for p in ports:
        if p.get("port") == port and p.get("state", "").lower() in ("open", "open|filtered"):
            return True
    return False


def _extract_domain(scan_results: dict, host: str) -> str:
    """Try to extract AD domain name from scan results."""
    # From bloodhound
    bh = scan_results.get("bloodhound", {})
    if isinstance(bh, dict):
        domain = bh.get("domain") or bh.get("ad_domain", "")
        if domain:
            return domain

    # From netexec
    ne = scan_results.get("netexec", {})
    if isinstance(ne, dict):
        domain = ne.get("domain", "")
        if domain:
            return domain

    # From enum4linux
    e4l = scan_results.get("enum4linux", {})
    if isinstance(e4l, dict):
        domain = e4l.get("domain", "") or e4l.get("workgroup", "")
        if domain:
            return domain

    return ""


def _has_spn_users(bloodhound: dict) -> bool:
    """Check if bloodhound found users with SPNs."""
    if not bloodhound or bloodhound.get("skipped"):
        return False
    users = bloodhound.get("users", [])
    if isinstance(users, list):
        for u in users:
            if isinstance(u, dict) and u.get("has_spn"):
                return True
    return bloodhound.get("kerberoastable", 0) > 0


def _has_no_preauth_users(bloodhound: dict) -> bool:
    """Check if bloodhound found users without pre-authentication."""
    if not bloodhound or bloodhound.get("skipped"):
        return False
    users = bloodhound.get("users", [])
    if isinstance(users, list):
        for u in users:
            if isinstance(u, dict) and u.get("no_preauth"):
                return True
    return bloodhound.get("asreproastable", 0) > 0


def _has_null_session(netexec: dict, enum4linux: dict) -> bool:
    """Check if null session access was detected."""
    if isinstance(netexec, dict) and not netexec.get("skipped"):
        if netexec.get("null_session") or netexec.get("anonymous_access"):
            return True
        vulns = netexec.get("vulnerabilities", [])
        for v in vulns:
            if isinstance(v, dict) and "null" in v.get("title", "").lower():
                return True
    if isinstance(enum4linux, dict) and not enum4linux.get("skipped"):
        if enum4linux.get("null_session"):
            return True
    return False


def _run_lookupsid(bin_path: str, host: str, domain: str) -> list:
    """Run lookupsid.py for SID enumeration."""
    sids = []
    try:
        target_str = f"{domain}/{''!s}:{''}@{host}" if domain else f"guest@{host}"
        cmd = [bin_path, "-no-pass", target_str, "500"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout + "\n" + proc.stderr
        # Parse: 500: DOMAIN\username (SidTypeUser)
        for line in output.splitlines():
            match = re.match(r"(\d+):\s+(\S+\\)?(\S+)\s+\((\w+)\)", line.strip())
            if match:
                sid_num = match.group(1)
                domain_part = (match.group(2) or "").rstrip("\\")
                username = match.group(3)
                sid_type = match.group(4)
                sids.append({
                    "sid": sid_num,
                    "username": username,
                    "domain": domain_part,
                    "type": sid_type,
                })
    except (subprocess.TimeoutExpired, Exception):
        pass
    return sids


def _run_kerberoast(bin_path: str, host: str, domain: str) -> list:
    """Run GetUserSPNs.py for Kerberoasting."""
    hashes = []
    if not domain:
        return hashes
    try:
        cmd = [bin_path, "-no-pass", "-dc-ip", host, f"{domain}/guest"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout + "\n" + proc.stderr
        current_user = ""
        current_spn = ""
        for line in output.splitlines():
            stripped = line.strip()
            # Table format: ServicePrincipalName  Name  MemberOf  PasswordLastSet  LastLogon
            if stripped.startswith("$krb5tgs$"):
                hashes.append({
                    "username": current_user or "unknown",
                    "spn": current_spn or "unknown",
                    "hash": _mask_hash(stripped),
                    "hash_type": "krb5tgs",
                })
            elif "\t" in stripped or "  " in stripped:
                parts = stripped.split()
                if len(parts) >= 2 and "/" in parts[0]:
                    current_spn = parts[0]
                    current_user = parts[1]
    except (subprocess.TimeoutExpired, Exception):
        pass
    return hashes


def _run_asreproast(bin_path: str, host: str, domain: str) -> list:
    """Run GetNPUsers.py for AS-REP Roasting."""
    hashes = []
    if not domain:
        return hashes
    try:
        cmd = [bin_path, "-no-pass", "-dc-ip", host, f"{domain}/", "-format", "hashcat"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout + "\n" + proc.stderr
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("$krb5asrep$"):
                # Format: $krb5asrep$23$user@DOMAIN:...
                user_match = re.search(r"\$krb5asrep\$\d+\$([^@:]+)", stripped)
                username = user_match.group(1) if user_match else "unknown"
                hashes.append({
                    "username": username,
                    "hash": _mask_hash(stripped),
                    "hash_type": "krb5asrep",
                })
    except (subprocess.TimeoutExpired, Exception):
        pass
    return hashes


def _run_secretsdump(bin_path: str, host: str, domain: str) -> list:
    """Run secretsdump.py for credential extraction via null session."""
    secrets = []
    try:
        target_str = f"{domain}/guest@{host}" if domain else f"guest@{host}"
        cmd = [bin_path, "-no-pass", target_str]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout + "\n" + proc.stderr
        for line in output.splitlines():
            stripped = line.strip()
            # Format: user:rid:lmhash:nthash:::
            if ":::" in stripped and not stripped.startswith("["):
                parts = stripped.split(":")
                if len(parts) >= 4:
                    account = parts[0]
                    secrets.append({
                        "account": account,
                        "secret_type": "NTLM hash",
                        "value": _mask_hash(stripped),
                    })
            # SAM/LSA entries
            elif stripped.startswith("$MACHINE.ACC") or "DefaultPassword" in stripped:
                secrets.append({
                    "account": stripped.split(":")[0] if ":" in stripped else stripped[:30],
                    "secret_type": "LSA secret",
                    "value": _mask_hash(stripped),
                })
    except (subprocess.TimeoutExpired, Exception):
        pass
    return secrets


def _mask_hash(hash_str: str) -> str:
    """Mask a hash value, showing only first and last few characters."""
    if len(hash_str) <= 20:
        return hash_str[:8] + "..." + hash_str[-4:]
    return hash_str[:16] + "..." + hash_str[-8:]
