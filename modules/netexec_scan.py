import subprocess
import shutil
import re
import os


def _run_nxc(args: list, timeout: int = 120) -> str:
    """Run a netexec command and return stdout."""
    try:
        result = subprocess.run(
            args,
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def _parse_smb_info(output: str) -> dict:
    """Parse SMB host info from netexec smb output header line.
    Example: SMB  10.0.0.1  445  HOSTNAME  [*] Windows 10.0 Build 19041 x64 (name:HOSTNAME) (domain:CORP) (signing:False) (SMBv1:True)
    """
    info = {}
    for line in output.splitlines():
        if "signing:" in line.lower() or "smbv1:" in line.lower() or "(name:" in line.lower():
            # Extract hostname
            m = re.search(r'\(name:([^)]+)\)', line, re.IGNORECASE)
            if m:
                info["hostname"] = m.group(1).strip()
            # Extract domain
            m = re.search(r'\(domain:([^)]+)\)', line, re.IGNORECASE)
            if m:
                info["domain"] = m.group(1).strip()
            # Extract signing
            m = re.search(r'\(signing:(True|False)\)', line, re.IGNORECASE)
            if m:
                info["signing"] = m.group(1).strip().lower() == "true"
            # Extract SMBv1
            m = re.search(r'\(SMBv1:(True|False)\)', line, re.IGNORECASE)
            if m:
                info["smbv1"] = m.group(1).strip().lower() == "true"
            # Extract OS from the line between port and (name:...)
            m = re.search(r'\[\*\]\s+(.*?)\s+\(name:', line)
            if m:
                info["os"] = m.group(1).strip()
            break
    return info


def _parse_shares(output: str) -> list:
    """Parse share listing from netexec --shares output.
    Example: SMB  10.0.0.1  445  HOST  ADMIN$  READ  Remote Admin
    """
    shares = []
    for line in output.splitlines():
        # Lines with share info contain READ, WRITE, or NO ACCESS
        if not line.strip():
            continue
        # Skip header/status lines
        if "[*]" in line or "[+]" in line or "[!]" in line:
            # [+] line may indicate successful auth
            continue
        # Try to match share lines: after the host column, share data follows
        # Format varies: SMB  IP  PORT  HOST  SHARE_NAME  PERMISSIONS  REMARK
        parts = line.split()
        if len(parts) < 5:
            continue
        # Find share info after the host identifier (4th column)
        # Look for READ, WRITE, NO ACCESS patterns
        line_upper = line.upper()
        access = "NO ACCESS"
        if "READ,WRITE" in line_upper or "READ, WRITE" in line_upper:
            access = "READ,WRITE"
        elif "WRITE" in line_upper and "READ" in line_upper:
            access = "READ,WRITE"
        elif "READ" in line_upper:
            access = "READ"
        elif "WRITE" in line_upper:
            access = "WRITE"

        # Extract share name - typically the 5th field after SMB IP PORT HOSTNAME
        if len(parts) >= 5:
            # Skip lines that are clearly not share listings
            if parts[0] != "SMB":
                continue
            share_name = parts[4] if len(parts) > 4 else ""
            if not share_name or share_name.startswith("["):
                continue
            # Avoid duplicates
            if any(s["name"] == share_name for s in shares):
                continue
            shares.append({
                "name": share_name,
                "access": access,
            })
    return shares


def _parse_users(output: str) -> list:
    """Parse user listing from netexec --users output."""
    users = []
    for line in output.splitlines():
        if not line.strip():
            continue
        # Skip status lines
        if "[*]" in line or "[+]" in line or "[!]" in line or "[-]" in line:
            continue
        parts = line.split()
        if len(parts) < 5 or parts[0] != "SMB":
            continue
        # User info after host column: username  badpwdcount  description...
        if len(parts) > 4:
            username = parts[4]
            if username.startswith("[") or not username:
                continue
            desc = " ".join(parts[5:]) if len(parts) > 5 else ""
            # Filter out numeric-only entries (badpwdcount)
            desc = re.sub(r'^\d+\s*', '', desc).strip()
            users.append({
                "username": username,
                "description": desc,
            })
    return users


def _parse_pass_pol(output: str) -> dict:
    """Parse password policy from netexec --pass-pol output."""
    policy = {}
    for line in output.splitlines():
        line_lower = line.lower()
        if "minimum password length" in line_lower:
            m = re.search(r'(\d+)', line.split(":")[-1] if ":" in line else line)
            if m:
                policy["min_length"] = int(m.group(1))
        elif "password complexity" in line_lower:
            if "disabled" in line_lower:
                policy["complexity"] = False
            elif "enabled" in line_lower:
                policy["complexity"] = True
            else:
                policy["complexity"] = "ENABLED" in line.upper()
        elif "account lockout threshold" in line_lower or "lockout threshold" in line_lower:
            m = re.search(r'(\d+)', line.split(":")[-1] if ":" in line else line)
            if m:
                policy["lockout_threshold"] = int(m.group(1))
        elif "minimum password age" in line_lower:
            m = re.search(r'(\d+)', line.split(":")[-1] if ":" in line else line)
            if m:
                policy["min_age_days"] = int(m.group(1))
        elif "maximum password age" in line_lower:
            m = re.search(r'(\d+)', line.split(":")[-1] if ":" in line else line)
            if m:
                policy["max_age_days"] = int(m.group(1))
        elif "lockout duration" in line_lower:
            m = re.search(r'(\d+)', line.split(":")[-1] if ":" in line else line)
            if m:
                policy["lockout_duration_min"] = int(m.group(1))
    return policy


def _parse_relay_targets(filepath: str) -> list:
    """Read relay target list generated by --gen-relay-list."""
    targets = []
    try:
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        targets.append(ip)
            os.remove(filepath)
    except Exception:
        pass
    return targets


def netexec_scan(target: str) -> dict:
    """Network enumeration using NetExec (nxc) — SMB shares, users, password policy, relay targets."""
    # Try both 'netexec' and 'nxc' binary names
    nxc_bin = shutil.which("netexec") or shutil.which("nxc")
    if not nxc_bin:
        return {"skipped": True, "reason": "netexec not installed"}

    relay_file = "/tmp/netexec_relay.txt"

    # 1. SMB info + relay list
    smb_output = _run_nxc([nxc_bin, "smb", target, "--gen-relay-list", relay_file])
    smb_info = _parse_smb_info(smb_output)

    if not smb_info:
        return {"skipped": True, "reason": "SMB not responding or target unreachable"}

    relay_targets = _parse_relay_targets(relay_file)

    # 2. Shares (null session)
    shares_output = _run_nxc([nxc_bin, "smb", target, "-u", "", "-p", "", "--shares"])
    shares = _parse_shares(shares_output)

    # 3. Users (null session)
    users_output = _run_nxc([nxc_bin, "smb", target, "-u", "", "-p", "", "--users"])
    users = _parse_users(users_output)

    # 4. Password policy (null session)
    passpol_output = _run_nxc([nxc_bin, "smb", target, "-u", "", "-p", "", "--pass-pol"])
    password_policy = _parse_pass_pol(passpol_output)

    # Detect null session success
    null_session = False
    for out in [shares_output, users_output, passpol_output]:
        if "[+]" in out:
            null_session = True
            break

    # Build vulnerabilities list
    vulnerabilities = []
    signing = smb_info.get("signing", True)
    smbv1 = smb_info.get("smbv1", False)

    if not signing:
        vulnerabilities.append({
            "id": "smb_signing_disabled",
            "severity": "critical",
            "title": "SMB Signing Disabled",
            "description": "SMB signing is not enforced — host is vulnerable to NTLM relay attacks",
        })
    if smbv1:
        vulnerabilities.append({
            "id": "smbv1_enabled",
            "severity": "high",
            "title": "SMBv1 Enabled",
            "description": "SMBv1 is enabled — vulnerable to EternalBlue (MS17-010) and similar exploits",
        })
    if null_session:
        vulnerabilities.append({
            "id": "null_session",
            "severity": "medium",
            "title": "Null Session Allowed",
            "description": "Anonymous/null session login succeeded — information disclosure risk",
        })
    anon_shares = [s for s in shares if s["access"] in ("READ", "READ,WRITE", "WRITE")]
    if anon_shares:
        vulnerabilities.append({
            "id": "anonymous_shares",
            "severity": "medium",
            "title": f"Anonymous Share Access ({len(anon_shares)} shares)",
            "description": "Shares accessible without authentication: " + ", ".join(s["name"] for s in anon_shares),
        })

    return {
        "smb_info": smb_info,
        "shares": shares,
        "users": users,
        "password_policy": password_policy,
        "relay_targets": relay_targets,
        "vulnerabilities": vulnerabilities,
        "null_session": null_session,
        "total_shares": len(shares),
        "total_users": len(users),
        "total_relay_targets": len(relay_targets),
        "total_vulnerabilities": len(vulnerabilities),
    }
