import os
import re
import json
import shutil
import subprocess
import tempfile


def _safe_int(val, default=0):
    """Convert value to int, returning default on failure."""
    if val is None or val == "":
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def enum4linux_scan(target: str) -> dict:
    """Run enum4linux-ng against target for SMB/NetBIOS enumeration."""
    # Strip protocol/path
    host = re.sub(r'^https?://', '', target)
    host = host.split('/')[0].split(':')[0]

    if not shutil.which("enum4linux-ng"):
        return {"skipped": True, "reason": "enum4linux-ng not installed"}

    outfile = os.path.join(tempfile.gettempdir(), f"enum4linux_{host}.json")

    try:
        proc = subprocess.run(
            ["enum4linux-ng", "-A", host, "-oJ", outfile],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "Timeout (180s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}

    # Parse JSON output
    data = {}
    if os.path.exists(outfile):
        try:
            with open(outfile, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
        finally:
            try:
                os.remove(outfile)
            except OSError:
                pass

    if not data:
        stderr = (proc.stderr or "")[:500] if proc else ""
        if "Connection refused" in stderr or "Could not negotiate" in stderr or "NT_STATUS" in stderr:
            return {"skipped": True, "reason": "Not a Windows/Samba host"}
        return {"skipped": True, "reason": stderr or "No SMB data returned"}

    # ── OS Info ──
    os_info_raw = data.get("os_info") or {}
    nmblookup = data.get("nmblookup") or {}
    workgroup = data.get("workgroup", "")
    domain = nmblookup.get("domain", "") if isinstance(nmblookup, dict) else ""
    netbios_name = ""
    if isinstance(nmblookup, dict):
        netbios_name = nmblookup.get("nbname", "") or nmblookup.get("netbios_name", "")

    os_info = {
        "os": os_info_raw.get("OS", ""),
        "version": os_info_raw.get("OS version", ""),
        "domain": domain,
        "workgroup": workgroup,
        "netbios_name": netbios_name,
    }

    # ── Users ──
    users = []
    users_raw = data.get("users") or {}
    for rid, info in users_raw.items():
        flags = ""
        acb = info.get("acb_info", "")
        if acb:
            flags = acb
        users.append({
            "username": info.get("username", ""),
            "rid": rid,
            "description": info.get("description", "") or "",
            "flags": flags,
        })

    # ── Groups ──
    groups = []
    groups_raw = data.get("groups") or {}
    for rid, info in groups_raw.items():
        members = []
        members_raw = info.get("members") or []
        if isinstance(members_raw, list):
            members = members_raw
        elif isinstance(members_raw, dict):
            members = list(members_raw.values())
        groups.append({
            "name": info.get("groupname", ""),
            "rid": rid,
            "members": members,
        })

    # ── Shares ──
    shares = []
    shares_raw = data.get("shares") or {}
    for name, info in shares_raw.items():
        access = "NO ACCESS"
        access_raw = info.get("access", "") if isinstance(info, dict) else ""
        if isinstance(access_raw, str):
            if "READ" in access_raw.upper() and "WRITE" in access_raw.upper():
                access = "READ,WRITE"
            elif "READ" in access_raw.upper():
                access = "READ"
            elif "WRITE" in access_raw.upper():
                access = "WRITE"
            elif "OK" in access_raw.upper() or "ALLOWED" in access_raw.upper():
                access = "READ"
        shares.append({
            "name": name,
            "type": info.get("type", "") if isinstance(info, dict) else "",
            "comment": info.get("comment", "") if isinstance(info, dict) else "",
            "access": access,
        })

    # ── Password Policy ──
    policy_raw = data.get("policy") or {}
    password_policy = {}
    if policy_raw:
        min_length = _safe_int(policy_raw.get("min_length") or policy_raw.get("minimum_password_length"))
        lockout_threshold = _safe_int(policy_raw.get("lockout_threshold") or policy_raw.get("account_lockout_threshold"))
        complexity = policy_raw.get("password_complexity", None)
        if complexity is None:
            complexity = policy_raw.get("complexity", None)
        password_policy = {
            "min_length": min_length,
            "lockout_threshold": lockout_threshold,
            "lockout_duration": _safe_int(policy_raw.get("lockout_duration_mins") or policy_raw.get("lockout_duration")),
            "password_history": _safe_int(policy_raw.get("password_history_length") or policy_raw.get("password_history")),
            "max_age": _safe_int(policy_raw.get("max_password_age_days") or policy_raw.get("maximum_password_age")),
            "complexity": complexity,
        }

    # ── Domain Info ──
    domain_info = {}
    if domain:
        domain_info["domain"] = domain
    dns_domain = os_info_raw.get("FQDN", "") or os_info_raw.get("DNS domain", "")
    if dns_domain:
        domain_info["dns_domain"] = dns_domain
    forest = os_info_raw.get("Forest", "") or os_info_raw.get("forest", "")
    if forest:
        domain_info["forest"] = forest
    dc = os_info_raw.get("DC", "") or os_info_raw.get("dc", "")
    if dc:
        domain_info["dc"] = dc

    # ── Printers ──
    printers = []
    printers_raw = data.get("printers") or {}
    for name, info in printers_raw.items():
        printers.append({
            "name": name,
            "description": info.get("description", "") if isinstance(info, dict) else str(info),
        })

    # ── Vulnerability Detection ──
    vulnerabilities = []
    null_session_users = len(users) > 0
    null_session_shares = any(s["access"] in ("READ", "READ,WRITE", "WRITE") for s in shares)

    if null_session_users:
        vulnerabilities.append({
            "id": "null_session_users",
            "severity": "medium",
            "title": f"Null Session — User Enumeration ({len(users)} users)",
            "description": "Users could be enumerated without authentication via null session",
        })
    if null_session_shares:
        accessible = [s["name"] for s in shares if s["access"] in ("READ", "READ,WRITE", "WRITE")]
        vulnerabilities.append({
            "id": "null_session_shares",
            "severity": "medium",
            "title": f"Null Session — Share Access ({len(accessible)} shares)",
            "description": "Shares accessible without authentication: " + ", ".join(accessible),
        })
    if password_policy:
        ml = password_policy.get("min_length", 0)
        if isinstance(ml, int) and ml < 8 and ml > 0:
            vulnerabilities.append({
                "id": "weak_password_policy",
                "severity": "high",
                "title": f"Weak Password Policy (min length: {ml})",
                "description": "Minimum password length is below 8 characters — brute force risk",
            })
        lt = password_policy.get("lockout_threshold", -1)
        if isinstance(lt, int) and lt == 0:
            vulnerabilities.append({
                "id": "no_lockout",
                "severity": "high",
                "title": "No Account Lockout",
                "description": "Account lockout threshold is 0 — unlimited password guessing possible",
            })

    return {
        "os_info": os_info,
        "users": users,
        "groups": groups,
        "shares": shares,
        "password_policy": password_policy,
        "domain_info": domain_info,
        "printers": printers,
        "vulnerabilities": vulnerabilities,
        "summary": {
            "users_count": len(users),
            "groups_count": len(groups),
            "shares_count": len(shares),
        },
        "total_vulnerabilities": len(vulnerabilities),
    }


# Backward-compatible alias
scan = enum4linux_scan
