import os
import re
import json
import shutil
import subprocess
import tempfile


def scan(target: str) -> dict:
    """Run enum4linux-ng against target for SMB/NetBIOS enumeration."""
    # Strip protocol/path
    host = re.sub(r'^https?://', '', target)
    host = host.split('/')[0].split(':')[0]

    # Check if enum4linux-ng is available
    if not shutil.which("enum4linux-ng"):
        return {"target": host, "skipped": True, "reason": "enum4linux-ng not installed"}

    outfile = os.path.join(tempfile.gettempdir(), f"enum4linux_{host}.json")

    try:
        proc = subprocess.run(
            ["enum4linux-ng", "-A", host, "-oJ", outfile],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {"target": host, "skipped": False, "error": "Timeout (120s)", "users": [], "groups": [], "shares": []}
    except Exception as e:
        return {"target": host, "skipped": False, "error": str(e), "users": [], "groups": [], "shares": []}

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
        # No data — host probably doesn't expose SMB
        stderr = (proc.stderr or "")[:500] if proc else ""
        if "Connection refused" in stderr or "Could not negotiate" in stderr:
            return {"target": host, "skipped": True, "reason": "SMB not available on target"}
        return {"target": host, "skipped": False, "error": stderr or "No results", "users": [], "groups": [], "shares": []}

    # Extract users
    users = []
    users_raw = data.get("users") or {}
    for rid, info in users_raw.items():
        users.append({
            "username": info.get("username", ""),
            "rid": rid,
            "description": info.get("acb_info", "") or info.get("description", ""),
        })

    # Extract groups
    groups = []
    groups_raw = data.get("groups") or {}
    for rid, info in groups_raw.items():
        groups.append({
            "name": info.get("groupname", ""),
            "rid": rid,
            "type": info.get("type", ""),
        })

    # Extract shares
    shares = []
    shares_raw = data.get("shares") or {}
    for name, info in shares_raw.items():
        shares.append({
            "name": name,
            "type": info.get("type", ""),
            "comment": info.get("comment", ""),
        })

    # OS info
    os_info_raw = data.get("os_info") or {}
    os_info = {
        "name": os_info_raw.get("OS", ""),
        "version": os_info_raw.get("OS version", ""),
    }

    # Workgroup / domain
    workgroup = data.get("workgroup", "")
    domain = ""
    nmblookup = data.get("nmblookup") or {}
    if isinstance(nmblookup, dict):
        domain = nmblookup.get("domain", "")

    # Password policy
    policy_raw = data.get("policy") or {}
    password_policy = {}
    if policy_raw:
        password_policy = {
            "min_length": policy_raw.get("min_length", ""),
            "lockout_threshold": policy_raw.get("lockout_threshold", ""),
            "lockout_duration": policy_raw.get("lockout_duration_mins", ""),
            "password_history": policy_raw.get("password_history_length", ""),
            "max_password_age": policy_raw.get("max_password_age_days", ""),
        }

    # Printers
    printers = []
    printers_raw = data.get("printers") or {}
    for name, info in printers_raw.items():
        printers.append({
            "name": name,
            "description": info.get("description", "") if isinstance(info, dict) else str(info),
        })

    return {
        "target": host,
        "skipped": False,
        "users": users,
        "groups": groups,
        "shares": shares,
        "os_info": os_info,
        "workgroup": workgroup,
        "domain": domain,
        "password_policy": password_policy,
        "printers": printers,
    }
