import subprocess
import shutil
import json
import os
import glob
import zipfile
import tempfile
import re


def _find_bloodhound_bin():
    """Find bloodhound-python or bloodhound collector binary."""
    for name in ["bloodhound-python", "bloodhound"]:
        path = shutil.which(name)
        if path:
            return path
    return None


def _parse_json_files(output_dir: str) -> dict:
    """Parse BloodHound JSON output files from collection directory."""
    result = {
        "users": [],
        "computers": [],
        "groups": [],
        "domains": [],
        "gpos": [],
        "ous": [],
        "sessions": [],
        "attack_paths": [],
    }

    json_files = glob.glob(os.path.join(output_dir, "*.json"))

    # Also check for zip files and extract them
    zip_files = glob.glob(os.path.join(output_dir, "*.zip"))
    for zf in zip_files:
        try:
            with zipfile.ZipFile(zf, "r") as z:
                z.extractall(output_dir)
            json_files = glob.glob(os.path.join(output_dir, "*.json"))
        except Exception:
            pass

    for jf in json_files:
        try:
            with open(jf, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            continue

        fname = os.path.basename(jf).lower()

        # BloodHound JSON format: {"data": [...], "meta": {...}}
        items = data if isinstance(data, list) else data.get("data", data.get("computers", data.get("users", data.get("groups", []))))
        if not isinstance(items, list):
            items = [data]

        if "user" in fname:
            for item in items:
                props = item.get("Properties", item.get("properties", item))
                if not isinstance(props, dict):
                    continue
                user = {
                    "name": props.get("name", "") or props.get("samaccountname", ""),
                    "domain": props.get("domain", ""),
                    "enabled": props.get("enabled", True),
                    "admin_count": props.get("admincount", False),
                    "last_logon": props.get("lastlogon", ""),
                    "password_never_expires": props.get("pwdneverexpires", False),
                    "password_not_required": props.get("passwordnotreqd", False),
                    "dont_require_preauth": props.get("dontreqpreauth", False),
                    "has_spn": props.get("hasspn", False),
                    "description": props.get("description", ""),
                }
                if user["name"]:
                    result["users"].append(user)

        elif "computer" in fname:
            for item in items:
                props = item.get("Properties", item.get("properties", item))
                if not isinstance(props, dict):
                    continue
                comp = {
                    "name": props.get("name", ""),
                    "domain": props.get("domain", ""),
                    "os": props.get("operatingsystem", ""),
                    "enabled": props.get("enabled", True),
                    "unconstraineddelegation": props.get("unconstraineddelegation", False),
                    "owned": props.get("owned", False),
                    "has_laps": props.get("haslaps", False),
                    "last_logon": props.get("lastlogontimestamp", ""),
                }
                if comp["name"]:
                    result["computers"].append(comp)

        elif "group" in fname:
            for item in items:
                props = item.get("Properties", item.get("properties", item))
                members_raw = item.get("Members", item.get("members", []))
                if not isinstance(props, dict):
                    continue
                members = []
                if isinstance(members_raw, list):
                    for m in members_raw:
                        if isinstance(m, dict):
                            members.append(m.get("MemberName", m.get("ObjectIdentifier", str(m))))
                        else:
                            members.append(str(m))
                grp = {
                    "name": props.get("name", ""),
                    "domain": props.get("domain", ""),
                    "admin_count": props.get("admincount", False),
                    "member_count": len(members),
                    "members": members[:20],
                }
                if grp["name"]:
                    result["groups"].append(grp)

        elif "domain" in fname:
            for item in items:
                props = item.get("Properties", item.get("properties", item))
                if not isinstance(props, dict):
                    continue
                dom = {
                    "name": props.get("name", ""),
                    "functional_level": props.get("functionallevel", ""),
                    "domain_controllers": [],
                }
                # Extract child objects that are DCs
                children = item.get("ChildObjects", [])
                if isinstance(children, list):
                    for c in children:
                        if isinstance(c, dict) and c.get("ObjectType", "").lower() == "computer":
                            dom["domain_controllers"].append(c.get("ObjectIdentifier", ""))
                if dom["name"]:
                    result["domains"].append(dom)

        elif "gpo" in fname:
            for item in items:
                props = item.get("Properties", item.get("properties", item))
                if not isinstance(props, dict):
                    continue
                gpo = {
                    "name": props.get("name", ""),
                    "domain": props.get("domain", ""),
                    "gpc_path": props.get("gpcpath", ""),
                }
                if gpo["name"]:
                    result["gpos"].append(gpo)

        elif "ou" in fname:
            for item in items:
                props = item.get("Properties", item.get("properties", item))
                if not isinstance(props, dict):
                    continue
                ou = {
                    "name": props.get("name", ""),
                    "domain": props.get("domain", ""),
                    "guid": props.get("objectid", ""),
                }
                if ou["name"]:
                    result["ous"].append(ou)

        elif "session" in fname:
            for item in items:
                if isinstance(item, dict):
                    session = {
                        "user": item.get("UserName", item.get("user", "")),
                        "computer": item.get("ComputerName", item.get("computer", "")),
                    }
                    if session["user"] and session["computer"]:
                        result["sessions"].append(session)

    return result


def _detect_attack_paths(data: dict) -> list:
    """Detect common AD attack paths from collected data."""
    paths = []

    # Kerberoastable users (has SPN + enabled)
    kerberoastable = [u for u in data["users"] if u.get("has_spn") and u.get("enabled")]
    if kerberoastable:
        paths.append({
            "id": "kerberoasting",
            "severity": "high",
            "title": f"Kerberoastable Accounts ({len(kerberoastable)})",
            "description": "Users with SPNs set can be targeted for offline password cracking",
            "affected": [u["name"] for u in kerberoastable[:10]],
            "mitre": "T1558.003",
        })

    # AS-REP Roastable (dont_require_preauth + enabled)
    asrep = [u for u in data["users"] if u.get("dont_require_preauth") and u.get("enabled")]
    if asrep:
        paths.append({
            "id": "asrep_roasting",
            "severity": "high",
            "title": f"AS-REP Roastable Accounts ({len(asrep)})",
            "description": "Users with 'Do not require Kerberos preauthentication' — can obtain TGT without password",
            "affected": [u["name"] for u in asrep[:10]],
            "mitre": "T1558.004",
        })

    # Password not required
    no_pass = [u for u in data["users"] if u.get("password_not_required") and u.get("enabled")]
    if no_pass:
        paths.append({
            "id": "password_not_required",
            "severity": "critical",
            "title": f"Password Not Required ({len(no_pass)})",
            "description": "Accounts with PASSWD_NOTREQD flag — can have empty password",
            "affected": [u["name"] for u in no_pass[:10]],
            "mitre": "T1078",
        })

    # Password never expires
    never_expire = [u for u in data["users"] if u.get("password_never_expires") and u.get("enabled")]
    if never_expire:
        paths.append({
            "id": "password_never_expires",
            "severity": "medium",
            "title": f"Password Never Expires ({len(never_expire)})",
            "description": "Accounts with non-expiring passwords increase brute force window",
            "affected": [u["name"] for u in never_expire[:10]],
            "mitre": "T1110",
        })

    # Unconstrained delegation
    uncon_deleg = [c for c in data["computers"] if c.get("unconstraineddelegation") and c.get("enabled")]
    if uncon_deleg:
        paths.append({
            "id": "unconstrained_delegation",
            "severity": "critical",
            "title": f"Unconstrained Delegation ({len(uncon_deleg)})",
            "description": "Computers with unconstrained delegation can impersonate any user",
            "affected": [c["name"] for c in uncon_deleg[:10]],
            "mitre": "T1134.001",
        })

    # Admin count users (highly privileged)
    admin_users = [u for u in data["users"] if u.get("admin_count") and u.get("enabled")]
    if len(admin_users) > 5:
        paths.append({
            "id": "excessive_admins",
            "severity": "medium",
            "title": f"Excessive Admin Accounts ({len(admin_users)})",
            "description": "Large number of accounts with adminCount=1 increases attack surface",
            "affected": [u["name"] for u in admin_users[:10]],
            "mitre": "T1078.002",
        })

    # No LAPS on computers
    no_laps = [c for c in data["computers"] if not c.get("has_laps") and c.get("enabled")]
    if no_laps and len(data["computers"]) > 0:
        ratio = len(no_laps) / len(data["computers"])
        if ratio > 0.5:
            paths.append({
                "id": "no_laps",
                "severity": "medium",
                "title": f"No LAPS ({len(no_laps)}/{len(data['computers'])} computers)",
                "description": "Computers without LAPS may share local admin passwords — lateral movement risk",
                "affected": [c["name"] for c in no_laps[:10]],
                "mitre": "T1078.003",
            })

    return paths


def bloodhound_scan(target: str) -> dict:
    """Active Directory enumeration using BloodHound Python collector."""
    bh_bin = _find_bloodhound_bin()
    if not bh_bin:
        return {"skipped": True, "reason": "bloodhound-python not installed"}

    # Strip protocol/path — target should be domain or DC IP
    host = re.sub(r'^https?://', '', target)
    host = host.split('/')[0].split(':')[0]

    output_dir = tempfile.mkdtemp(prefix="bloodhound_")

    try:
        # Run bloodhound-python with all collection methods
        # Uses anonymous/null bind — will fail on hardened DCs but gracefully
        proc = subprocess.run(
            [
                bh_bin,
                "-c", "All",
                "-d", host,
                "-ns", host,
                "--zip",
                "-op", os.path.join(output_dir, "bh"),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        stderr = proc.stderr or ""

        # Check for auth/connection failures
        if proc.returncode != 0:
            if "Could not authenticate" in stderr or "Connection refused" in stderr:
                return {"skipped": True, "reason": "Cannot authenticate to AD (credentials required)"}
            if "Name or service not known" in stderr or "LDAP" in stderr:
                return {"skipped": True, "reason": "Not an Active Directory target"}
            # Partial results may still exist — continue parsing

        data = _parse_json_files(output_dir)

        # If we got nothing useful
        total_objects = (
            len(data["users"]) + len(data["computers"]) +
            len(data["groups"]) + len(data["domains"])
        )
        if total_objects == 0:
            reason = "No AD data collected"
            if "credentials" in stderr.lower() or "auth" in stderr.lower():
                reason = "Authentication required — provide domain credentials for full enumeration"
            return {"skipped": True, "reason": reason}

        # Detect attack paths
        attack_paths = _detect_attack_paths(data)

        # Count severity
        critical_count = sum(1 for p in attack_paths if p["severity"] == "critical")
        high_count = sum(1 for p in attack_paths if p["severity"] == "high")
        medium_count = sum(1 for p in attack_paths if p["severity"] == "medium")

        return {
            "users": data["users"],
            "computers": data["computers"],
            "groups": data["groups"],
            "domains": data["domains"],
            "gpos": data["gpos"],
            "ous": data["ous"],
            "sessions": data["sessions"],
            "attack_paths": attack_paths,
            "total_users": len(data["users"]),
            "total_computers": len(data["computers"]),
            "total_groups": len(data["groups"]),
            "total_domains": len(data["domains"]),
            "total_gpos": len(data["gpos"]),
            "total_sessions": len(data["sessions"]),
            "total_attack_paths": len(attack_paths),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "BloodHound timeout (300s)"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
    finally:
        # Cleanup temp files
        try:
            import shutil as _shutil
            _shutil.rmtree(output_dir, ignore_errors=True)
        except Exception:
            pass
