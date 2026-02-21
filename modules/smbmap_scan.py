import subprocess
import shutil
import re


def smbmap_scan(target: str) -> dict:
    """
    Run SMBMap to enumerate SMB shares, permissions, and files.
    Attempts null session and guest access to discover accessible shares,
    writable directories, and sensitive files.
    """
    smbmap_bin = shutil.which("smbmap")
    if not smbmap_bin:
        return {"skipped": True, "reason": "smbmap not installed"}

    host = target.strip()
    for prefix in ["http://", "https://", "ftp://"]:
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0].split(":")[0]

    result = {
        "target": host,
        "shares": [],
        "total_shares": 0,
        "readable_shares": 0,
        "writable_shares": 0,
        "interesting_files": [],
        "total_files": 0,
        "host_info": {},
        "access_method": None,
        "vulnerabilities": [],
        "total_vulnerabilities": 0,
    }

    # Try null session first, then guest
    for method, user_arg in [("null", ["-u", "", "-p", ""]), ("guest", ["-u", "guest", "-p", ""])]:
        shares = _run_smbmap_shares(smbmap_bin, host, user_arg)
        if shares:
            result["access_method"] = method
            result["shares"] = shares
            result["total_shares"] = len(shares)
            result["readable_shares"] = sum(1 for s in shares if s.get("read"))
            result["writable_shares"] = sum(1 for s in shares if s.get("write"))

            # Enumerate files on readable shares
            readable = [s["name"] for s in shares if s.get("read")]
            if readable:
                files = _run_smbmap_files(smbmap_bin, host, user_arg, readable)
                result["interesting_files"] = files
                result["total_files"] = len(files)
            break

    # Detect vulnerabilities
    _detect_vulnerabilities(result)

    return result


def _run_smbmap_shares(smbmap_bin: str, host: str, user_arg: list) -> list:
    """Run smbmap to list shares and their permissions."""
    try:
        cmd = [smbmap_bin, "-H", host] + user_arg + ["--no-banner"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = proc.stdout
        return _parse_shares(output)
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


def _parse_shares(output: str) -> list:
    """Parse smbmap share listing output."""
    shares = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # SMBMap output format:
        # SHARE_NAME        READ, WRITE     or   READ ONLY   or   NO ACCESS
        # Also: "Disk" column sometimes present
        # Typical: "  IPC$            NO ACCESS"
        # Or:      "  Users           READ ONLY"
        # Or:      "  Public          READ, WRITE"

        # Match share lines - they typically have share name followed by access level
        share_match = re.match(
            r"^\s*(\S+)\s+.*?(READ(?:\s*,\s*WRITE)?|READ\s+ONLY|WRITE\s+ONLY|NO\s+ACCESS)\s*$",
            line, re.IGNORECASE,
        )
        if share_match:
            name = share_match.group(1)
            access = share_match.group(2).upper().strip()

            # Skip header lines
            if name.upper() in ("SHARE", "-----", "DISK", "----"):
                continue

            read_access = "READ" in access
            write_access = "WRITE" in access and "ONLY" not in access.replace("WRITE ONLY", "")
            # Handle "READ, WRITE"
            if "READ" in access and "WRITE" in access:
                read_access = True
                write_access = True
            elif "WRITE ONLY" in access:
                read_access = False
                write_access = True

            shares.append({
                "name": name,
                "access": access,
                "read": read_access,
                "write": write_access,
            })
            continue

        # Alternative format: columns with Disk type
        # "  ShareName    Disk    READ, WRITE    Comment here"
        alt_match = re.match(
            r"^\s*(\S+)\s+Disk\s+(READ(?:\s*,\s*WRITE)?|READ\s+ONLY|WRITE\s+ONLY|NO\s+ACCESS)\s*(.*)?$",
            line, re.IGNORECASE,
        )
        if alt_match:
            name = alt_match.group(1)
            access = alt_match.group(2).upper().strip()
            comment = (alt_match.group(3) or "").strip()

            read_access = "READ" in access
            write_access = "READ" in access and "WRITE" in access
            if "WRITE ONLY" in access:
                read_access = False
                write_access = True

            entry = {
                "name": name,
                "access": access,
                "read": read_access,
                "write": write_access,
            }
            if comment:
                entry["comment"] = comment
            shares.append(entry)

    return shares


def _run_smbmap_files(smbmap_bin: str, host: str, user_arg: list, share_names: list) -> list:
    """Recursively list files on readable shares, filter interesting ones."""
    interesting = []
    interesting_patterns = re.compile(
        r"\.(conf|config|cfg|ini|xml|bak|old|backup|sql|db|sqlite|mdb|"
        r"key|pem|crt|cer|pfx|p12|kdbx|kdb|"
        r"bat|ps1|vbs|cmd|sh|py|"
        r"rdp|ovpn|vpn|"
        r"doc|docx|xls|xlsx|pdf|txt|csv|log)$",
        re.IGNORECASE,
    )
    sensitive_names = re.compile(
        r"(password|passwd|credential|secret|token|api.?key|"
        r"web\.config|\.htaccess|\.env|shadow|id_rsa|authorized_keys|"
        r"ntds|sam|system|security|unattend|sysprep)",
        re.IGNORECASE,
    )

    for share in share_names[:5]:  # Limit to 5 shares
        try:
            cmd = [smbmap_bin, "-H", host] + user_arg + [
                "-r", share, "--depth", "2", "--no-banner",
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue

                # File listing lines contain file size and date
                # "  dr--r--r--   0  Mon Jan  1 00:00:00 2024  dirname"
                # "  -r--r--r--  1234  Mon Jan  1 00:00:00 2024  file.txt"
                file_match = re.match(
                    r"^\s*([drwx\-]+)\s+(\d+)\s+\w+\s+\w+\s+\d+\s+[\d:]+\s+\d+\s+(.+)$",
                    line,
                )
                if not file_match:
                    # Alternative: simpler format
                    file_match = re.search(r"(\S+\.\w{2,5})\s*$", line)
                    if file_match:
                        fname = file_match.group(1)
                        if interesting_patterns.search(fname) or sensitive_names.search(fname):
                            entry = {
                                "share": share,
                                "filename": fname,
                                "sensitive": bool(sensitive_names.search(fname)),
                            }
                            if entry not in interesting:
                                interesting.append(entry)
                    continue

                perms = file_match.group(1)
                size = int(file_match.group(2))
                fname = file_match.group(3).strip()

                if fname in (".", ".."):
                    continue

                is_dir = perms.startswith("d")
                is_interesting = interesting_patterns.search(fname) or sensitive_names.search(fname)

                if is_interesting and not is_dir:
                    entry = {
                        "share": share,
                        "filename": fname,
                        "size": size,
                        "permissions": perms,
                        "sensitive": bool(sensitive_names.search(fname)),
                    }
                    interesting.append(entry)

        except (subprocess.TimeoutExpired, Exception):
            continue

    return interesting[:100]


def _detect_vulnerabilities(result: dict):
    """Detect vulnerabilities based on SMBMap findings."""
    vulns = []

    if result.get("access_method") == "null":
        vulns.append({
            "title": "SMB Null Session Allowed",
            "severity": "high",
            "description": "SMB server accepts null session connections, allowing anonymous enumeration of shares.",
            "mitre": "T1021.002",
            "remediation": "Disable null sessions: set 'RestrictAnonymous' to 2 in registry or via Group Policy.",
        })
    elif result.get("access_method") == "guest":
        vulns.append({
            "title": "SMB Guest Access Allowed",
            "severity": "medium",
            "description": "SMB server accepts guest authentication, allowing unauthenticated access to shares.",
            "mitre": "T1021.002",
            "remediation": "Disable guest access: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Accounts: Guest account status' = Disabled",
        })

    if result.get("writable_shares", 0) > 0:
        writable = [s["name"] for s in result.get("shares", []) if s.get("write")]
        vulns.append({
            "title": "Writable SMB Shares Detected",
            "severity": "high",
            "description": f"Anonymous/guest write access to shares: {', '.join(writable)}. "
                           f"Attackers can upload malicious files or backdoors.",
            "mitre": "T1570",
            "remediation": "Remove write permissions for anonymous/guest accounts on all shares. Review share ACLs.",
        })

    sensitive_files = [f for f in result.get("interesting_files", []) if f.get("sensitive")]
    if sensitive_files:
        fnames = list(set(f["filename"] for f in sensitive_files[:5]))
        vulns.append({
            "title": "Sensitive Files Accessible via SMB",
            "severity": "critical" if any(
                re.search(r"(password|ntds|sam|shadow|id_rsa|\.env)", f, re.I)
                for f in fnames
            ) else "high",
            "description": f"Sensitive files found on accessible shares: {', '.join(fnames)}",
            "mitre": "T1083",
            "remediation": "Move sensitive files to restricted shares. Apply principle of least privilege to share permissions.",
        })

    non_default_readable = [
        s["name"] for s in result.get("shares", [])
        if s.get("read") and s["name"].upper() not in ("IPC$", "PRINT$")
    ]
    if len(non_default_readable) > 2:
        vulns.append({
            "title": "Excessive SMB Share Exposure",
            "severity": "medium",
            "description": f"{len(non_default_readable)} non-default shares are readable anonymously: {', '.join(non_default_readable[:5])}",
            "mitre": "T1135",
            "remediation": "Review share permissions. Only expose shares that require anonymous/guest access.",
        })

    result["vulnerabilities"] = vulns
    result["total_vulnerabilities"] = len(vulns)
    result["critical_count"] = sum(1 for v in vulns if v["severity"] == "critical")
    result["high_count"] = sum(1 for v in vulns if v["severity"] == "high")
    result["medium_count"] = sum(1 for v in vulns if v["severity"] == "medium")
