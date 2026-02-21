import subprocess
import shutil
import re
import tempfile
import os


# Common SNMP community strings to brute-force
COMMUNITY_STRINGS = [
    "public", "private", "community", "manager", "cisco", "admin",
    "snmp", "default", "monitor", "secret", "read", "write",
    "ILMI", "openview", "tivoli", "all private", "system",
    "cable-docsis", "rmon", "rmon_admin", "hp_admin",
    "internal", "mngt", "access", "netman", "network",
    "security", "snmpd", "test", "guest",
]


def onesixtyone_scan(target: str) -> dict:
    """
    Run onesixtyone to brute-force SNMP community strings on a target.
    Discovers which community strings are accepted, revealing SNMP access
    and the system description for each valid string.
    """
    ost_bin = shutil.which("onesixtyone")
    if not ost_bin:
        return {"skipped": True, "reason": "onesixtyone not installed"}

    host = target.strip()
    for prefix in ["http://", "https://", "ftp://"]:
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0].split(":")[0]

    result = {
        "target": host,
        "communities_found": [],
        "total_found": 0,
        "total_tested": len(COMMUNITY_STRINGS),
        "system_descriptions": [],
        "vulnerabilities": [],
        "total_vulnerabilities": 0,
    }

    try:
        # Write community strings to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="ost_"
        ) as f:
            for cs in COMMUNITY_STRINGS:
                f.write(cs + "\n")
            cs_file = f.name

        try:
            cmd = [ost_bin, "-c", cs_file, host]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = proc.stdout + "\n" + proc.stderr
            _parse_output(output, host, result)
        finally:
            os.unlink(cs_file)

    except subprocess.TimeoutExpired:
        result["error"] = "onesixtyone scan timed out after 60s"
    except Exception as e:
        result["error"] = str(e)

    _detect_vulnerabilities(result)
    return result


def _parse_output(output: str, target_host: str, result: dict):
    """Parse onesixtyone output.

    Typical output format:
      192.168.1.1 [public] Linux router 4.19.0 #1 SMP
      192.168.1.1 [private] Linux router 4.19.0 #1 SMP
    """
    communities = []
    descriptions = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Match: IP [community] sysDescr
        match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\s+\[([^\]]+)\]\s+(.*)",
            line,
        )
        if match:
            ip = match.group(1)
            community = match.group(2)
            sys_descr = match.group(3).strip()

            entry = {
                "community": community,
                "system_description": sys_descr,
            }

            # Classify community string risk
            if community.lower() in ("public",):
                entry["risk"] = "medium"
                entry["type"] = "default_read"
            elif community.lower() in ("private", "write", "all private"):
                entry["risk"] = "critical"
                entry["type"] = "write_access"
            elif community.lower() in (
                "admin", "manager", "secret", "security",
                "hp_admin", "rmon_admin",
            ):
                entry["risk"] = "high"
                entry["type"] = "privileged"
            else:
                entry["risk"] = "high"
                entry["type"] = "custom"

            communities.append(entry)

            if sys_descr and sys_descr not in descriptions:
                descriptions.append(sys_descr)

        # Also match hostname-based output
        # "hostname [community] sysDescr"
        match2 = re.match(
            r"^(\S+)\s+\[([^\]]+)\]\s+(.*)",
            line,
        )
        if match2 and not match:
            hostname = match2.group(1)
            community = match2.group(2)
            sys_descr = match2.group(3).strip()

            entry = {
                "community": community,
                "system_description": sys_descr,
            }
            if community.lower() in ("public",):
                entry["risk"] = "medium"
                entry["type"] = "default_read"
            elif community.lower() in ("private", "write", "all private"):
                entry["risk"] = "critical"
                entry["type"] = "write_access"
            elif community.lower() in (
                "admin", "manager", "secret", "security",
            ):
                entry["risk"] = "high"
                entry["type"] = "privileged"
            else:
                entry["risk"] = "high"
                entry["type"] = "custom"

            communities.append(entry)
            if sys_descr and sys_descr not in descriptions:
                descriptions.append(sys_descr)

    result["communities_found"] = communities
    result["total_found"] = len(communities)
    result["system_descriptions"] = descriptions


def _detect_vulnerabilities(result: dict):
    """Detect vulnerabilities based on discovered community strings."""
    vulns = []
    communities = result.get("communities_found", [])

    if not communities:
        return

    # Any community string found = SNMP is accessible
    vulns.append({
        "title": "SNMP Service Accessible",
        "severity": "medium",
        "description": f"SNMP service responds to community string brute-force. "
                       f"{len(communities)} valid community string(s) discovered.",
        "mitre": "T1046",
        "remediation": "Restrict SNMP access via firewall rules (UDP 161). "
                       "Use SNMPv3 with authentication and encryption.",
    })

    # Default community strings
    defaults = [c for c in communities if c["community"].lower() in ("public", "private")]
    if defaults:
        vulns.append({
            "title": "Default SNMP Community Strings",
            "severity": "high",
            "description": "Default community strings accepted: "
                           + ", ".join(set(c["community"] for c in defaults))
                           + ". Attackers can enumerate system information.",
            "mitre": "T1552.001",
            "remediation": "Change default community strings to unique, complex values. "
                           "Migrate to SNMPv3.",
        })

    # Write-access community strings
    write_cs = [c for c in communities if c.get("type") == "write_access"]
    if write_cs:
        vulns.append({
            "title": "SNMP Write Access Community String Found",
            "severity": "critical",
            "description": "Write-capable community strings discovered: "
                           + ", ".join(set(c["community"] for c in write_cs))
                           + ". Attackers can modify device configuration remotely.",
            "mitre": "T1059",
            "remediation": "Immediately change write community strings. Disable SNMP write access "
                           "if not required. Use SNMPv3 with auth+priv.",
        })

    # Privileged community strings
    priv_cs = [c for c in communities if c.get("type") == "privileged"]
    if priv_cs:
        vulns.append({
            "title": "Privileged SNMP Community Strings",
            "severity": "high",
            "description": "Privileged/administrative community strings accepted: "
                           + ", ".join(set(c["community"] for c in priv_cs))
                           + ".",
            "mitre": "T1552.001",
            "remediation": "Change all privileged community strings to unique values. "
                           "Restrict SNMP access to management network only.",
        })

    # Weak/guessable community strings
    weak_cs = [c for c in communities if c.get("type") == "custom"]
    if weak_cs:
        vulns.append({
            "title": "Weak/Guessable SNMP Community Strings",
            "severity": "high",
            "description": "Easily guessable community strings found via brute-force: "
                           + ", ".join(set(c["community"] for c in weak_cs))
                           + ".",
            "mitre": "T1110.001",
            "remediation": "Use strong, random community strings (16+ characters). "
                           "Migrate to SNMPv3.",
        })

    result["vulnerabilities"] = vulns
    result["total_vulnerabilities"] = len(vulns)
    result["critical_count"] = sum(1 for v in vulns if v["severity"] == "critical")
    result["high_count"] = sum(1 for v in vulns if v["severity"] == "high")
    result["medium_count"] = sum(1 for v in vulns if v["severity"] == "medium")
