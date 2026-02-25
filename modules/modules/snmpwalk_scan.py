import subprocess
import shutil
import re


# OID mappings for system info
SYSTEM_OIDS = {
    "1.3.6.1.2.1.1.1": "sysDescr",
    "1.3.6.1.2.1.1.2": "sysObjectID",
    "1.3.6.1.2.1.1.3": "sysUpTime",
    "1.3.6.1.2.1.1.4": "sysContact",
    "1.3.6.1.2.1.1.5": "sysName",
    "1.3.6.1.2.1.1.6": "sysLocation",
}

# OID mappings for interface properties
IFACE_OIDS = {
    "1.3.6.1.2.1.2.2.1.1": "index",
    "1.3.6.1.2.1.2.2.1.2": "name",
    "1.3.6.1.2.1.2.2.1.3": "type",
    "1.3.6.1.2.1.2.2.1.4": "mtu",
    "1.3.6.1.2.1.2.2.1.5": "speed",
    "1.3.6.1.2.1.2.2.1.6": "mac",
    "1.3.6.1.2.1.2.2.1.7": "admin_status",
    "1.3.6.1.2.1.2.2.1.8": "oper_status",
    "1.3.6.1.2.1.2.2.1.10": "in_octets",
    "1.3.6.1.2.1.2.2.1.16": "out_octets",
}

ADMIN_STATUS_MAP = {"1": "up", "2": "down", "3": "testing"}
OPER_STATUS_MAP = {"1": "up", "2": "down", "3": "testing", "4": "unknown", "5": "dormant", "6": "notPresent", "7": "lowerLayerDown"}


def _run_snmpwalk(target: str, oid: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "public", "-t", "10", "-r", "1", "-O", "n", target, oid],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def _parse_snmp_line(line: str):
    """Parse a line like: .1.3.6.1.2.1.1.1.0 = STRING: Linux server 5.4.0"""
    m = re.match(r'^\.?([\d.]+)\s*=\s*(\w+):\s*(.*)$', line)
    if m:
        return m.group(1), m.group(2), m.group(3).strip().strip('"')
    # Handle "No Such" or "No more variables" lines
    return None, None, None


def _format_mac(raw: str) -> str:
    """Format MAC from hex string to XX:XX:XX:XX:XX:XX."""
    raw = raw.strip()
    # Already formatted
    if re.match(r'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$', raw):
        return raw.upper()
    # Hex-String format: XX XX XX XX XX XX
    parts = raw.split()
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        return ":".join(p.upper() for p in parts)
    # Raw hex without separators
    cleaned = re.sub(r'[^0-9a-fA-F]', '', raw)
    if len(cleaned) == 12:
        return ":".join(cleaned[i:i+2].upper() for i in range(0, 12, 2))
    return raw


def _format_speed(speed_str: str) -> str:
    """Format speed from bps to human-readable."""
    try:
        speed = int(speed_str)
        if speed >= 1_000_000_000:
            return f"{speed // 1_000_000_000} Gbps"
        elif speed >= 1_000_000:
            return f"{speed // 1_000_000} Mbps"
        elif speed >= 1_000:
            return f"{speed // 1_000} Kbps"
        return f"{speed} bps"
    except (ValueError, TypeError):
        return speed_str


def snmpwalk_scan(target: str) -> dict:
    """SNMP enumeration using snmpwalk — discovers system info, interfaces, and running services."""
    if not shutil.which("snmpwalk"):
        return {"skipped": True, "reason": "snmpwalk not installed"}

    # ── System info (OID 1.3.6.1.2.1.1) ──
    system_output = _run_snmpwalk(target, "1.3.6.1.2.1.1")
    if not system_output:
        # SNMP not responding or no community access
        return {"skipped": True, "reason": "SNMP not responding (community: public, v2c)"}

    system_info = {}
    for line in system_output.splitlines():
        oid, typ, val = _parse_snmp_line(line)
        if not oid:
            continue
        # Match base OID (strip instance suffix like .0)
        base_oid = re.sub(r'\.\d+$', '', oid)
        field = SYSTEM_OIDS.get(base_oid)
        if field and val:
            system_info[field] = val

    # ── Interfaces (OID 1.3.6.1.2.1.2.2.1) ──
    iface_output = _run_snmpwalk(target, "1.3.6.1.2.1.2.2.1")
    iface_data = {}  # keyed by interface index
    if iface_output:
        for line in iface_output.splitlines():
            oid, typ, val = _parse_snmp_line(line)
            if not oid:
                continue
            # OID format: base_oid.iface_index
            for base_oid, field in IFACE_OIDS.items():
                if oid.startswith(base_oid + "."):
                    idx = oid[len(base_oid) + 1:]
                    if idx not in iface_data:
                        iface_data[idx] = {}
                    iface_data[idx][field] = val
                    break

    interfaces = []
    for idx in sorted(iface_data.keys(), key=lambda x: int(x) if x.isdigit() else 0):
        iface = iface_data[idx]
        admin = iface.get("admin_status", "")
        oper = iface.get("oper_status", "")
        speed_raw = iface.get("speed", "")
        interfaces.append({
            "index": idx,
            "name": iface.get("name", f"if{idx}"),
            "type": iface.get("type", ""),
            "mtu": iface.get("mtu", ""),
            "speed": _format_speed(speed_raw),
            "speed_bps": speed_raw,
            "mac": _format_mac(iface.get("mac", "")),
            "admin_status": ADMIN_STATUS_MAP.get(admin, admin),
            "oper_status": OPER_STATUS_MAP.get(oper, oper),
            "in_octets": iface.get("in_octets", "0"),
            "out_octets": iface.get("out_octets", "0"),
        })

    active_interfaces = sum(1 for i in interfaces if i["oper_status"] == "up")

    # ── Running services (OID 1.3.6.1.2.1.25.4.2.1.2 — hrSWRunName) ──
    services_output = _run_snmpwalk(target, "1.3.6.1.2.1.25.4.2.1.2")
    services = []
    if services_output:
        seen = set()
        for line in services_output.splitlines():
            oid, typ, val = _parse_snmp_line(line)
            if not oid or not val:
                continue
            svc_name = val.strip('"')
            if svc_name and svc_name not in seen:
                seen.add(svc_name)
                services.append(svc_name)
        services.sort()

    return {
        "system_info": system_info,
        "interfaces": interfaces,
        "total_interfaces": len(interfaces),
        "active_interfaces": active_interfaces,
        "services": services,
        "total_services": len(services),
        "snmp_version": "v2c",
        "community_string": "public",
    }
