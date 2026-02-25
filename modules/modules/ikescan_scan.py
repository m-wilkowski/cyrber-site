import subprocess
import shutil
import re


def ikescan_scan(target: str) -> dict:
    """
    Run ike-scan to discover and fingerprint IKE/IPsec VPN gateways.
    Probes UDP 500 (IKE) and UDP 4500 (NAT-T) to detect VPN endpoints,
    identify supported transforms, and detect aggressive mode vulnerabilities.
    """
    ike_bin = shutil.which("ike-scan")
    if not ike_bin:
        return {"skipped": True, "reason": "ike-scan not installed"}

    host = target.strip()
    for prefix in ["http://", "https://", "ftp://"]:
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0].split(":")[0]

    result = {
        "target": host,
        "ike_detected": False,
        "main_mode": None,
        "aggressive_mode": None,
        "nat_t": None,
        "transforms": [],
        "total_transforms": 0,
        "vendor_id": None,
        "implementation": None,
        "vulnerabilities": [],
        "total_vulnerabilities": 0,
    }

    # Phase 1: Main Mode scan (default)
    main = _run_ike_scan(ike_bin, host, [])
    if main:
        result["ike_detected"] = True
        result["main_mode"] = main

    # Phase 2: Aggressive Mode scan
    aggressive = _run_ike_scan(ike_bin, host, ["--aggressive", "--id=vpntest"])
    if aggressive:
        result["ike_detected"] = True
        result["aggressive_mode"] = aggressive

    # Phase 3: NAT-T (port 4500) scan
    nat_t = _run_ike_scan(ike_bin, host, ["--nat-t"])
    if nat_t:
        result["nat_t"] = nat_t

    if not result["ike_detected"]:
        return {"skipped": True, "reason": "No IKE service detected on target"}

    # Collect transforms from all modes
    all_transforms = []
    for mode_data in [main, aggressive]:
        if mode_data and mode_data.get("transforms"):
            all_transforms.extend(mode_data["transforms"])
    result["transforms"] = all_transforms
    result["total_transforms"] = len(all_transforms)

    # Extract vendor info
    for mode_data in [main, aggressive, nat_t]:
        if mode_data:
            if mode_data.get("vendor_id") and not result["vendor_id"]:
                result["vendor_id"] = mode_data["vendor_id"]
            if mode_data.get("implementation") and not result["implementation"]:
                result["implementation"] = mode_data["implementation"]

    _detect_vulnerabilities(result)
    return result


def _run_ike_scan(ike_bin: str, host: str, extra_args: list) -> dict:
    """Run a single ike-scan probe and parse results."""
    try:
        cmd = [ike_bin, host, "--retry=2", "--timeout=500"] + extra_args
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = proc.stdout + "\n" + proc.stderr
        return _parse_ike_output(output, host)
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def _parse_ike_output(output: str, host: str) -> dict:
    """Parse ike-scan text output."""
    result = {
        "responded": False,
        "handshake": None,
        "transforms": [],
        "vendor_id": None,
        "implementation": None,
        "notify_message": None,
        "raw_sa": None,
    }

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Check if host responded
        # "192.168.1.1  Main Mode Handshake returned"
        # "192.168.1.1  Aggressive Mode Handshake returned"
        if host in line and "Handshake returned" in line:
            result["responded"] = True
            if "Main Mode" in line:
                result["handshake"] = "main"
            elif "Aggressive Mode" in line:
                result["handshake"] = "aggressive"
            continue

        # Notify message (no response)
        # "192.168.1.1  Notify Message 14 (NO-PROPOSAL-CHOSEN)"
        notify_match = re.search(r"Notify Message\s+\d+\s+\(([^)]+)\)", line)
        if notify_match:
            result["responded"] = True
            result["notify_message"] = notify_match.group(1)
            continue

        # SA transform
        # "SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK ...)"
        sa_match = re.search(r"SA=\(([^)]+)\)", line)
        if sa_match:
            sa_str = sa_match.group(1)
            result["raw_sa"] = sa_str
            transform = _parse_transform(sa_str)
            if transform:
                result["transforms"].append(transform)
            continue

        # Vendor ID
        # "VID=... (Cisco VPN Concentrator)"
        vid_match = re.search(r"VID=\S+\s+\(([^)]+)\)", line)
        if vid_match:
            result["vendor_id"] = vid_match.group(1)
            continue

        # Plain vendor ID hex
        vid_hex_match = re.search(r"VID=([0-9a-fA-F]+)", line)
        if vid_hex_match and not result["vendor_id"]:
            result["vendor_id"] = vid_hex_match.group(1)[:32]
            continue

        # Implementation detection
        for impl in [
            "Cisco", "Juniper", "Checkpoint", "Fortinet", "SonicWall",
            "Palo Alto", "StrongSwan", "OpenSwan", "Libreswan",
            "racoon", "isakmpd", "Windows",
        ]:
            if impl.lower() in line.lower():
                result["implementation"] = impl
                break

    if not result["responded"]:
        return None
    return result


def _parse_transform(sa_str: str) -> dict:
    """Parse SA transform string into structured data."""
    transform = {}

    enc_match = re.search(r"Enc=(\S+)", sa_str)
    if enc_match:
        transform["encryption"] = enc_match.group(1)

    hash_match = re.search(r"Hash=(\S+)", sa_str)
    if hash_match:
        transform["hash"] = hash_match.group(1)

    group_match = re.search(r"Group=(\S+)", sa_str)
    if group_match:
        transform["dh_group"] = group_match.group(1)

    auth_match = re.search(r"Auth=(\S+)", sa_str)
    if auth_match:
        transform["auth"] = auth_match.group(1)

    life_match = re.search(r"LifeType=(\S+)", sa_str)
    if life_match:
        transform["life_type"] = life_match.group(1)

    dur_match = re.search(r"LifeDuration=(\S+)", sa_str)
    if dur_match:
        transform["life_duration"] = dur_match.group(1)

    # Assess strength
    enc = transform.get("encryption", "")
    hsh = transform.get("hash", "")
    grp = transform.get("dh_group", "")

    weak_enc = any(w in enc.upper() for w in ["DES", "3DES", "RC4", "BLOWFISH"])
    weak_hash = any(w in hsh.upper() for w in ["MD5"])
    weak_group = any(w in grp for w in ["1:", "2:", "1 ", "2 "])  # DH group 1 or 2

    if weak_enc and "3DES" not in enc.upper():
        transform["strength"] = "weak"
    elif weak_enc or weak_hash or weak_group:
        transform["strength"] = "moderate"
    else:
        transform["strength"] = "strong"

    return transform


def _detect_vulnerabilities(result: dict):
    """Detect VPN vulnerabilities based on ike-scan findings."""
    vulns = []

    # Aggressive Mode enabled
    agg = result.get("aggressive_mode")
    if agg and agg.get("responded") and agg.get("handshake") == "aggressive":
        vulns.append({
            "title": "IKE Aggressive Mode Enabled",
            "severity": "high",
            "description": "IKE Aggressive Mode is enabled. The pre-shared key hash is transmitted "
                           "in the clear during Phase 1, allowing offline brute-force attacks.",
            "mitre": "T1110.002",
            "remediation": "Disable IKE Aggressive Mode. Use only Main Mode with certificate-based "
                           "authentication or strong PSK (20+ characters).",
        })

    # Weak encryption algorithms
    weak_transforms = [
        t for t in result.get("transforms", [])
        if t.get("strength") == "weak"
    ]
    if weak_transforms:
        weak_enc = set(t.get("encryption", "") for t in weak_transforms)
        vulns.append({
            "title": "Weak IKE Encryption Algorithms",
            "severity": "high",
            "description": f"Weak encryption algorithms accepted: {', '.join(weak_enc)}. "
                           f"These can be broken with current computing power.",
            "mitre": "T1600.001",
            "remediation": "Configure VPN to use AES-256 or AES-128. Disable DES, 3DES, RC4, Blowfish.",
        })

    # Weak hash algorithms (MD5)
    md5_transforms = [
        t for t in result.get("transforms", [])
        if "MD5" in t.get("hash", "").upper()
    ]
    if md5_transforms:
        vulns.append({
            "title": "MD5 Hash Algorithm in IKE",
            "severity": "medium",
            "description": "MD5 hash algorithm is accepted for IKE. MD5 is cryptographically broken "
                           "and should not be used for integrity verification.",
            "mitre": "T1600.001",
            "remediation": "Configure VPN to use SHA-256 or SHA-384. Disable MD5 and SHA-1.",
        })

    # Weak DH groups (1 or 2)
    weak_dh = [
        t for t in result.get("transforms", [])
        if any(w in t.get("dh_group", "") for w in ["1:", "2:", "modp768", "modp1024"])
    ]
    if weak_dh:
        groups = set(t.get("dh_group", "") for t in weak_dh)
        vulns.append({
            "title": "Weak Diffie-Hellman Groups",
            "severity": "high",
            "description": f"Weak DH groups accepted: {', '.join(groups)}. "
                           f"Groups 1 (768-bit) and 2 (1024-bit) are vulnerable to Logjam attack.",
            "mitre": "T1600.001",
            "remediation": "Use DH Group 14 (2048-bit) minimum. Prefer Group 19/20 (ECDH) or Group 21 (ECP-521).",
        })

    # PSK authentication (pre-shared key)
    psk_transforms = [
        t for t in result.get("transforms", [])
        if t.get("auth", "").upper() == "PSK"
    ]
    if psk_transforms and agg and agg.get("handshake") == "aggressive":
        vulns.append({
            "title": "PSK with Aggressive Mode — Key Recovery Risk",
            "severity": "critical",
            "description": "Pre-Shared Key authentication combined with Aggressive Mode. "
                           "The PSK hash can be captured and cracked offline using tools like ike-crack.",
            "mitre": "T1110.002",
            "remediation": "Switch to certificate-based authentication (RSA/ECDSA). "
                           "If PSK is required, disable Aggressive Mode and use very strong keys (20+ chars).",
        })

    # NAT-T detected (informational + potential bypass)
    nat_t = result.get("nat_t")
    if nat_t and nat_t.get("responded"):
        vulns.append({
            "title": "IKE NAT-Traversal Enabled",
            "severity": "low",
            "description": "NAT-Traversal (UDP 4500) is enabled. While necessary for NAT environments, "
                           "it may allow VPN traffic to bypass certain firewall rules.",
            "mitre": "T1572",
            "remediation": "Ensure NAT-T is only enabled when required. Monitor UDP 4500 traffic.",
        })

    result["vulnerabilities"] = vulns
    result["total_vulnerabilities"] = len(vulns)
    result["critical_count"] = sum(1 for v in vulns if v["severity"] == "critical")
    result["high_count"] = sum(1 for v in vulns if v["severity"] == "high")
    result["medium_count"] = sum(1 for v in vulns if v["severity"] == "medium")
    result["low_count"] = sum(1 for v in vulns if v["severity"] == "low")
