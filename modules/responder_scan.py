import subprocess
import shutil
import os
import re
import time


def responder_scan(target: str) -> dict:
    """
    Run Responder in analyze mode (-A) to detect poisonable protocols
    (LLMNR, NBT-NS, MDNS, WPAD) without poisoning.
    Returns detected protocols, browsers, and potential vulnerabilities.
    """
    responder_bin = None
    for path in ["/opt/responder/Responder.py", "/opt/Responder/Responder.py"]:
        if os.path.isfile(path):
            responder_bin = path
            break
    if not responder_bin:
        responder_bin = shutil.which("responder") or shutil.which("Responder")

    if not responder_bin:
        return {"skipped": True, "reason": "Responder not installed"}

    # Responder works on network interfaces, not directly on IPs.
    # Detect which interface can reach the target, or use default.
    iface = _detect_interface(target)
    if not iface:
        return {"skipped": True, "reason": "Cannot determine network interface for target"}

    result = {
        "target": target,
        "interface": iface,
        "protocols_detected": [],
        "browsers_detected": [],
        "poisonable_requests": [],
        "total_requests": 0,
        "total_protocols": 0,
        "vulnerabilities": [],
        "analyze_mode": True,
        "duration_seconds": 30,
    }

    try:
        # Run Responder in analyze-only mode for 30 seconds
        cmd = ["python3", responder_bin, "-A", "-I", iface, "-v"]
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            cwd=os.path.dirname(responder_bin),
        )

        output_lines = []
        start = time.time()
        timeout = 35  # slightly more than duration

        try:
            while time.time() - start < timeout:
                remaining = timeout - (time.time() - start)
                if remaining <= 0:
                    break
                try:
                    proc.wait(timeout=min(remaining, 1))
                    # Process ended on its own
                    break
                except subprocess.TimeoutExpired:
                    continue
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

        stdout = proc.stdout.read() if proc.stdout else ""
        output_lines = stdout.splitlines()

        result["duration_seconds"] = round(time.time() - start, 1)

        # Parse Responder output
        _parse_responder_output(output_lines, result)

        # Detect vulnerabilities based on findings
        _detect_vulnerabilities(result)

    except FileNotFoundError:
        return {"skipped": True, "reason": "Responder binary not found"}
    except Exception as e:
        result["error"] = str(e)

    return result


def _detect_interface(target: str) -> str:
    """Detect the network interface that can reach the target."""
    try:
        # Use ip route to find the outgoing interface
        out = subprocess.check_output(
            ["ip", "route", "get", target],
            timeout=5, text=True, stderr=subprocess.DEVNULL,
        )
        # Output like: "192.168.1.1 dev eth0 src 192.168.1.100 uid 0"
        m = re.search(r"dev\s+(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass

    # Fallback: try to find default interface
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            timeout=5, text=True, stderr=subprocess.DEVNULL,
        )
        m = re.search(r"dev\s+(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass

    # Last fallback
    for iface in ["eth0", "ens33", "ens160", "wlan0"]:
        if os.path.exists(f"/sys/class/net/{iface}"):
            return iface

    return None


def _parse_responder_output(lines: list, result: dict):
    """Parse Responder analyze mode output."""
    protocols = set()
    browsers = []
    requests = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Detect protocol poisoning opportunities
        # Responder logs like: "[*] [LLMNR] Poisoned answer sent to ..."
        # In analyze mode: "[Analyze mode: LLMNR] Request by ..."
        proto_match = re.search(
            r"\[(LLMNR|NBT-NS|MDNS|WPAD|HTTP|SMB|LDAP|FTP|POP|IMAP|SMTP|DNS|MSSQL|Proxy Auth)\]",
            line, re.IGNORECASE,
        )
        if proto_match:
            proto = proto_match.group(1).upper()
            protocols.add(proto)

        # Detect analyze mode requests
        if "Analyze mode" in line or "analyze mode" in line:
            requests.append(line)

        # Detect poisoned answers (in analyze mode these are "would poison")
        if any(kw in line.lower() for kw in ["poisoned", "poison", "request by", "query"]):
            if line not in requests:
                requests.append(line)

        # Detect browser/workstation info
        # "[*] [NBT-NS] ... WORKSTATION<00>"
        browser_match = re.search(r"(\S+)<(\w+)>", line)
        if browser_match:
            name = browser_match.group(1)
            suffix = browser_match.group(2)
            entry = {"name": name, "suffix": suffix}
            if entry not in browsers:
                browsers.append(entry)

        # Detect NTLM hash capture opportunities
        if any(kw in line.lower() for kw in ["ntlm", "hash", "ntlmv1", "ntlmv2", "challenge"]):
            if "NTLM" not in protocols:
                protocols.add("NTLM")
            if line not in requests:
                requests.append(line)

        # Detect WPAD proxy
        if "wpad" in line.lower():
            if "WPAD" not in protocols:
                protocols.add("WPAD")

    result["protocols_detected"] = sorted(protocols)
    result["browsers_detected"] = browsers[:50]
    result["poisonable_requests"] = requests[:100]
    result["total_requests"] = len(requests)
    result["total_protocols"] = len(protocols)


def _detect_vulnerabilities(result: dict):
    """Detect vulnerabilities based on Responder findings."""
    vulns = []
    protocols = set(result.get("protocols_detected", []))

    if "LLMNR" in protocols:
        vulns.append({
            "title": "LLMNR Poisoning Possible",
            "severity": "high",
            "description": "Link-Local Multicast Name Resolution (LLMNR) is enabled on the network. "
                           "Attackers can respond to LLMNR queries to capture NTLM hashes.",
            "mitre": "T1557.001",
            "remediation": "Disable LLMNR via Group Policy: "
                           "Computer Configuration > Administrative Templates > Network > DNS Client > Turn Off Multicast Name Resolution = Enabled",
        })

    if "NBT-NS" in protocols:
        vulns.append({
            "title": "NBT-NS Poisoning Possible",
            "severity": "high",
            "description": "NetBIOS Name Service (NBT-NS) is enabled on the network. "
                           "Attackers can respond to NBT-NS broadcasts to capture NTLM hashes.",
            "mitre": "T1557.001",
            "remediation": "Disable NetBIOS over TCP/IP on all network adapters via DHCP options or manually in adapter settings.",
        })

    if "MDNS" in protocols:
        vulns.append({
            "title": "mDNS Poisoning Possible",
            "severity": "medium",
            "description": "Multicast DNS (mDNS) is active on the network. "
                           "Can be exploited for name resolution poisoning.",
            "mitre": "T1557.001",
            "remediation": "Disable mDNS if not required. On Windows, this is controlled via the DNS Client service.",
        })

    if "WPAD" in protocols:
        vulns.append({
            "title": "WPAD Proxy Auto-Discovery Vulnerable",
            "severity": "high",
            "description": "Web Proxy Auto-Discovery Protocol (WPAD) requests detected. "
                           "Attackers can serve malicious proxy configurations to intercept traffic.",
            "mitre": "T1557.001",
            "remediation": "Disable WPAD via Group Policy or add a DNS entry for 'wpad' pointing to a legitimate proxy server.",
        })

    if "NTLM" in protocols:
        vulns.append({
            "title": "NTLM Hash Capture Opportunity",
            "severity": "critical",
            "description": "NTLM authentication challenges detected on the network. "
                           "Credentials can be captured and cracked or relayed.",
            "mitre": "T1003.001",
            "remediation": "Enforce Kerberos authentication, disable NTLM where possible via Group Policy, "
                           "enable SMB signing to prevent relay attacks.",
        })

    if "SMB" in protocols:
        vulns.append({
            "title": "SMB Traffic Interceptable",
            "severity": "medium",
            "description": "SMB traffic detected that could be intercepted via name resolution poisoning.",
            "mitre": "T1557",
            "remediation": "Enable SMB signing on all systems. Use Kerberos authentication instead of NTLM.",
        })

    if "HTTP" in protocols:
        vulns.append({
            "title": "HTTP Authentication Interceptable",
            "severity": "medium",
            "description": "HTTP authentication requests detected that could be intercepted via name resolution poisoning.",
            "mitre": "T1557",
            "remediation": "Use HTTPS for all web services. Implement certificate pinning where possible.",
        })

    # Count severities
    result["vulnerabilities"] = vulns
    result["total_vulnerabilities"] = len(vulns)
    result["critical_count"] = sum(1 for v in vulns if v["severity"] == "critical")
    result["high_count"] = sum(1 for v in vulns if v["severity"] == "high")
    result["medium_count"] = sum(1 for v in vulns if v["severity"] == "medium")
