import os
import json
import re
import requests

CACHE_PATH = os.getenv("MITRE_CACHE_PATH", "/app/data/mitre_attack.json")
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# ── Static mapping rules ──
# Each rule: (condition_fn, technique_id, technique_name, tactic, confidence, trigger_label)

PORT_MAP = {
    21:   ("T1071.002", "Application Layer Protocol: File Transfer Protocols", "command-and-control", "high"),
    22:   ("T1021.004", "Remote Services: SSH", "lateral-movement", "high"),
    23:   ("T1021",     "Remote Services: Telnet", "lateral-movement", "high"),
    25:   ("T1071.003", "Application Layer Protocol: Mail Protocols", "command-and-control", "medium"),
    53:   ("T1071.004", "Application Layer Protocol: DNS", "command-and-control", "medium"),
    80:   ("T1190",     "Exploit Public-Facing Application", "initial-access", "low"),
    110:  ("T1071.003", "Application Layer Protocol: Mail Protocols", "command-and-control", "medium"),
    135:  ("T1047",     "Windows Management Instrumentation", "execution", "medium"),
    139:  ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement", "high"),
    143:  ("T1071.003", "Application Layer Protocol: Mail Protocols", "command-and-control", "medium"),
    443:  ("T1190",     "Exploit Public-Facing Application", "initial-access", "low"),
    445:  ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement", "high"),
    1433: ("T1190",     "Exploit Public-Facing Application", "initial-access", "medium"),
    1521: ("T1190",     "Exploit Public-Facing Application", "initial-access", "medium"),
    3306: ("T1190",     "Exploit Public-Facing Application", "initial-access", "medium"),
    3389: ("T1021.001", "Remote Services: Remote Desktop Protocol", "lateral-movement", "high"),
    5432: ("T1190",     "Exploit Public-Facing Application", "initial-access", "medium"),
    5900: ("T1021.005", "Remote Services: VNC", "lateral-movement", "high"),
    5985: ("T1021.006", "Remote Services: Windows Remote Management", "lateral-movement", "high"),
    5986: ("T1021.006", "Remote Services: Windows Remote Management", "lateral-movement", "high"),
    6379: ("T1190",     "Exploit Public-Facing Application", "initial-access", "medium"),
    8080: ("T1190",     "Exploit Public-Facing Application", "initial-access", "low"),
    8443: ("T1190",     "Exploit Public-Facing Application", "initial-access", "low"),
    27017:("T1190",     "Exploit Public-Facing Application", "initial-access", "medium"),
}

TACTIC_DISPLAY = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
}

# Cache for MITRE descriptions loaded from JSON
_mitre_descriptions = {}


def _load_mitre_descriptions():
    """Load technique descriptions from cached MITRE ATT&CK JSON."""
    global _mitre_descriptions
    if _mitre_descriptions:
        return

    if not os.path.exists(CACHE_PATH):
        _download_mitre_data()

    if not os.path.exists(CACHE_PATH):
        return

    try:
        with open(CACHE_PATH, "r") as f:
            data = json.load(f)
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                ext_refs = obj.get("external_references", [])
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id", "")
                        _mitre_descriptions[tid] = {
                            "name": obj.get("name", ""),
                            "description": (obj.get("description", "") or "")[:300],
                            "url": ref.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"),
                        }
                        break
    except Exception as e:
        print(f"[mitre] Failed to load cache: {e}")


def _download_mitre_data():
    """Download MITRE ATT&CK enterprise data to cache."""
    cache_dir = os.path.dirname(CACHE_PATH)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
    try:
        print("[mitre] Downloading MITRE ATT&CK data...")
        r = requests.get(MITRE_URL, timeout=60)
        r.raise_for_status()
        with open(CACHE_PATH, "w") as f:
            f.write(r.text)
        print(f"[mitre] Cached to {CACHE_PATH}")
    except Exception as e:
        print(f"[mitre] Download failed: {e}")


def _technique_url(tid: str) -> str:
    """Build attack.mitre.org URL for technique ID."""
    if tid in _mitre_descriptions and _mitre_descriptions[tid].get("url"):
        return _mitre_descriptions[tid]["url"]
    return f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"


def _technique_desc(tid: str) -> str:
    """Get technique description from cache."""
    if tid in _mitre_descriptions:
        return _mitre_descriptions[tid].get("description", "")
    return ""


def _add(techniques: dict, tid: str, name: str, tactic: str, confidence: str, triggered_by: str):
    """Add technique, upgrading confidence if already present."""
    conf_order = {"high": 3, "medium": 2, "low": 1}
    if tid in techniques:
        existing = techniques[tid]
        if conf_order.get(confidence, 0) > conf_order.get(existing["confidence"], 0):
            existing["confidence"] = confidence
        if triggered_by not in existing["triggered_by"]:
            existing["triggered_by"] += ", " + triggered_by
        return
    techniques[tid] = {
        "technique_id": tid,
        "technique_name": name,
        "tactic": TACTIC_DISPLAY.get(tactic, tactic),
        "description": _technique_desc(tid),
        "url": _technique_url(tid),
        "confidence": confidence,
        "triggered_by": triggered_by,
    }


def mitre_map(scan_results: dict) -> dict:
    """Map scan results to MITRE ATT&CK techniques."""
    _load_mitre_descriptions()

    techniques = {}

    # ── 1. Open ports ──
    ports = scan_results.get("ports", [])
    for p in ports:
        port_num = p.get("port")
        if port_num and int(port_num) in PORT_MAP:
            tid, name, tactic, conf = PORT_MAP[int(port_num)]
            service = p.get("service", "")
            trigger = f"Port {port_num}" + (f"/{service}" if service else "")
            _add(techniques, tid, name, tactic, conf, trigger)

    # ── 2. SQL Injection ──
    sqlmap = scan_results.get("sqlmap", {})
    if sqlmap.get("vulnerable"):
        params = sqlmap.get("injectable_params", [])
        trigger = "SQLMap: " + (", ".join(params) if params else "SQL injection detected")
        _add(techniques, "T1190", "Exploit Public-Facing Application", "initial-access", "high", trigger)

    # ── 3. Nuclei vulnerabilities ──
    nuclei = scan_results.get("nuclei", {})
    nuclei_findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for finding in nuclei_findings:
        name_str = finding.get("name", "") or finding.get("template-id", "") or ""
        severity = (finding.get("severity", "") or "").lower()

        # CVE detection
        cve_match = re.search(r'CVE-\d{4}-\d+', name_str, re.IGNORECASE)
        if cve_match:
            conf = "high" if severity in ("critical", "high") else "medium"
            _add(techniques, "T1190", "Exploit Public-Facing Application", "initial-access", conf, f"Nuclei: {cve_match.group()}")

        # XSS
        if "xss" in name_str.lower():
            _add(techniques, "T1059.007", "Command and Scripting Interpreter: JavaScript", "execution", "medium", f"Nuclei: {name_str[:60]}")

        # Default credentials
        if "default" in name_str.lower() and ("login" in name_str.lower() or "cred" in name_str.lower() or "password" in name_str.lower()):
            _add(techniques, "T1078.001", "Valid Accounts: Default Accounts", "initial-access", "high", f"Nuclei: {name_str[:60]}")

        # Info disclosure
        if severity == "info" and ("disclosure" in name_str.lower() or "exposed" in name_str.lower()):
            _add(techniques, "T1592", "Gather Victim Host Information", "reconnaissance", "low", f"Nuclei: {name_str[:60]}")

    # ── 4. Gobuster directory listing ──
    gobuster = scan_results.get("gobuster", {})
    gob_findings = gobuster.get("findings", []) if isinstance(gobuster, dict) else []
    if gob_findings:
        sensitive_paths = [f for f in gob_findings if any(kw in (f.get("path", "") or "").lower() for kw in [
            "admin", "backup", ".git", ".env", "config", "wp-admin", "phpmyadmin", "debug", ".svn"
        ])]
        if sensitive_paths:
            paths_str = ", ".join([f.get("path", "") for f in sensitive_paths[:5]])
            _add(techniques, "T1083", "File and Directory Discovery", "discovery", "medium", f"Gobuster: {paths_str}")
        if len(gob_findings) > 10:
            _add(techniques, "T1083", "File and Directory Discovery", "discovery", "low", f"Gobuster: {len(gob_findings)} paths discovered")

    # ── 5. SSL/TLS issues ──
    testssl = scan_results.get("testssl", {})
    if isinstance(testssl, dict):
        grade = (testssl.get("grade", "") or "").upper()
        issues = testssl.get("issues", [])
        if grade in ("F", "C") or len(issues) > 3:
            _add(techniques, "T1557", "Adversary-in-the-Middle", "credential-access", "medium", f"TLS grade {grade}, {len(issues)} issues")
        if any("ssl" in str(i).lower() and ("2" in str(i) or "3" in str(i)) for i in issues):
            _add(techniques, "T1557", "Adversary-in-the-Middle", "credential-access", "high", "Deprecated SSL/TLS version")

    # ── 6. SMB shares (enum4linux) ──
    enum4linux = scan_results.get("enum4linux", {})
    if isinstance(enum4linux, dict) and not enum4linux.get("skipped"):
        shares = enum4linux.get("shares", [])
        if shares:
            share_names = ", ".join([s.get("name", "") for s in shares[:5]])
            _add(techniques, "T1039", "Data from Network Shared Drive", "collection", "high", f"SMB shares: {share_names}")
        users = enum4linux.get("users", [])
        if users:
            _add(techniques, "T1087.002", "Account Discovery: Domain Account", "discovery", "medium", f"enum4linux: {len(users)} users enumerated")
        policy = enum4linux.get("password_policy", {})
        if policy and policy.get("min_length"):
            try:
                min_len = int(policy["min_length"])
                if min_len < 8:
                    _add(techniques, "T1110", "Brute Force", "credential-access", "high", f"Weak password policy: min length {min_len}")
            except (ValueError, TypeError):
                pass

    # ── 7. Nikto findings ──
    nikto = scan_results.get("nikto", {})
    nikto_findings = nikto.get("findings", []) if isinstance(nikto, dict) else []
    for finding in nikto_findings:
        desc = (finding.get("description", "") or "").lower()
        if "server header" in desc or "version" in desc:
            _add(techniques, "T1592.004", "Gather Victim Host Information: Client Configurations", "reconnaissance", "low", "Nikto: server version disclosure")
            break
    if any("directory" in (f.get("description", "") or "").lower() and "index" in (f.get("description", "") or "").lower() for f in nikto_findings):
        _add(techniques, "T1083", "File and Directory Discovery", "discovery", "medium", "Nikto: directory indexing enabled")

    # ── 8. Masscan fast scan results (additional ports) ──
    masscan = scan_results.get("masscan", {})
    masscan_ports = masscan.get("ports", []) if isinstance(masscan, dict) else []
    for p in masscan_ports:
        port_num = p.get("port")
        if port_num and int(port_num) in PORT_MAP:
            tid, name, tactic, conf = PORT_MAP[int(port_num)]
            if tid not in techniques:
                _add(techniques, tid, name, tactic, "low", f"Masscan port {port_num}")

    # Sort: high → medium → low
    conf_order = {"high": 0, "medium": 1, "low": 2}
    sorted_techniques = sorted(
        techniques.values(),
        key=lambda t: (conf_order.get(t["confidence"], 3), t["technique_id"])
    )

    return {
        "techniques": sorted_techniques,
        "count": len(sorted_techniques),
        "high_count": sum(1 for t in sorted_techniques if t["confidence"] == "high"),
        "medium_count": sum(1 for t in sorted_techniques if t["confidence"] == "medium"),
        "low_count": sum(1 for t in sorted_techniques if t["confidence"] == "low"),
    }
