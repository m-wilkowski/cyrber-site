"""OWASP Top 10 2021 mapping module — maps scan results to OWASP categories."""


# OWASP Top 10 2021 definitions
OWASP_TOP10 = {
    "A01": {
        "name": "Broken Access Control",
        "description": "Failures related to enforcement of policies such that users cannot act outside of their intended permissions. Violations include unauthorized access, privilege escalation, CORS misconfiguration, and directory traversal.",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    "A02": {
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often lead to sensitive data exposure. This includes use of weak algorithms, improper certificate validation, cleartext transmission, and missing encryption.",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    "A03": {
        "name": "Injection",
        "description": "SQL injection, XSS, OS command injection, LDAP injection, and other injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    "A04": {
        "name": "Insecure Design",
        "description": "Risks related to design and architectural flaws. Insecure design cannot be fixed by a perfect implementation — the security controls needed to defend against specific attacks were never created.",
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    "A05": {
        "name": "Security Misconfiguration",
        "description": "Missing security hardening, open cloud storage, unnecessary features, default accounts, verbose error messages, and improper security headers.",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "description": "Components with known vulnerabilities such as libraries, frameworks, and software modules that run with the same privileges as the application.",
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "description": "Confirmation of the user's identity, authentication, and session management. Weaknesses include weak passwords, credential stuffing, missing MFA, and session fixation.",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "description": "Failures related to code and infrastructure that does not protect against integrity violations. This includes insecure deserialization, use of untrusted plugins, and insecure CI/CD pipelines.",
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, monitoring, and alerting allow attackers to further attack systems, maintain persistence, pivot to more systems, and tamper with or extract data.",
        "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    "A10": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL, allowing an attacker to coerce the application to send requests to unexpected destinations.",
        "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    },
}


def _check_broken_access_control(scan_results: dict) -> list:
    """A01: Check for broken access control indicators."""
    triggers = []

    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        name_lower = (f.get("name", "") or f.get("template-id", "") or "").lower()
        tags = f.get("info", {}).get("tags", []) or f.get("tags", []) or []
        combined = name_lower + " " + " ".join(str(t).lower() for t in tags)
        if any(kw in combined for kw in ["directory-traversal", "path-traversal", "lfi", "idor",
                                          "access-control", "cors", "unauthorized", "privilege"]):
            triggers.append("nuclei: " + (f.get("name", "") or f.get("template-id", "")))

    gobuster = scan_results.get("gobuster", {}) or {}
    gob_findings = gobuster.get("findings", []) or []
    sensitive = [".git", ".env", "admin", "backup", ".htaccess", "wp-admin"]
    for g in gob_findings:
        path_lower = (g.get("path", "") or "").lower()
        if any(s in path_lower for s in sensitive):
            triggers.append(f"gobuster: {g.get('path', '')}")
            break

    enum4linux = scan_results.get("enum4linux", {}) or {}
    if enum4linux.get("shares") or enum4linux.get("users"):
        triggers.append("enum4linux: SMB shares/users exposed")

    return triggers


def _check_crypto_failures(scan_results: dict) -> list:
    """A02: Check for cryptographic failures."""
    triggers = []

    testssl = scan_results.get("testssl", {}) or {}
    issues = testssl.get("issues", []) or []
    for issue in issues:
        issue_lower = str(issue).lower()
        if any(kw in issue_lower for kw in ["weak", "ssl", "tls 1.0", "tls 1.1", "rc4", "des",
                                              "md5", "sha1", "export", "null", "cleartext",
                                              "certificate", "obsolete"]):
            triggers.append(f"testssl: {issue[:80]}")

    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        name_lower = (f.get("name", "") or "").lower()
        if any(kw in name_lower for kw in ["ssl", "tls", "cipher", "certificate", "https", "hsts"]):
            triggers.append("nuclei: " + (f.get("name", "") or f.get("template-id", "")))

    return triggers


def _check_injection(scan_results: dict) -> list:
    """A03: Check for injection flaws."""
    triggers = []

    sqlmap = scan_results.get("sqlmap", {}) or {}
    if sqlmap.get("vulnerable"):
        params = sqlmap.get("injectable_params", [])
        triggers.append(f"sqlmap: SQL injection ({', '.join(params) if params else 'confirmed'})")

    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        name_lower = (f.get("name", "") or f.get("template-id", "") or "").lower()
        tags = f.get("info", {}).get("tags", []) or f.get("tags", []) or []
        combined = name_lower + " " + " ".join(str(t).lower() for t in tags)
        if any(kw in combined for kw in ["sqli", "sql-injection", "xss", "command-injection",
                                          "rce", "ssti", "xxe", "ldap", "injection"]):
            triggers.append("nuclei: " + (f.get("name", "") or f.get("template-id", "")))

    nikto = scan_results.get("nikto", {}) or {}
    nikto_findings = nikto.get("findings", []) if isinstance(nikto, dict) else []
    for nf in nikto_findings:
        desc_lower = (nf.get("description", "") or "").lower()
        if any(kw in desc_lower for kw in ["injection", "xss", "script"]):
            triggers.append(f"nikto: {nf.get('description', '')[:80]}")

    return triggers


def _check_insecure_design(scan_results: dict) -> list:
    """A04: Check for insecure design indicators."""
    triggers = []

    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        name_lower = (f.get("name", "") or "").lower()
        if any(kw in name_lower for kw in ["default-page", "debug", "phpinfo", "server-status",
                                             "trace-method", "options-method"]):
            triggers.append("nuclei: " + (f.get("name", "") or f.get("template-id", "")))

    return triggers


def _check_security_misconfig(scan_results: dict) -> list:
    """A05: Check for security misconfiguration."""
    triggers = []

    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        name_lower = (f.get("name", "") or f.get("template-id", "") or "").lower()
        tags = f.get("info", {}).get("tags", []) or f.get("tags", []) or []
        combined = name_lower + " " + " ".join(str(t).lower() for t in tags)
        if any(kw in combined for kw in ["misconfig", "misconfiguration", "default-login",
                                          "directory-listing", "security-header", "missing-header",
                                          "x-frame-options", "content-security-policy",
                                          "exposed-panel", "admin-panel"]):
            triggers.append("nuclei: " + (f.get("name", "") or f.get("template-id", "")))

    nikto = scan_results.get("nikto", {}) or {}
    nikto_findings = nikto.get("findings", []) if isinstance(nikto, dict) else []
    for nf in nikto_findings:
        desc_lower = (nf.get("description", "") or "").lower()
        if any(kw in desc_lower for kw in ["directory", "listing", "header", "server"]):
            triggers.append(f"nikto: {nf.get('description', '')[:80]}")
            break

    gobuster = scan_results.get("gobuster", {}) or {}
    gob_findings = gobuster.get("findings", []) or []
    misconfig_paths = ["server-status", "server-info", ".svn", ".DS_Store", "web.config"]
    for g in gob_findings:
        path_lower = (g.get("path", "") or "").lower()
        if any(s in path_lower for s in misconfig_paths):
            triggers.append(f"gobuster: {g.get('path', '')}")

    return triggers


def _check_vulnerable_components(scan_results: dict) -> list:
    """A06: Check for vulnerable and outdated components."""
    triggers = []

    nvd = scan_results.get("nvd", {}) or {}
    cves = nvd.get("cves", []) or []
    if cves:
        high_crit = [c for c in cves if c.get("cvss_severity", "").upper() in ("CRITICAL", "HIGH")]
        if high_crit:
            triggers.append(f"nvd: {len(high_crit)} HIGH/CRITICAL CVEs")
        elif cves:
            triggers.append(f"nvd: {len(cves)} known CVEs")

    exploitdb = scan_results.get("exploitdb", {}) or {}
    exploits = exploitdb.get("exploits", []) or []
    if exploits:
        triggers.append(f"exploitdb: {len(exploits)} public exploits")

    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        tags = f.get("info", {}).get("tags", []) or f.get("tags", []) or []
        combined = " ".join(str(t).lower() for t in tags)
        if any(kw in combined for kw in ["cve", "outdated", "eol", "end-of-life"]):
            triggers.append("nuclei: " + (f.get("name", "") or f.get("template-id", "")))
            break

    return triggers


def _check_auth_failures(scan_results: dict) -> list:
    """A07: Check for authentication failures."""
    triggers = []

    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        name_lower = (f.get("name", "") or f.get("template-id", "") or "").lower()
        tags = f.get("info", {}).get("tags", []) or f.get("tags", []) or []
        combined = name_lower + " " + " ".join(str(t).lower() for t in tags)
        if any(kw in combined for kw in ["default-login", "default-credential", "weak-password",
                                          "brute-force", "hardcoded", "authentication-bypass"]):
            triggers.append("nuclei: " + (f.get("name", "") or f.get("template-id", "")))

    enum4linux = scan_results.get("enum4linux", {}) or {}
    if enum4linux.get("null_session"):
        triggers.append("enum4linux: NULL session allowed")

    return triggers


def _check_integrity_failures(scan_results: dict) -> list:
    """A08: Check for software and data integrity failures."""
    triggers = []

    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        name_lower = (f.get("name", "") or f.get("template-id", "") or "").lower()
        tags = f.get("info", {}).get("tags", []) or f.get("tags", []) or []
        combined = name_lower + " " + " ".join(str(t).lower() for t in tags)
        if any(kw in combined for kw in ["deserialization", "insecure-deserial", "code-injection",
                                          "subresource-integrity"]):
            triggers.append("nuclei: " + (f.get("name", "") or f.get("template-id", "")))

    return triggers


def _check_logging_failures(scan_results: dict) -> list:
    """A09: Check for logging and monitoring failures."""
    triggers = []

    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        name_lower = (f.get("name", "") or f.get("template-id", "") or "").lower()
        if any(kw in name_lower for kw in ["log4j", "log-file", "logging", "log-exposure"]):
            triggers.append("nuclei: " + (f.get("name", "") or f.get("template-id", "")))

    gobuster = scan_results.get("gobuster", {}) or {}
    gob_findings = gobuster.get("findings", []) or []
    for g in gob_findings:
        path_lower = (g.get("path", "") or "").lower()
        if any(kw in path_lower for kw in [".log", "logs/", "access.log", "error.log"]):
            triggers.append(f"gobuster: {g.get('path', '')}")
            break

    return triggers


def _check_ssrf(scan_results: dict) -> list:
    """A10: Check for SSRF."""
    triggers = []

    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        name_lower = (f.get("name", "") or f.get("template-id", "") or "").lower()
        tags = f.get("info", {}).get("tags", []) or f.get("tags", []) or []
        combined = name_lower + " " + " ".join(str(t).lower() for t in tags)
        if "ssrf" in combined:
            triggers.append("nuclei: " + (f.get("name", "") or f.get("template-id", "")))

    return triggers


# Check functions mapped to OWASP IDs
_CHECKERS = {
    "A01": _check_broken_access_control,
    "A02": _check_crypto_failures,
    "A03": _check_injection,
    "A04": _check_insecure_design,
    "A05": _check_security_misconfig,
    "A06": _check_vulnerable_components,
    "A07": _check_auth_failures,
    "A08": _check_integrity_failures,
    "A09": _check_logging_failures,
    "A10": _check_ssrf,
}

# Risk level based on severity of category
_RISK_LEVELS = {
    "A01": "Critical",
    "A02": "High",
    "A03": "Critical",
    "A04": "High",
    "A05": "High",
    "A06": "High",
    "A07": "Critical",
    "A08": "Medium",
    "A09": "Medium",
    "A10": "High",
}


def owasp_mapping(scan_results: dict) -> dict:
    """Map scan results to OWASP Top 10 2021 categories.

    Args:
        scan_results: Combined scan results dict.

    Returns:
        Dict with OWASP mapping results.
    """
    categories = []
    detected_count = 0

    for owasp_id in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]:
        checker = _CHECKERS[owasp_id]
        triggers = checker(scan_results)

        # Deduplicate triggers
        seen = set()
        unique_triggers = []
        for t in triggers:
            if t not in seen:
                seen.add(t)
                unique_triggers.append(t)

        info = OWASP_TOP10[owasp_id]
        detected = len(unique_triggers) > 0
        if detected:
            detected_count += 1

        categories.append({
            "id": owasp_id,
            "name": info["name"],
            "description": info["description"],
            "url": info["url"],
            "risk_level": _RISK_LEVELS[owasp_id] if detected else "None",
            "detected": detected,
            "triggered_by": unique_triggers[:10],
        })

    return {
        "categories": categories,
        "detected_count": detected_count,
        "total": 10,
    }
