"""CWE mapping module — maps scan results to Common Weakness Enumeration entries."""

import re

# Local CWE database — top 50 most relevant weaknesses
CWE_DB = {
    20: {"name": "Improper Input Validation", "category": "Input Validation", "likelihood": "High",
         "description": "The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program."},
    22: {"name": "Path Traversal", "category": "Input Validation", "likelihood": "High",
         "description": "The software uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize special elements."},
    77: {"name": "Command Injection", "category": "Injection", "likelihood": "High",
         "description": "The software constructs all or part of a command using externally-influenced input but does not neutralize special elements that could modify the intended command."},
    78: {"name": "OS Command Injection", "category": "Injection", "likelihood": "High",
         "description": "The software constructs all or part of an OS command using externally-influenced input without properly neutralizing special elements."},
    79: {"name": "Cross-site Scripting (XSS)", "category": "Injection", "likelihood": "High",
         "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page."},
    89: {"name": "SQL Injection", "category": "Injection", "likelihood": "High",
         "description": "The software constructs all or part of an SQL command using externally-influenced input without properly neutralizing special elements."},
    94: {"name": "Code Injection", "category": "Injection", "likelihood": "High",
         "description": "The software constructs all or part of a code segment using externally-influenced input without properly neutralizing special elements."},
    119: {"name": "Buffer Overflow", "category": "Memory Safety", "likelihood": "High",
          "description": "The software performs operations on a memory buffer without restricting the size of input, causing data to be written beyond the allocated boundary."},
    125: {"name": "Out-of-bounds Read", "category": "Memory Safety", "likelihood": "Medium",
          "description": "The software reads data past the end, or before the beginning, of the intended buffer."},
    190: {"name": "Integer Overflow", "category": "Memory Safety", "likelihood": "Medium",
          "description": "The software performs a calculation that can produce an integer overflow or wraparound, leading to unexpected behavior."},
    200: {"name": "Information Exposure", "category": "Information Disclosure", "likelihood": "Medium",
          "description": "The software exposes sensitive information to an actor that is not explicitly authorized to have access to that information."},
    209: {"name": "Error Message Information Leak", "category": "Information Disclosure", "likelihood": "Medium",
          "description": "The software generates an error message that includes sensitive information about its environment, users, or associated data."},
    250: {"name": "Execution with Unnecessary Privileges", "category": "Access Control", "likelihood": "Medium",
          "description": "The software performs an operation at a privilege level higher than the minimum level required."},
    269: {"name": "Improper Privilege Management", "category": "Access Control", "likelihood": "Medium",
          "description": "The software does not properly assign, modify, track, or check privileges for an actor."},
    276: {"name": "Incorrect Default Permissions", "category": "Access Control", "likelihood": "Medium",
          "description": "During installation, installed file permissions are set to allow anyone to modify those files."},
    284: {"name": "Improper Access Control", "category": "Access Control", "likelihood": "High",
          "description": "The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor."},
    287: {"name": "Improper Authentication", "category": "Authentication", "likelihood": "High",
          "description": "The system does not sufficiently verify that the claimed identity of an actor is correct."},
    295: {"name": "Improper Certificate Validation", "category": "Cryptography", "likelihood": "Medium",
          "description": "The software does not validate, or incorrectly validates, a certificate."},
    306: {"name": "Missing Authentication for Critical Function", "category": "Authentication", "likelihood": "High",
          "description": "The software does not perform any authentication for functionality that requires a provable user identity."},
    307: {"name": "Improper Restriction of Excessive Auth Attempts", "category": "Authentication", "likelihood": "Medium",
          "description": "The software does not implement sufficient measures to prevent multiple failed authentication attempts."},
    311: {"name": "Missing Encryption of Sensitive Data", "category": "Cryptography", "likelihood": "Medium",
          "description": "The software does not encrypt sensitive or critical information before storage or transmission."},
    319: {"name": "Cleartext Transmission of Sensitive Info", "category": "Cryptography", "likelihood": "Medium",
          "description": "The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors."},
    326: {"name": "Inadequate Encryption Strength", "category": "Cryptography", "likelihood": "Medium",
          "description": "The software stores or transmits sensitive data using an encryption scheme that is theoretically sound but is not strong enough for the level of protection required."},
    327: {"name": "Use of Broken Crypto Algorithm", "category": "Cryptography", "likelihood": "Medium",
          "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information."},
    330: {"name": "Use of Insufficiently Random Values", "category": "Cryptography", "likelihood": "Medium",
          "description": "The software uses insufficiently random numbers or values in a security context that depends on unpredictable numbers."},
    352: {"name": "Cross-Site Request Forgery (CSRF)", "category": "Session Management", "likelihood": "Medium",
          "description": "The web application does not sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user."},
    362: {"name": "Race Condition", "category": "Concurrency", "likelihood": "Low",
          "description": "The program contains a code sequence that can run concurrently with other code and requires temporary exclusive access to a shared resource."},
    400: {"name": "Uncontrolled Resource Consumption", "category": "Resource Management", "likelihood": "Medium",
          "description": "The software does not properly control the allocation and maintenance of a limited resource, allowing an actor to influence resource consumption."},
    416: {"name": "Use After Free", "category": "Memory Safety", "likelihood": "High",
          "description": "Referencing memory after it has been freed can cause a program to crash or execute arbitrary code."},
    434: {"name": "Unrestricted File Upload", "category": "Input Validation", "likelihood": "High",
          "description": "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed."},
    476: {"name": "NULL Pointer Dereference", "category": "Memory Safety", "likelihood": "Low",
          "description": "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL."},
    502: {"name": "Deserialization of Untrusted Data", "category": "Input Validation", "likelihood": "High",
          "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid."},
    521: {"name": "Weak Password Requirements", "category": "Authentication", "likelihood": "Medium",
          "description": "The product does not require that users should have strong passwords, making it easier for attackers to compromise user accounts."},
    522: {"name": "Insufficiently Protected Credentials", "category": "Authentication", "likelihood": "Medium",
          "description": "The product transmits or stores authentication credentials, but it uses an insecure method susceptible to unauthorized interception."},
    532: {"name": "Log File Information Leak", "category": "Information Disclosure", "likelihood": "Low",
          "description": "Information written to log files can be of a sensitive nature and give valuable guidance to an attacker."},
    601: {"name": "Open Redirect", "category": "Input Validation", "likelihood": "Medium",
          "description": "A web application accepts a user-controlled input that specifies a link to an external site and uses it in a redirect."},
    611: {"name": "XML External Entity (XXE)", "category": "Injection", "likelihood": "High",
          "description": "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control."},
    668: {"name": "Exposure of Resource to Wrong Sphere", "category": "Access Control", "likelihood": "Medium",
          "description": "The product exposes a resource to the wrong control sphere, providing unintended actors with inappropriate access."},
    732: {"name": "Incorrect Permission Assignment", "category": "Access Control", "likelihood": "Medium",
          "description": "The product specifies permissions for a security-critical resource in a way that allows unintended actors to access the resource."},
    754: {"name": "Improper Check for Unusual Conditions", "category": "Error Handling", "likelihood": "Low",
          "description": "The software does not check or improperly checks for unusual or exceptional conditions that are not expected to occur frequently."},
    776: {"name": "XML Entity Expansion (Billion Laughs)", "category": "Injection", "likelihood": "Medium",
          "description": "The software uses XML documents and allows their structure to be defined with a DTD, but does not properly control the number of recursive entity expansions."},
    787: {"name": "Out-of-bounds Write", "category": "Memory Safety", "likelihood": "High",
          "description": "The software writes data past the end, or before the beginning, of the intended buffer."},
    798: {"name": "Hardcoded Credentials", "category": "Authentication", "likelihood": "High",
          "description": "The software contains hard-coded credentials such as a password or cryptographic key, which it uses for its own authentication or for outbound communication."},
    862: {"name": "Missing Authorization", "category": "Access Control", "likelihood": "High",
          "description": "The software does not perform an authorization check when an actor attempts to access a resource or perform an action."},
    863: {"name": "Incorrect Authorization", "category": "Access Control", "likelihood": "High",
          "description": "The software performs an authorization check when an actor attempts to access a resource, but it does not correctly perform the check."},
    918: {"name": "Server-Side Request Forgery (SSRF)", "category": "Input Validation", "likelihood": "High",
          "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure the request is being sent to the expected destination."},
    916: {"name": "Use of Password Hash With Insufficient Effort", "category": "Cryptography", "likelihood": "Medium",
          "description": "The software generates a hash for a password, but it uses a scheme that does not provide a sufficient level of computational effort."},
    943: {"name": "Improper Neutralization of Special Elements in Data Query Logic", "category": "Injection", "likelihood": "High",
          "description": "The application generates a query intended to access or manipulate data in a data store, but it does not neutralize special elements properly."},
    1021: {"name": "Improper Restriction of Rendered UI Layers (Clickjacking)", "category": "UI Security", "likelihood": "Medium",
           "description": "The web application does not restrict or incorrectly restricts frame rendering, making it vulnerable to clickjacking attacks."},
}


def _extract_cwe_ids(scan_results: dict) -> set:
    """Extract CWE IDs from NVD results and nuclei findings."""
    cwe_ids = set()

    # From NVD CVE data
    nvd = scan_results.get("nvd", {})
    cves = nvd.get("cves", []) if isinstance(nvd, dict) else []
    for cve in cves:
        cwe_list = cve.get("cwe_ids", []) or []
        for cwe_str in cwe_list:
            match = re.search(r'CWE-(\d+)', str(cwe_str))
            if match:
                cwe_ids.add(int(match.group(1)))

    # From nuclei findings
    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        # Check classification.cwe-id or tags
        info = f.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        cwe_id = classification.get("cwe-id", "") or ""
        if cwe_id:
            for c in (cwe_id if isinstance(cwe_id, list) else [cwe_id]):
                match = re.search(r'(\d+)', str(c))
                if match:
                    cwe_ids.add(int(match.group(1)))
        # Also check tags for CWE references
        tags = info.get("tags", []) or f.get("tags", []) or []
        for tag in tags:
            match = re.match(r'cwe-?(\d+)', str(tag).lower())
            if match:
                cwe_ids.add(int(match.group(1)))

    return cwe_ids


def _infer_cwes_from_scan(scan_results: dict) -> set:
    """Infer CWE IDs from scan module results when not explicitly tagged."""
    inferred = set()

    # SQLMap → SQL Injection
    sqlmap = scan_results.get("sqlmap", {}) or {}
    if sqlmap.get("vulnerable"):
        inferred.add(89)

    # TestSSL issues → crypto weaknesses
    testssl = scan_results.get("testssl", {}) or {}
    issues = testssl.get("issues", []) or []
    for issue in issues:
        issue_lower = str(issue).lower()
        if "certificate" in issue_lower:
            inferred.add(295)
        if "cleartext" in issue_lower or "http" in issue_lower:
            inferred.add(319)
        if any(w in issue_lower for w in ["weak", "obsolete", "rc4", "des", "md5"]):
            inferred.add(327)
        if "random" in issue_lower:
            inferred.add(330)

    # Nuclei severity-based inference
    nuclei = scan_results.get("nuclei", {})
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    for f in findings:
        name_lower = (f.get("name", "") or f.get("template-id", "") or "").lower()
        tags = f.get("info", {}).get("tags", []) or f.get("tags", []) or []
        tags_str = " ".join(str(t).lower() for t in tags)
        combined = name_lower + " " + tags_str

        if "xss" in combined or "cross-site scripting" in combined:
            inferred.add(79)
        if "sqli" in combined or "sql-injection" in combined or "sql injection" in combined:
            inferred.add(89)
        if "lfi" in combined or "path-traversal" in combined or "directory-traversal" in combined:
            inferred.add(22)
        if "rce" in combined or "command-injection" in combined or "os-command" in combined:
            inferred.add(78)
        if "ssrf" in combined:
            inferred.add(918)
        if "xxe" in combined:
            inferred.add(611)
        if "csrf" in combined:
            inferred.add(352)
        if "upload" in combined:
            inferred.add(434)
        if "open-redirect" in combined:
            inferred.add(601)
        if "deserialization" in combined:
            inferred.add(502)
        if "hardcoded" in combined or "default-credential" in combined:
            inferred.add(798)
        if "clickjacking" in combined or "x-frame" in combined:
            inferred.add(1021)
        if "information-disclosure" in combined or "exposure" in combined:
            inferred.add(200)
        if "missing-auth" in combined or "unauth" in combined:
            inferred.add(306)

    # Gobuster findings → info exposure
    gobuster = scan_results.get("gobuster", {}) or {}
    gob_findings = gobuster.get("findings", []) or []
    sensitive_paths = [".env", ".git", "backup", "admin", "phpmyadmin", "config", ".htaccess", "wp-config"]
    for f in gob_findings:
        path_lower = (f.get("path", "") or "").lower()
        if any(s in path_lower for s in sensitive_paths):
            inferred.add(200)
            break

    # Nikto findings → misconfig, info exposure
    nikto = scan_results.get("nikto", {}) or {}
    nikto_findings = nikto.get("findings", []) if isinstance(nikto, dict) else []
    if nikto_findings:
        inferred.add(200)  # Information exposure from web scanner

    return inferred


def cwe_mapping(scan_results: dict) -> dict:
    """Map scan results to CWE entries.

    Args:
        scan_results: Combined scan results dict.

    Returns:
        Dict with CWE mapping results.
    """
    # Collect CWE IDs from explicit sources
    explicit_ids = _extract_cwe_ids(scan_results)

    # Infer CWE IDs from scan behavior
    inferred_ids = _infer_cwes_from_scan(scan_results)

    all_ids = explicit_ids | inferred_ids

    if not all_ids:
        return {"cwes": [], "total": 0}

    cwes = []
    for cwe_id in sorted(all_ids):
        entry = CWE_DB.get(cwe_id)
        if entry:
            cwes.append({
                "cwe_id": f"CWE-{cwe_id}",
                "name": entry["name"],
                "description": entry["description"],
                "category": entry["category"],
                "likelihood": entry["likelihood"],
                "url": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
            })
        else:
            cwes.append({
                "cwe_id": f"CWE-{cwe_id}",
                "name": f"CWE-{cwe_id}",
                "description": "",
                "category": "Other",
                "likelihood": "Medium",
                "url": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
            })

    # Sort by likelihood (High first)
    lik_order = {"High": 0, "Medium": 1, "Low": 2}
    cwes.sort(key=lambda c: lik_order.get(c["likelihood"], 3))

    return {
        "cwes": cwes,
        "total": len(cwes),
        "high_count": sum(1 for c in cwes if c["likelihood"] == "High"),
        "medium_count": sum(1 for c in cwes if c["likelihood"] == "Medium"),
        "low_count": sum(1 for c in cwes if c["likelihood"] == "Low"),
    }
