"""
Certipy AD CS enumeration module for CYRBER.

Wraps `certipy find` to discover vulnerable certificate templates
and AD CS misconfigurations (ESC1–ESC13 attack paths).
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile

log = logging.getLogger("certipy_scan")

# ESC attack path descriptions
_ESC_DESCRIPTIONS = {
    "ESC1": "Template allows SAN (Subject Alternative Name) — attacker can request cert as any user",
    "ESC2": "Template allows any purpose EKU — can be used for client auth as any user",
    "ESC3": "Enrollment agent template — attacker can enroll on behalf of other users",
    "ESC4": "Template has vulnerable ACLs — attacker can modify template to enable ESC1",
    "ESC5": "CA has vulnerable ACLs — attacker can reconfigure the CA",
    "ESC6": "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 — any template can specify SAN",
    "ESC7": "CA has ManageCA/ManageCertificates rights for low-priv users",
    "ESC8": "HTTP enrollment endpoint (Web Enrollment) — NTLM relay to AD CS",
    "ESC9": "No security extension in template — bypasses mapping restrictions",
    "ESC10": "Weak certificate mapping — allows impersonation via crafted certs",
    "ESC11": "NTLM relay to AD CS via ICertPassage (RPC)",
    "ESC13": "Issuance policy linked to group — cert grants group membership",
}


def run_certipy(target: str, username: str = None, password: str = None,
                domain: str = None, dc_ip: str = None) -> dict:
    """Run certipy find to enumerate AD CS vulnerabilities."""
    if not shutil.which("certipy"):
        return {"skipped": True, "reason": "certipy not installed"}

    # Credentials from params or env
    username = username or os.getenv("CERTIPY_USER", "")
    password = password or os.getenv("CERTIPY_PASS", "")
    domain = domain or os.getenv("CERTIPY_DOMAIN", "")
    dc_ip = dc_ip or os.getenv("CERTIPY_DC_IP", "")

    if not all([username, password, domain, dc_ip]):
        return {"skipped": True, "reason": "requires AD credentials (CERTIPY_USER, CERTIPY_PASS, CERTIPY_DOMAIN, CERTIPY_DC_IP)"}

    with tempfile.TemporaryDirectory(prefix="certipy_") as tmpdir:
        output_prefix = os.path.join(tmpdir, "certipy")
        cmd = [
            "certipy", "find",
            "-json", "-vulnerable", "-enabled",
            "-u", f"{username}@{domain}",
            "-p", password,
            "-dc-ip", dc_ip,
            "-output", output_prefix,
            "-timeout", "30",
        ]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            return {"error": "certipy find timed out (120s)", "findings": []}

        # certipy writes to {prefix}_Certipy.json
        json_path = None
        for f in os.listdir(tmpdir):
            if f.endswith(".json"):
                json_path = os.path.join(tmpdir, f)
                break

        if not json_path or not os.path.exists(json_path):
            stderr = proc.stderr.strip()
            if "Authentication" in stderr or "KDC" in stderr:
                return {"error": f"Authentication failed: {stderr[:200]}", "findings": []}
            return {"error": f"No output file: {stderr[:200]}", "findings": []}

        try:
            with open(json_path) as fh:
                raw = json.load(fh)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON output: {e}", "findings": []}

    return _parse_certipy_output(raw, dc_ip)


def _parse_certipy_output(raw: dict, dc_ip: str) -> dict:
    """Normalize certipy JSON output into CYRBER findings format."""
    cas = []
    templates = []
    findings = []

    # Certificate Authorities
    for ca_name, ca_data in (raw.get("Certificate Authorities") or {}).items():
        ca_info = {
            "name": ca_name,
            "dns_name": ca_data.get("DNS Name", ""),
            "cert_subject": ca_data.get("Certificate Subject", ""),
            "web_enrollment": ca_data.get("Web Enrollment", "Disabled"),
            "user_san": ca_data.get("User Specified SAN", "Disabled"),
        }
        cas.append(ca_info)

        # ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2
        if ca_data.get("User Specified SAN", "").lower() == "enabled":
            findings.append(_make_finding(
                "ESC6", ca_name,
                f"CA '{ca_name}' has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled — "
                f"any template can specify a Subject Alternative Name",
                "critical",
            ))

        # ESC8 — Web Enrollment
        if ca_data.get("Web Enrollment", "").lower() == "enabled":
            findings.append(_make_finding(
                "ESC8", ca_name,
                f"CA '{ca_name}' has Web Enrollment enabled — vulnerable to NTLM relay",
                "high",
            ))

        # ESC7 — ManageCA/ManageCertificates for low-priv
        for perm_key in ("ManageCA", "ManageCertificates"):
            for principal in (ca_data.get(perm_key) or []):
                if _is_low_priv(principal):
                    findings.append(_make_finding(
                        "ESC7", ca_name,
                        f"CA '{ca_name}' grants {perm_key} to low-privilege principal '{principal}'",
                        "critical",
                    ))

    # Certificate Templates
    for tpl_name, tpl_data in (raw.get("Certificate Templates") or {}).items():
        tpl_info = {
            "name": tpl_name,
            "enabled": tpl_data.get("Enabled", False),
            "client_auth": tpl_data.get("Client Authentication", False),
            "enrollee_supplies_subject": tpl_data.get("Enrollee Supplies Subject", False),
            "requires_approval": tpl_data.get("Requires Manager Approval", False),
            "authorized_signatures": tpl_data.get("Authorized Signatures Required", 0),
            "enrollment_rights": tpl_data.get("Enrollment Rights", []),
            "vulnerabilities": [],
        }

        esc_vulns = _detect_esc_vulns(tpl_name, tpl_data)
        tpl_info["vulnerabilities"] = [e["esc"] for e in esc_vulns]
        findings.extend(esc_vulns)
        templates.append(tpl_info)

    vuln_templates = [t for t in templates if t["vulnerabilities"]]

    # Risk level
    crit_count = sum(1 for f in findings if f["severity"] == "critical")
    high_count = sum(1 for f in findings if f["severity"] == "high")
    if crit_count > 0:
        risk_level = "critical"
    elif high_count > 0:
        risk_level = "high"
    elif findings:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "target": dc_ip,
        "certificate_authorities": cas,
        "vulnerable_templates": vuln_templates,
        "all_templates_count": len(templates),
        "findings": findings,
        "findings_count": len(findings),
        "risk_level": risk_level,
    }


def _detect_esc_vulns(tpl_name: str, tpl: dict) -> list[dict]:
    """Detect ESC1–ESC13 vulnerabilities in a template."""
    vulns = []
    enrollee_supplies = tpl.get("Enrollee Supplies Subject", False)
    client_auth = tpl.get("Client Authentication", False)
    any_purpose = tpl.get("Any Purpose", False)
    requires_approval = tpl.get("Requires Manager Approval", False)
    auth_signatures = tpl.get("Authorized Signatures Required", 0)
    enrollment_rights = tpl.get("Enrollment Rights", [])
    has_low_priv_enroll = any(_is_low_priv(p) for p in enrollment_rights)

    # ESC1 — enrollee supplies SAN + client auth + low-priv can enroll
    if enrollee_supplies and client_auth and has_low_priv_enroll and not requires_approval:
        vulns.append(_make_finding(
            "ESC1", tpl_name,
            f"Template '{tpl_name}' allows enrollee to specify SAN with client auth — "
            f"attacker can request cert as any domain user",
            "critical",
        ))

    # ESC2 — any purpose EKU + low-priv
    if any_purpose and has_low_priv_enroll:
        vulns.append(_make_finding(
            "ESC2", tpl_name,
            f"Template '{tpl_name}' has Any Purpose EKU — can be used for client auth as any user",
            "critical",
        ))

    # ESC3 — Certificate Request Agent + low-priv
    if tpl.get("Certificate Request Agent", False) and has_low_priv_enroll:
        vulns.append(_make_finding(
            "ESC3", tpl_name,
            f"Template '{tpl_name}' is an enrollment agent — can enroll on behalf of others",
            "high",
        ))

    # ESC4 — vulnerable write ACLs on template
    for acl_key in ("Write Owner", "Write Dacl", "Write Property"):
        for principal in (tpl.get(acl_key) or []):
            if _is_low_priv(principal):
                vulns.append(_make_finding(
                    "ESC4", tpl_name,
                    f"Template '{tpl_name}' grants {acl_key} to '{principal}' — "
                    f"attacker can modify template to enable ESC1",
                    "critical",
                ))
                break  # one finding per ACL type

    # ESC9 — no security extension
    if tpl.get("No Security Extension", False) and has_low_priv_enroll:
        vulns.append(_make_finding(
            "ESC9", tpl_name,
            f"Template '{tpl_name}' has no security extension — bypasses mapping restrictions",
            "high",
        ))

    # ESC13 — issuance policy linked to group
    if tpl.get("Issuance Policies") and has_low_priv_enroll:
        vulns.append(_make_finding(
            "ESC13", tpl_name,
            f"Template '{tpl_name}' has issuance policy linked to group — "
            f"cert grants group membership",
            "high",
        ))

    return vulns


def _make_finding(esc: str, target_name: str, description: str, severity: str) -> dict:
    """Create a normalized finding dict."""
    return {
        "esc": esc,
        "name": f"{esc}: {target_name}",
        "title": f"AD CS {esc} — {target_name}",
        "severity": severity,
        "description": description,
        "detail": _ESC_DESCRIPTIONS.get(esc, ""),
        "mitre": "T1649",  # Steal or Forge Authentication Certificates
        "source": "certipy",
        "remediation": _esc_remediation(esc),
    }


def _esc_remediation(esc: str) -> str:
    """Return remediation advice per ESC type."""
    remediations = {
        "ESC1": "Disable 'Supply in the request' on the template or restrict enrollment to admins only.",
        "ESC2": "Remove 'Any Purpose' EKU or restrict enrollment rights.",
        "ESC3": "Restrict enrollment agent templates to privileged accounts and require approval.",
        "ESC4": "Remove write permissions (WriteDacl/WriteOwner/WriteProperty) from low-privilege principals.",
        "ESC5": "Review and restrict CA ACLs; remove ManageCA from non-admin principals.",
        "ESC6": "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA: certutil -config 'CA' -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
        "ESC7": "Remove ManageCA/ManageCertificates permissions from low-privilege accounts.",
        "ESC8": "Disable HTTP enrollment or enforce EPA (Extended Protection for Authentication) on IIS.",
        "ESC9": "Enable the security extension (szOID_NTDS_CA_SECURITY_EXT) on the template.",
        "ESC10": "Enable strong certificate mapping (KB5014754) and set StrongCertificateBindingEnforcement=2.",
        "ESC11": "Enforce encryption on RPC (ICertPassage) and disable NTLM on the CA server.",
        "ESC13": "Remove issuance policy from template or restrict enrollment to trusted principals.",
    }
    return remediations.get(esc, "Review and restrict AD CS configuration.")


def _is_low_priv(principal: str) -> bool:
    """Check if a principal name indicates a low-privilege/broad group."""
    low_priv_markers = (
        "authenticated users", "domain users", "domain computers",
        "everyone", "users", "builtin\\users",
    )
    p = principal.lower().strip()
    return any(marker in p for marker in low_priv_markers)
