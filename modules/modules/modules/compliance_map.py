"""
CYRBER Compliance Mapping — NIS2 & ISO 27001.
Maps security findings to regulatory articles/controls.
"""

# ── NIS2 Directive Article 21(2) ──────────────────────────

NIS2_MAPPING = {
    "sql_injection":        {"article": "Art. 21(2)(e)", "requirement": "Bezpieczeństwo w pozyskiwaniu, rozwijaniu i utrzymywaniu sieci i systemów"},
    "xss":                  {"article": "Art. 21(2)(e)", "requirement": "Bezpieczeństwo w pozyskiwaniu, rozwijaniu i utrzymywaniu sieci i systemów"},
    "command_injection":    {"article": "Art. 21(2)(e)", "requirement": "Bezpieczeństwo w pozyskiwaniu, rozwijaniu i utrzymywaniu sieci i systemów"},
    "path_traversal":       {"article": "Art. 21(2)(e)", "requirement": "Bezpieczeństwo w pozyskiwaniu, rozwijaniu i utrzymywaniu sieci i systemów"},
    "ssrf":                 {"article": "Art. 21(2)(e)", "requirement": "Bezpieczeństwo w pozyskiwaniu, rozwijaniu i utrzymywaniu sieci i systemów"},
    "ssl_weak":             {"article": "Art. 21(2)(h)", "requirement": "Polityki stosowania kryptografii i szyfrowania"},
    "ssl_expired":          {"article": "Art. 21(2)(h)", "requirement": "Polityki stosowania kryptografii i szyfrowania"},
    "tls_misconfiguration": {"article": "Art. 21(2)(h)", "requirement": "Polityki stosowania kryptografii i szyfrowania"},
    "open_port":            {"article": "Art. 21(2)(a)", "requirement": "Polityki analizy ryzyka i bezpieczeństwa systemów informacyjnych"},
    "unnecessary_service":  {"article": "Art. 21(2)(a)", "requirement": "Polityki analizy ryzyka i bezpieczeństwa systemów informacyjnych"},
    "default_credentials":  {"article": "Art. 21(2)(i)", "requirement": "Bezpieczeństwo zasobów ludzkich, kontrola dostępu i zarządzanie aktywami"},
    "weak_password":        {"article": "Art. 21(2)(i)", "requirement": "Bezpieczeństwo zasobów ludzkich, kontrola dostępu i zarządzanie aktywami"},
    "authentication_bypass":{"article": "Art. 21(2)(i)", "requirement": "Bezpieczeństwo zasobów ludzkich, kontrola dostępu i zarządzanie aktywami"},
    "outdated_software":    {"article": "Art. 21(2)(e)", "requirement": "Zarządzanie podatnościami i ich ujawnianiem"},
    "cve":                  {"article": "Art. 21(2)(e)", "requirement": "Zarządzanie podatnościami i ich ujawnianiem"},
    "missing_headers":      {"article": "Art. 21(2)(e)", "requirement": "Bezpieczeństwo w pozyskiwaniu, rozwijaniu i utrzymywaniu sieci i systemów"},
    "phishing":             {"article": "Art. 21(2)(g)", "requirement": "Podstawowe praktyki cyberhigieny i szkolenia w zakresie cyberbezpieczeństwa"},
    "ad_misconfiguration":  {"article": "Art. 21(2)(i)", "requirement": "Bezpieczeństwo zasobów ludzkich, kontrola dostępu i zarządzanie aktywami"},
    "smb_exposure":         {"article": "Art. 21(2)(a)", "requirement": "Polityki analizy ryzyka i bezpieczeństwa systemów informacyjnych"},
    "information_disclosure":{"article": "Art. 21(2)(e)", "requirement": "Bezpieczeństwo w pozyskiwaniu, rozwijaniu i utrzymywaniu sieci i systemów"},
    "backup_exposure":      {"article": "Art. 21(2)(c)", "requirement": "Ciągłość działania i zarządzanie kryzysowe"},
    "dns_misconfiguration": {"article": "Art. 21(2)(a)", "requirement": "Polityki analizy ryzyka i bezpieczeństwa systemów informacyjnych"},
}

# ── ISO 27001:2022 Annex A Controls ──────────────────────

ISO27001_MAPPING = {
    "sql_injection":        {"control": "A.8.28", "name": "Bezpieczne kodowanie"},
    "xss":                  {"control": "A.8.28", "name": "Bezpieczne kodowanie"},
    "command_injection":    {"control": "A.8.28", "name": "Bezpieczne kodowanie"},
    "path_traversal":       {"control": "A.8.28", "name": "Bezpieczne kodowanie"},
    "ssrf":                 {"control": "A.8.28", "name": "Bezpieczne kodowanie"},
    "ssl_weak":             {"control": "A.8.24", "name": "Stosowanie kryptografii"},
    "ssl_expired":          {"control": "A.8.24", "name": "Stosowanie kryptografii"},
    "tls_misconfiguration": {"control": "A.8.24", "name": "Stosowanie kryptografii"},
    "open_port":            {"control": "A.8.20", "name": "Bezpieczeństwo sieci"},
    "unnecessary_service":  {"control": "A.8.20", "name": "Bezpieczeństwo sieci"},
    "default_credentials":  {"control": "A.8.5",  "name": "Bezpieczne uwierzytelnianie"},
    "weak_password":        {"control": "A.8.5",  "name": "Bezpieczne uwierzytelnianie"},
    "authentication_bypass":{"control": "A.8.5",  "name": "Bezpieczne uwierzytelnianie"},
    "outdated_software":    {"control": "A.8.8",  "name": "Zarządzanie podatnościami technicznymi"},
    "cve":                  {"control": "A.8.8",  "name": "Zarządzanie podatnościami technicznymi"},
    "missing_headers":      {"control": "A.8.28", "name": "Bezpieczne kodowanie"},
    "phishing":             {"control": "A.6.3",  "name": "Świadomość bezpieczeństwa informacji, edukacja i szkolenia"},
    "ad_misconfiguration":  {"control": "A.8.2",  "name": "Zarządzanie uprzywilejowanymi prawami dostępu"},
    "smb_exposure":         {"control": "A.8.20", "name": "Bezpieczeństwo sieci"},
    "information_disclosure":{"control": "A.8.12","name": "Zapobieganie wyciekowi danych"},
    "backup_exposure":      {"control": "A.8.13", "name": "Kopie zapasowe informacji"},
    "dns_misconfiguration": {"control": "A.8.20", "name": "Bezpieczeństwo sieci"},
}

# ── Keyword → category mapping (fuzzy) ───────────────────

_KEYWORD_MAP = [
    (["sql injection", "sqli", "sqlmap", "sql inj"],           "sql_injection"),
    (["xss", "cross-site scripting", "script injection"],       "xss"),
    (["command injection", "os command", "rce", "remote code"], "command_injection"),
    (["path traversal", "directory traversal", "lfi", "rfi"],   "path_traversal"),
    (["ssrf", "server-side request"],                           "ssrf"),
    (["ssl", "tls", "certificate", "cipher", "poodle", "beast", "heartbleed"], "ssl_weak"),
    (["expired cert", "certificate expir"],                     "ssl_expired"),
    (["open port", "unnecessary port", "exposed port"],         "open_port"),
    (["default cred", "default password", "default login"],     "default_credentials"),
    (["weak password", "brute force", "password policy"],       "weak_password"),
    (["authentication bypass", "auth bypass", "broken auth"],   "authentication_bypass"),
    (["outdated", "obsolete", "end of life", "eol", "upgrade"], "outdated_software"),
    (["cve-"],                                                  "cve"),
    (["missing header", "x-frame", "x-content-type", "hsts", "csp", "content-security"], "missing_headers"),
    (["phishing", "social engineering", "spear"],               "phishing"),
    (["active directory", "ad cs", "kerberos", "ldap", "bloodhound", "certipy"], "ad_misconfiguration"),
    (["smb", "samba", "netexec", "enum4linux"],                 "smb_exposure"),
    (["information disclosure", "info leak", "version disclosure", "server header"], "information_disclosure"),
    (["backup", ".bak", ".old", ".sql dump"],                   "backup_exposure"),
    (["dns", "zone transfer", "axfr", "spf", "dkim", "dmarc"], "dns_misconfiguration"),
]


def _classify_finding(name: str) -> str | None:
    """Match finding name to a compliance category via keyword search."""
    lower = name.lower()
    for keywords, category in _KEYWORD_MAP:
        for kw in keywords:
            if kw in lower:
                return category
    return None


def map_finding_to_compliance(finding_name: str) -> dict:
    """Map a single finding name to NIS2 and ISO 27001 references."""
    cat = _classify_finding(finding_name)
    if not cat:
        return {"nis2": None, "iso27001": None, "category": None}
    return {
        "nis2": NIS2_MAPPING.get(cat),
        "iso27001": ISO27001_MAPPING.get(cat),
        "category": cat,
    }


# ── Full NIS2 article list for gap analysis ──────────────

NIS2_ARTICLES = [
    ("Art. 21(2)(a)", "Polityki analizy ryzyka i bezpieczeństwa systemów informacyjnych"),
    ("Art. 21(2)(b)", "Obsługa incydentów"),
    ("Art. 21(2)(c)", "Ciągłość działania, zarządzanie kopiami zapasowymi i odtwarzanie po awarii, zarządzanie kryzysowe"),
    ("Art. 21(2)(d)", "Bezpieczeństwo łańcucha dostaw"),
    ("Art. 21(2)(e)", "Bezpieczeństwo w pozyskiwaniu, rozwijaniu i utrzymywaniu sieci i systemów, w tym obsługa i ujawnianie podatności"),
    ("Art. 21(2)(f)", "Polityki i procedury oceny skuteczności środków zarządzania ryzykiem w cyberbezpieczeństwie"),
    ("Art. 21(2)(g)", "Podstawowe praktyki cyberhigieny i szkolenia w zakresie cyberbezpieczeństwa"),
    ("Art. 21(2)(h)", "Polityki i procedury stosowania kryptografii i szyfrowania"),
    ("Art. 21(2)(i)", "Bezpieczeństwo zasobów ludzkich, kontrola dostępu i zarządzanie aktywami"),
    ("Art. 21(2)(j)", "Stosowanie uwierzytelniania wieloskładnikowego lub ciągłego"),
]

ISO27001_CONTROLS_TESTED = [
    ("A.5.1",  "Polityki bezpieczeństwa informacji"),
    ("A.6.3",  "Świadomość bezpieczeństwa informacji"),
    ("A.8.2",  "Zarządzanie uprzywilejowanymi prawami dostępu"),
    ("A.8.5",  "Bezpieczne uwierzytelnianie"),
    ("A.8.8",  "Zarządzanie podatnościami technicznymi"),
    ("A.8.12", "Zapobieganie wyciekowi danych"),
    ("A.8.13", "Kopie zapasowe informacji"),
    ("A.8.20", "Bezpieczeństwo sieci"),
    ("A.8.24", "Stosowanie kryptografii"),
    ("A.8.28", "Bezpieczne kodowanie"),
]


def generate_compliance_summary(findings: list, remediation_tasks: list) -> dict:
    """
    Analyze findings against NIS2 and ISO 27001, factoring in remediation status.

    Returns: {
        nis2_articles: [{article, requirement, status, findings_count, fixed_count}],
        iso27001_controls: [{control, name, status, findings_count, fixed_count}],
        overall_status: "ZGODNY" | "CZĘŚCIOWO ZGODNY" | "NIEZGODNY",
        compliance_score: 0-100,
        gaps: [str],
        stats: {total, fixed, verified, open, wontfix}
    }
    """
    # Build remediation lookup: finding_name → status
    rem_status = {}
    for t in remediation_tasks:
        key = (t.get("finding_name", "") or "").lower()
        if key:
            rem_status[key] = t.get("status", "open")

    # Map findings to compliance categories
    nis2_hits = {}   # article → {findings: [], fixed: 0}
    iso_hits = {}    # control → {findings: [], fixed: 0}

    for f in findings:
        name = f if isinstance(f, str) else (f.get("name") or f.get("finding_name") or "")
        severity = "" if isinstance(f, str) else (f.get("severity") or "")
        mapping = map_finding_to_compliance(name)

        f_status = rem_status.get(name.lower(), "open")
        is_fixed = f_status in ("fixed", "verified", "wontfix")

        if mapping["nis2"]:
            art = mapping["nis2"]["article"]
            if art not in nis2_hits:
                nis2_hits[art] = {"findings": [], "fixed": 0}
            nis2_hits[art]["findings"].append(name)
            if is_fixed:
                nis2_hits[art]["fixed"] += 1

        if mapping["iso27001"]:
            ctrl = mapping["iso27001"]["control"]
            if ctrl not in iso_hits:
                iso_hits[ctrl] = {"findings": [], "fixed": 0}
            iso_hits[ctrl]["findings"].append(name)
            if is_fixed:
                iso_hits[ctrl]["fixed"] += 1

    # Build NIS2 article table
    nis2_result = []
    for art, req in NIS2_ARTICLES:
        hit = nis2_hits.get(art)
        if not hit:
            nis2_result.append({
                "article": art, "requirement": req,
                "status": "OK", "findings_count": 0, "fixed_count": 0,
            })
        else:
            total = len(hit["findings"])
            fixed = hit["fixed"]
            status = "OK" if fixed >= total else ("PARTIAL" if fixed > 0 else "FAIL")
            nis2_result.append({
                "article": art, "requirement": req,
                "status": status, "findings_count": total, "fixed_count": fixed,
            })

    # Build ISO 27001 control table
    iso_result = []
    for ctrl, name in ISO27001_CONTROLS_TESTED:
        hit = iso_hits.get(ctrl)
        if not hit:
            iso_result.append({
                "control": ctrl, "name": name,
                "status": "OK", "findings_count": 0, "fixed_count": 0,
            })
        else:
            total = len(hit["findings"])
            fixed = hit["fixed"]
            status = "OK" if fixed >= total else ("PARTIAL" if fixed > 0 else "FAIL")
            iso_result.append({
                "control": ctrl, "name": name,
                "status": status, "findings_count": total, "fixed_count": fixed,
            })

    # Stats
    total_rem = len(remediation_tasks)
    fixed = sum(1 for t in remediation_tasks if t.get("status") in ("fixed", "verified"))
    verified = sum(1 for t in remediation_tasks if t.get("status") == "verified")
    wontfix = sum(1 for t in remediation_tasks if t.get("status") == "wontfix")
    open_count = total_rem - fixed - wontfix

    # Gaps
    gaps = []
    for r in nis2_result:
        if r["status"] == "FAIL":
            gaps.append(f'{r["article"]}: {r["requirement"]} — {r["findings_count"]} nienaprawionych podatności')

    # Overall status
    fail_count = sum(1 for r in nis2_result if r["status"] == "FAIL")
    partial_count = sum(1 for r in nis2_result if r["status"] == "PARTIAL")
    if fail_count == 0 and partial_count == 0:
        overall = "ZGODNY"
    elif fail_count == 0:
        overall = "CZĘŚCIOWO ZGODNY"
    else:
        overall = "NIEZGODNY"

    # Score: 100 = all OK, subtract per FAIL/PARTIAL
    total_articles = len(NIS2_ARTICLES)
    ok_count = sum(1 for r in nis2_result if r["status"] == "OK")
    score = round((ok_count + partial_count * 0.5) / total_articles * 100)

    return {
        "nis2_articles": nis2_result,
        "iso27001_controls": iso_result,
        "overall_status": overall,
        "compliance_score": score,
        "gaps": gaps,
        "stats": {
            "total": total_rem,
            "fixed": fixed,
            "verified": verified,
            "open": open_count,
            "wontfix": wontfix,
        },
    }
