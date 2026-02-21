"""
Unified AI Analysis for CYRBER.

Single LLM call producing a cohesive security report:
  executive_summary, attack_narrative, exploit_chain,
  business_impact, remediation_priority, risk_score.

Primary: Claude (Anthropic API)
Fallback: Ollama (llama3.2)
Timeout: 120s
"""

import json
import logging
from modules.llm_provider import get_provider

log = logging.getLogger("ai_analysis")

# Severity weights for risk_score calculation
_SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 5, "low": 1, "info": 0}


def _collect_findings(scan_results: dict) -> list[dict]:
    """Extract all vulnerability findings across all modules into a flat list."""
    findings = []

    # Nuclei findings
    nuclei = scan_results.get("nuclei", {})
    for f in (nuclei.get("findings") or []):
        info = f.get("info", {})
        findings.append({
            "source": "nuclei",
            "name": info.get("name", ""),
            "severity": (info.get("severity") or "info").lower(),
            "description": info.get("description", ""),
            "cve": info.get("classification", {}).get("cve-id"),
            "cvss": info.get("classification", {}).get("cvss-score"),
        })

    # ZAP alerts
    zap = scan_results.get("zap", {})
    for a in (zap.get("summary", {}).get("alerts") or zap.get("alerts") or []):
        findings.append({
            "source": "zap",
            "name": a.get("name", a.get("alert", "")),
            "severity": (a.get("risk", "info")).lower(),
            "description": a.get("description", ""),
        })

    # Wapiti
    wapiti = scan_results.get("wapiti", {})
    for v in (wapiti.get("vulnerabilities") or []):
        findings.append({
            "source": "wapiti",
            "name": v.get("type", v.get("name", "")),
            "severity": (v.get("severity", "medium")).lower(),
            "description": v.get("description", v.get("url", "")),
        })

    # SQLMap
    sqlmap = scan_results.get("sqlmap", {})
    if sqlmap.get("vulnerable"):
        findings.append({
            "source": "sqlmap",
            "name": "SQL Injection",
            "severity": "critical",
            "description": f"Injectable params: {', '.join(sqlmap.get('injectable_params', []))}",
        })

    # Nikto
    nikto = scan_results.get("nikto", {})
    for f in (nikto.get("findings") or []):
        findings.append({
            "source": "nikto",
            "name": f.get("description", ""),
            "severity": "medium",
            "description": f.get("url", ""),
        })

    # TestSSL issues
    testssl = scan_results.get("testssl", {})
    for issue in (testssl.get("issues") or []):
        findings.append({
            "source": "testssl",
            "name": issue if isinstance(issue, str) else str(issue),
            "severity": "medium",
        })

    # SSLyze
    sslyze = scan_results.get("sslyze", {})
    if sslyze.get("total_accepted_ciphers", 0) > 0:
        for vuln in (sslyze.get("vulnerabilities") or []):
            findings.append({
                "source": "sslyze",
                "name": vuln if isinstance(vuln, str) else str(vuln),
                "severity": "medium",
            })

    # SearchSploit
    searchsploit = scan_results.get("searchsploit", {})
    for ex in (searchsploit.get("exploits") or []):
        findings.append({
            "source": "searchsploit",
            "name": ex.get("title", ""),
            "severity": "high",
            "description": ex.get("path", ""),
        })

    # Impacket
    impacket = scan_results.get("impacket", {})
    impacket_summary = impacket.get("summary", {})
    if impacket_summary.get("total_hashes", 0) > 0:
        findings.append({
            "source": "impacket",
            "name": "Credential dump",
            "severity": "critical",
            "description": f"{impacket_summary.get('total_hashes', 0)} hashes, "
                           f"{impacket_summary.get('secrets_found', 0)} secrets",
        })

    # ExploitDB
    exploitdb = scan_results.get("exploitdb", {})
    for ex in (exploitdb.get("exploits") or []):
        findings.append({
            "source": "exploitdb",
            "name": ex.get("title", ""),
            "severity": "high",
            "description": ex.get("description", ""),
        })

    # NVD CVEs
    nvd = scan_results.get("nvd", {})
    for cve in (nvd.get("cves") or []):
        sev = "medium"
        score = cve.get("cvss_score", 0)
        if score >= 9:
            sev = "critical"
        elif score >= 7:
            sev = "high"
        elif score < 4:
            sev = "low"
        findings.append({
            "source": "nvd",
            "name": cve.get("id", ""),
            "severity": sev,
            "description": cve.get("description", ""),
            "cvss": score,
        })

    # BloodHound / AD
    bloodhound = scan_results.get("bloodhound", {})
    if bloodhound and not bloodhound.get("skipped"):
        for path in (bloodhound.get("attack_paths") or []):
            findings.append({
                "source": "bloodhound",
                "name": f"AD Attack Path: {path.get('name', '')}",
                "severity": "critical",
                "description": path.get("description", ""),
            })

    # NetExec
    netexec = scan_results.get("netexec", {})
    if netexec and not netexec.get("skipped"):
        if netexec.get("null_session"):
            findings.append({
                "source": "netexec",
                "name": "SMB Null Session",
                "severity": "high",
                "description": "Null session allowed on SMB",
            })

    # SMBMap
    smbmap = scan_results.get("smbmap", {})
    if smbmap.get("total_shares", 0) > 0:
        findings.append({
            "source": "smbmap",
            "name": f"SMB Shares exposed ({smbmap.get('total_shares', 0)})",
            "severity": "high",
        })

    return findings


def _calculate_risk_score(findings: list[dict]) -> int:
    """Calculate risk score 0-100 based on severity-weighted findings."""
    raw = sum(_SEVERITY_WEIGHT.get(f.get("severity", "info"), 0) for f in findings)
    # Normalize: 0 findings=0, cap at 100
    score = min(100, raw)
    return score


def _build_prompt(scan_results: dict, findings: list[dict], risk_score: int) -> str:
    """Build the single comprehensive prompt for unified AI analysis."""
    target = scan_results.get("target", "unknown")
    profile = scan_results.get("profile", "STRAZNIK")
    ports = scan_results.get("ports", [])

    # Count modules that actually ran
    module_keys = [
        "nuclei", "whatweb", "gobuster", "testssl", "sqlmap", "nikto",
        "masscan", "zap", "wapiti", "wpscan", "joomscan", "cmsmap",
        "droopescan", "retirejs", "subfinder", "httpx", "naabu", "katana",
        "dnsx", "netdiscover", "arpscan", "fping", "traceroute", "nbtscan",
        "snmpwalk", "netexec", "enum4linux", "bloodhound", "responder",
        "fierce", "smbmap", "onesixtyone", "ikescan", "sslyze",
        "searchsploit", "impacket", "amass", "harvester",
    ]
    modules_ran = sum(
        1 for k in module_keys
        if scan_results.get(k) and not scan_results.get(k, {}).get("skipped")
    )

    # Summarize ports
    ports_summary = [
        {"port": p.get("port"), "service": p.get("service"), "version": p.get("version", "")}
        for p in ports[:20]
    ]

    # Summarize findings (limit to top 40 for prompt size)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 4))
    findings_for_prompt = sorted_findings[:40]

    sev_counts = {}
    for f in findings:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # MITRE data if available
    mitre = scan_results.get("mitre", {})
    mitre_techniques = [t.get("technique_id", "") for t in (mitre.get("techniques") or [])[:10]]

    # CWE data if available
    cwe = scan_results.get("cwe", {})
    cwe_ids = [c.get("id", "") for c in (cwe.get("cwes") or [])[:10]]

    # OWASP data if available
    owasp = scan_results.get("owasp", {})
    owasp_cats = [c.get("id", "") + " " + c.get("name", "") for c in (owasp.get("categories") or []) if c.get("detected")]

    return f"""Jestes ekspertem ds. cyberbezpieczenstwa i pentesterem z certyfikatami OSCP, OSCE, CRTO.
Przeanalizuj kompletne wyniki skanowania bezpieczenstwa i wygeneruj spojny raport narracyjny.

=== KONTEKST ===
Target: {target}
Profil skanowania: {profile}
Moduły uruchomione: {modules_ran}
Otwarte porty ({len(ports)}): {json.dumps(ports_summary, ensure_ascii=False)}
Severity distribution: {json.dumps(sev_counts, ensure_ascii=False)}
Risk score (calculated): {risk_score}/100
MITRE ATT&CK: {json.dumps(mitre_techniques, ensure_ascii=False)}
CWE: {json.dumps(cwe_ids, ensure_ascii=False)}
OWASP: {json.dumps(owasp_cats, ensure_ascii=False)}

=== FINDINGS ({len(findings)} total, showing top {len(findings_for_prompt)}) ===
{json.dumps(findings_for_prompt, indent=2, ensure_ascii=False)}

=== WYMAGANY FORMAT ODPOWIEDZI ===
Odpowiedz WYLACZNIE poprawnym JSON (bez markdown, bez komentarzy):
{{
  "executive_summary": "string ~200 slow, napisany dla CISO/CEO, bez technicznego zargonu. Ogolna ocena bezpieczenstwa, najwazniejsze 3 problemy w jezyku biznesowym.",

  "attack_narrative": "string ~300 slow. Scenariusz ataku krok po kroku jak prawdziwy hacker. 'Atakujacy najpierw uzyłby X aby dostac sie do Y, nastepnie...' Lacz podatnosci z roznych modulow w spojna historie.",

  "exploit_chain": [
    {{
      "step": 1,
      "technique": "nazwa techniki ataku",
      "tool": "narzedzie uzyte przez atakujacego",
      "cve": "CVE-XXXX-XXXX lub null",
      "mitre": "TXXXX",
      "impact": "opis skutku tego kroku",
      "likelihood": "Critical|High|Medium|Low"
    }}
  ],

  "business_impact": {{
    "financial_risk_eur": 50000,
    "data_at_risk": "opis jakie dane sa zagrozone",
    "compliance_violations": ["RODO", "NIS2", "ISO27001"],
    "downtime_hours": 24,
    "reputation_damage": "Critical|High|Medium|Low"
  }},

  "remediation_priority": [
    {{
      "priority": 1,
      "title": "co naprawic",
      "effort": "Low|Medium|High",
      "impact": "Critical|High|Medium|Low",
      "deadline": "Natychmiast|7 dni|30 dni|90 dni"
    }}
  ],

  "risk_level": "Critical|High|Medium|Low"
}}

WAZNE:
- executive_summary i attack_narrative pisz po polsku
- exploit_chain: max 8 krokow, od rekonesansu do pelnego przejecia
- remediation_priority: max 10 pozycji, posortowane od najwazniejszej
- business_impact.financial_risk_eur: realistyczna kwota strat w EUR
- compliance_violations: tylko te ktore faktycznie moga byc naruszone
- Odpowiedz TYLKO JSON, bez zadnych dodatkowych komentarzy"""


def _parse_response(text: str) -> dict | None:
    """Parse LLM response text into a dict, handling markdown fences."""
    clean = text.strip()
    if clean.startswith("```"):
        clean = clean.split("```")[1]
        if clean.startswith("json"):
            clean = clean[4:]
        clean = clean.strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        # Try extracting JSON from anywhere in the response
        start = text.find("{")
        end = text.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass
    return None


def _empty_result(risk_score: int, findings_count: int) -> dict:
    """Return a minimal result when LLM is unavailable."""
    risk_level = "Low"
    if risk_score >= 80:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Medium"
    return {
        "executive_summary": "Analiza AI niedostepna. Wynik oparty na automatycznej kalkulacji.",
        "attack_narrative": "",
        "exploit_chain": [],
        "business_impact": {
            "financial_risk_eur": 0,
            "data_at_risk": "Nieznane",
            "compliance_violations": [],
            "downtime_hours": 0,
            "reputation_damage": risk_level,
        },
        "remediation_priority": [],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings_count": findings_count,
        "provider": "none",
    }


def analyze_scan_results(scan_results: dict) -> dict:
    """Run unified AI analysis on complete scan results.

    Returns dict with: executive_summary, attack_narrative, exploit_chain,
    business_impact, remediation_priority, risk_score, risk_level.
    """
    findings = _collect_findings(scan_results)
    risk_score = _calculate_risk_score(findings)

    if not findings:
        return _empty_result(0, 0)

    prompt = _build_prompt(scan_results, findings, risk_score)

    # Try primary provider (Claude), then fallback to Ollama
    providers_to_try = ["claude", "ollama"]
    last_error = None

    for provider_name in providers_to_try:
        try:
            provider = get_provider(force=provider_name)
            if not provider.is_available():
                log.info("[ai_analysis] %s not available, skipping", provider_name)
                continue

            response_text = provider.chat(prompt, max_tokens=4096)
            parsed = _parse_response(response_text)

            if parsed is None:
                log.warning("[ai_analysis] %s returned unparseable response", provider_name)
                continue

            # Ensure all required keys exist with defaults
            result = {
                "executive_summary": parsed.get("executive_summary", ""),
                "attack_narrative": parsed.get("attack_narrative", ""),
                "exploit_chain": parsed.get("exploit_chain", []),
                "business_impact": parsed.get("business_impact", {}),
                "remediation_priority": parsed.get("remediation_priority", []),
                "risk_score": risk_score,
                "risk_level": parsed.get("risk_level", "Medium"),
                "findings_count": len(findings),
                "provider": provider_name,
            }

            # Ensure business_impact has all fields
            bi = result["business_impact"]
            bi.setdefault("financial_risk_eur", 0)
            bi.setdefault("data_at_risk", "")
            bi.setdefault("compliance_violations", [])
            bi.setdefault("downtime_hours", 0)
            bi.setdefault("reputation_damage", "Medium")

            log.info("[ai_analysis] Success via %s, risk_score=%d", provider_name, risk_score)
            return result

        except Exception as e:
            last_error = e
            log.warning("[ai_analysis] %s failed: %s", provider_name, e)
            continue

    log.error("[ai_analysis] All providers failed. Last error: %s", last_error)
    return _empty_result(risk_score, len(findings))
