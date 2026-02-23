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

# Maximum description length per finding (characters)
_MAX_DESCRIPTION_CHARS = 500


# ---------------------------------------------------------------------------
# Context window management
# ---------------------------------------------------------------------------

class ContextManager:
    """Manages LLM context budget to fit prompts within model limits."""

    # Token limits per model family (input budget, reserving space for output)
    _MODEL_LIMITS = {
        "claude-opus": 180_000,
        "claude-sonnet": 180_000,
        "claude-haiku": 180_000,
        "llama3.2": 6_000,
        "llama3": 6_000,
        "mistral": 6_000,
        "ollama": 6_000,
    }
    _DEFAULT_LIMIT = 50_000

    # Reserved tokens for the prompt template + JSON instructions + output
    _TEMPLATE_RESERVE = 5_000

    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Estimate token count from text length.

        JSON/code-heavy content averages ~1 token per 3 chars;
        natural language ~1 token per 4 chars.  We use /3.5 as a
        conservative middle ground for mixed security-report content.
        """
        if not text:
            return 0
        return max(1, int(len(text) / 3.5))

    @classmethod
    def get_model_context_limit(cls, model_name: str) -> int:
        """Return usable input-token budget for a given model name."""
        lower = model_name.lower()
        for prefix, limit in cls._MODEL_LIMITS.items():
            if prefix in lower:
                return limit
        return cls._DEFAULT_LIMIT

    @classmethod
    def truncate_findings(cls, findings: list[dict], budget_tokens: int) -> list[dict]:
        """Select findings that fit within *budget_tokens*.

        Findings are sorted by severity (critical first).  Each finding's
        description is capped at _MAX_DESCRIPTION_CHARS.  Returns a new
        list; the last element is a summary dict when items are dropped.
        """
        sorted_f = sorted(
            findings,
            key=lambda f: cls._SEVERITY_ORDER.get(f.get("severity", "info"), 4),
        )

        selected: list[dict] = []
        used = 0
        for f in sorted_f:
            trimmed = dict(f)
            desc = trimmed.get("description", "")
            if len(desc) > _MAX_DESCRIPTION_CHARS:
                trimmed["description"] = desc[:_MAX_DESCRIPTION_CHARS] + "..."
            cost = cls.estimate_tokens(json.dumps(trimmed, ensure_ascii=False))
            if used + cost > budget_tokens:
                break
            selected.append(trimmed)
            used += cost

        dropped = len(findings) - len(selected)
        if dropped > 0:
            sev_dropped: dict[str, int] = {}
            for f in sorted_f[len(selected):]:
                s = f.get("severity", "info")
                sev_dropped[s] = sev_dropped.get(s, 0) + 1
            selected.append({
                "_truncated": True,
                "dropped": dropped,
                "dropped_by_severity": sev_dropped,
            })

        return selected

    @classmethod
    def build_context_aware_prompt(
        cls,
        findings: list[dict],
        ports: list[dict],
        correlation_graph: str,
        scan_metadata: dict,
        model_name: str,
    ) -> tuple[list[dict], list[dict], str]:
        """Allocate token budget and return trimmed (findings, ports, correlations).

        Priority: correlations > critical/high findings > ports > medium/low findings.

        Returns (trimmed_findings, trimmed_ports, trimmed_correlations).
        """
        limit = cls.get_model_context_limit(model_name)
        budget = limit - cls._TEMPLATE_RESERVE

        # 1. Metadata (target, profile, sev_counts, mitre, cwe, owasp) — small, always fits
        meta_text = json.dumps(scan_metadata, ensure_ascii=False)
        meta_cost = cls.estimate_tokens(meta_text)
        remaining = max(0, budget - meta_cost)

        # 2. Correlations — highest priority
        corr_cost = cls.estimate_tokens(correlation_graph)
        if corr_cost > remaining:
            correlation_graph = correlation_graph[:int(remaining * 3.5)]
            corr_cost = cls.estimate_tokens(correlation_graph)
        remaining -= corr_cost

        # 3. Split findings into critical/high vs medium/low/info
        crit_high = [f for f in findings
                     if f.get("severity", "info") in ("critical", "high")]
        rest = [f for f in findings
                if f.get("severity", "info") not in ("critical", "high")]

        # Give critical/high 60% of remaining, ports 10%, rest 30%
        crit_budget = int(remaining * 0.60)
        ports_budget = int(remaining * 0.10)
        rest_budget = remaining - crit_budget - ports_budget

        # 4. Critical/high findings
        trimmed_crit = cls.truncate_findings(crit_high, crit_budget)

        # 5. Ports
        trimmed_ports: list[dict] = []
        ports_used = 0
        for p in ports:
            entry = {
                "port": p.get("port"),
                "service": p.get("service"),
                "version": p.get("version", ""),
            }
            cost = cls.estimate_tokens(json.dumps(entry, ensure_ascii=False))
            if ports_used + cost > ports_budget:
                break
            trimmed_ports.append(entry)
            ports_used += cost

        # 6. Remaining findings (medium/low/info)
        # Add unused budget from ports back
        rest_budget += max(0, ports_budget - ports_used)
        trimmed_rest = cls.truncate_findings(rest, rest_budget)

        # Merge findings: crit/high first, then rest
        all_findings = [f for f in trimmed_crit if not f.get("_truncated")]
        all_findings += [f for f in trimmed_rest if not f.get("_truncated")]

        # Collect truncation summaries
        total_dropped = 0
        for lst in (trimmed_crit, trimmed_rest):
            for f in lst:
                if f.get("_truncated"):
                    total_dropped += f.get("dropped", 0)

        if total_dropped > 0:
            all_findings.append({
                "_note": f"{total_dropped} lower-priority findings omitted (context limit)",
            })

        total_used = (
            meta_cost + corr_cost
            + cls.estimate_tokens(json.dumps(all_findings, ensure_ascii=False))
            + ports_used
        )

        log.info(
            "[context] model=%s limit=%d budget=%d used=%d findings=%d/%d ports=%d/%d",
            model_name, limit, budget, total_used,
            len([f for f in all_findings if not f.get("_note")]),
            len(findings),
            len(trimmed_ports),
            len(ports),
        )

        return all_findings, trimmed_ports, correlation_graph


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
            "name": a.get("name", a.get("alert_name", a.get("alert", ""))),
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


# ---------------------------------------------------------------------------
# Web vulnerability name normalization
# ---------------------------------------------------------------------------
_WEB_VULN_CATEGORIES = {
    "sql injection": "SQL Injection",
    "sqli": "SQL Injection",
    "blind sql": "SQL Injection",
    "xss": "XSS",
    "cross-site scripting": "XSS",
    "cross site scripting": "XSS",
    "rce": "RCE",
    "remote code execution": "RCE",
    "command execution": "RCE",
    "command injection": "RCE",
    "os command": "RCE",
    "ssrf": "SSRF",
    "server-side request": "SSRF",
    "server side request": "SSRF",
    "xxe": "XXE",
    "xml external": "XXE",
    "lfi": "LFI",
    "local file inclusion": "LFI",
    "path traversal": "LFI",
    "directory traversal": "LFI",
    "file inclusion": "LFI",
    "rfi": "RFI",
    "remote file inclusion": "RFI",
    "open redirect": "Open Redirect",
    "csrf": "CSRF",
    "cross-site request forgery": "CSRF",
    "idor": "IDOR",
    "insecure direct object": "IDOR",
    "ssti": "SSTI",
    "template injection": "SSTI",
    "server side template": "SSTI",
    "deserialization": "Deserialization",
    "upload": "File Upload",
    "file upload": "File Upload",
    "authentication bypass": "Auth Bypass",
    "auth bypass": "Auth Bypass",
    "broken authentication": "Auth Bypass",
}


def _categorize_web_vuln(name: str) -> str:
    """Normalize web vulnerability names to standard categories across scanners."""
    lower = name.lower()
    for pattern, category in _WEB_VULN_CATEGORIES.items():
        if pattern in lower:
            return category
    return "Other"


# ---------------------------------------------------------------------------
# Cross-module correlation functions
# ---------------------------------------------------------------------------

def _correlate_service_attack_surface(scan_results: dict) -> str:
    """Chain: port (nmap) -> service+version -> tech (whatweb) -> exploits (searchsploit) -> CVEs (nvd, CVSS>=7)."""
    ports = scan_results.get("ports", [])
    if not isinstance(ports, list) or not ports:
        return ""

    searchsploit = scan_results.get("searchsploit", {})
    if not isinstance(searchsploit, dict):
        searchsploit = {}
    by_service = searchsploit.get("by_service", {})
    if not isinstance(by_service, dict):
        by_service = {}

    whatweb = scan_results.get("whatweb", {})
    if not isinstance(whatweb, dict):
        whatweb = {}
    technologies = whatweb.get("technologies", [])
    if not isinstance(technologies, list):
        technologies = []

    nvd = scan_results.get("nvd", {})
    if not isinstance(nvd, dict):
        nvd = {}
    cves = nvd.get("cves", [])
    if not isinstance(cves, list):
        cves = []
    high_cves = [c for c in cves if isinstance(c, dict) and (c.get("cvss_score") or 0) >= 7]

    chains = []
    for p in ports[:15]:
        if not isinstance(p, dict):
            continue
        port_num = p.get("port", "?")
        service = p.get("service", "unknown")
        version = p.get("version", "")

        chain_parts = [f"Port {port_num}/{service}"]
        if version:
            chain_parts[0] += f" ({version})"

        # Match technologies from whatweb
        matched_tech = []
        for t in technologies[:20]:
            if not isinstance(t, dict):
                continue
            tech_name = t.get("name", "")
            tech_version = t.get("version", "")
            if service and tech_name and (
                service.lower() in tech_name.lower()
                or tech_name.lower() in service.lower()
                or (version and tech_name.lower() in version.lower())
            ):
                entry = tech_name
                if tech_version:
                    entry += f"/{tech_version}"
                matched_tech.append(entry)
        if matched_tech:
            chain_parts.append(f"tech: {', '.join(matched_tech[:3])}")

        # Match exploits from searchsploit by_service
        matched_exploits = []
        for svc_key, exploits in by_service.items():
            if not isinstance(svc_key, str) or not isinstance(exploits, list):
                continue
            if (
                service.lower() in svc_key.lower()
                or svc_key.lower() in service.lower()
                or (version and version.lower() in svc_key.lower())
            ):
                for ex in exploits[:3]:
                    if isinstance(ex, dict):
                        ex_type = ex.get("type", "")
                        ex_title = ex.get("title", "")[:60]
                        matched_exploits.append(f"{ex_title} ({ex_type})" if ex_type else ex_title)
        if matched_exploits:
            chain_parts.append(f"{len(matched_exploits)} exploits: {', '.join(matched_exploits[:3])}")

        # Match CVEs
        matched_cves = []
        for cve in high_cves:
            desc = (cve.get("description") or "").lower()
            cve_id = cve.get("cve_id") or cve.get("id") or ""
            score = cve.get("cvss_score", 0)
            if service.lower() in desc or (version and version.lower() in desc):
                matched_cves.append(f"{cve_id} (CVSS:{score})")
        if matched_cves:
            chain_parts.append(f"CVEs: {', '.join(matched_cves[:3])}")

        # Only emit chain if there's more than just the port
        if len(chain_parts) > 1:
            chains.append(" -> ".join(chain_parts))
        if len(chains) >= 5:
            break

    if not chains:
        return ""

    lines = [f"[1] POWIERZCHNIA ATAKU USLUG ({len(chains)} lancuchow):"]
    for chain in chains:
        lines.append(f"  {chain}")
    return "\n".join(lines)


def _correlate_ad_attack_paths(scan_results: dict) -> str:
    """Chain: users (enum4linux+netexec+bloodhound) -> attack paths (bloodhound) -> credentials (impacket)."""
    bloodhound = scan_results.get("bloodhound", {})
    if not isinstance(bloodhound, dict) or bloodhound.get("skipped"):
        bloodhound = {}

    enum4linux = scan_results.get("enum4linux", {})
    if not isinstance(enum4linux, dict) or enum4linux.get("skipped"):
        enum4linux = {}

    netexec = scan_results.get("netexec", {})
    if not isinstance(netexec, dict) or netexec.get("skipped"):
        netexec = {}

    impacket = scan_results.get("impacket", {})
    if not isinstance(impacket, dict) or impacket.get("skipped"):
        impacket = {}

    # Collect all users from various sources
    all_users = set()

    bh_users = bloodhound.get("users", [])
    if isinstance(bh_users, list):
        for u in bh_users:
            if isinstance(u, dict) and u.get("name"):
                all_users.add(u["name"])

    e4l_users = enum4linux.get("users", [])
    if isinstance(e4l_users, list):
        for u in e4l_users:
            if isinstance(u, dict) and u.get("username"):
                all_users.add(u["username"])

    ne_users = netexec.get("users", [])
    if isinstance(ne_users, list):
        for u in ne_users:
            if isinstance(u, dict) and u.get("username"):
                all_users.add(u["username"])

    attack_paths = bloodhound.get("attack_paths", [])
    if not isinstance(attack_paths, list):
        attack_paths = []

    impacket_summary = impacket.get("summary", {})
    if not isinstance(impacket_summary, dict):
        impacket_summary = {}

    if not all_users and not attack_paths and not impacket_summary:
        return ""

    lines = ["[2] SCIEZKI ATAKU AD:"]

    # Users discovered
    if all_users:
        user_list = sorted(all_users)
        shown = ", ".join(user_list[:8])
        if len(user_list) > 8:
            shown += ", ..."
        sources = []
        if bh_users:
            sources.append("bloodhound")
        if e4l_users:
            sources.append("enum4linux")
        if ne_users:
            sources.append("netexec")
        lines.append(f"  Uzytkownicy wykryci ({len(all_users)}, zrodla: {'+'.join(sources)}): {shown}")

    # Attack paths with cross-reference
    for path in attack_paths[:5]:
        if not isinstance(path, dict):
            continue
        path_name = path.get("title") or path.get("name") or path.get("id", "")
        if not path_name:
            continue
        severity = path.get("severity", "")
        affected = path.get("affected", [])
        if not isinstance(affected, list):
            affected = []

        # Cross-reference affected users with discovered users
        confirmed = [u for u in affected if u in all_users]

        line = f"  Sciezka ataku: {path_name}"
        if severity:
            line += f" [{severity}]"
        if confirmed:
            line += f" [potwierdzeni uzytkownicy: {', '.join(confirmed[:5])}]"
        lines.append(line)

    # Impacket summary
    impacket_parts = []
    if impacket_summary.get("kerberoastable", 0) > 0:
        impacket_parts.append(f"kerberoastable: {impacket_summary['kerberoastable']}")
    if impacket_summary.get("asreproastable", 0) > 0:
        impacket_parts.append(f"AS-REP roastable: {impacket_summary['asreproastable']}")
    if impacket_summary.get("secrets_found", 0) > 0:
        impacket_parts.append(f"secrets: {impacket_summary['secrets_found']}")
    if impacket_summary.get("total_hashes", 0) > 0:
        impacket_parts.append(f"hashes: {impacket_summary['total_hashes']}")

    if impacket_parts:
        lines.append(f"  Impacket: {', '.join(impacket_parts)}")

    # Build chain summary
    chain_modules = []
    if e4l_users or ne_users:
        enum_sources = []
        if e4l_users:
            enum_sources.append("enum4linux")
        if ne_users:
            enum_sources.append("netexec")
        chain_modules.append("+".join(enum_sources))
    if attack_paths:
        chain_modules.append("bloodhound")
    if impacket_summary.get("total_hashes", 0) > 0 or impacket_summary.get("secrets_found", 0) > 0:
        chain_modules.append("impacket")

    if len(chain_modules) >= 2:
        lines.append(f"  LANCUCH: {' -> '.join(chain_modules)}")

    return "\n".join(lines) if len(lines) > 1 else ""


def _correlate_web_exploit_chains(scan_results: dict) -> str:
    """Chain: web vulns (nuclei+zap+wapiti) -> sqlmap confirmation -> paths (gobuster) -> misconfig (nikto)."""
    nuclei = scan_results.get("nuclei", {})
    if not isinstance(nuclei, dict):
        nuclei = {}
    zap = scan_results.get("zap", {})
    if not isinstance(zap, dict):
        zap = {}
    wapiti = scan_results.get("wapiti", {})
    if not isinstance(wapiti, dict):
        wapiti = {}
    sqlmap = scan_results.get("sqlmap", {})
    if not isinstance(sqlmap, dict):
        sqlmap = {}
    gobuster = scan_results.get("gobuster", {})
    if not isinstance(gobuster, dict):
        gobuster = {}
    nikto = scan_results.get("nikto", {})
    if not isinstance(nikto, dict):
        nikto = {}

    # Collect web vulns and categorize: {category: {source: count}}
    category_sources: dict[str, dict[str, int]] = {}

    # Nuclei findings
    for f in (nuclei.get("findings") or []):
        if not isinstance(f, dict):
            continue
        info = f.get("info", {})
        if not isinstance(info, dict):
            continue
        name = info.get("name", "")
        cat = _categorize_web_vuln(name)
        if cat not in category_sources:
            category_sources[cat] = {}
        category_sources[cat]["nuclei"] = category_sources[cat].get("nuclei", 0) + 1

    # ZAP alerts
    zap_alerts = zap.get("summary", {}).get("alerts") or zap.get("alerts") or []
    if not isinstance(zap_alerts, list):
        zap_alerts = []
    for a in zap_alerts:
        if not isinstance(a, dict):
            continue
        name = a.get("name") or a.get("alert_name") or a.get("alert") or ""
        cat = _categorize_web_vuln(name)
        if cat not in category_sources:
            category_sources[cat] = {}
        category_sources[cat]["zap"] = category_sources[cat].get("zap", 0) + 1

    # Wapiti vulnerabilities
    for v in (wapiti.get("vulnerabilities") or []):
        if not isinstance(v, dict):
            continue
        name = v.get("name") or v.get("type", "")
        cat = _categorize_web_vuln(name)
        if cat not in category_sources:
            category_sources[cat] = {}
        category_sources[cat]["wapiti"] = category_sources[cat].get("wapiti", 0) + 1

    if not category_sources:
        return ""

    lines = ["[3] LANCUCHY EXPLOITOW WEB:"]

    # Identify confirmed (2+ scanners) vs single-source findings
    confirmed = []
    single_source = []
    for cat, sources in category_sources.items():
        if cat == "Other":
            continue
        total = sum(sources.values())
        source_names = sorted(sources.keys())
        if len(source_names) >= 2:
            confirmed.append((cat, source_names, total))
        else:
            single_source.append((cat, source_names, total))

    confirmed.sort(key=lambda x: x[2], reverse=True)
    single_source.sort(key=lambda x: x[2], reverse=True)

    for cat, sources, total in confirmed[:5]:
        lines.append(f"  POTWIERDZONE ({'+'.join(sources)}): {cat} ({total} wynikow)")

    for cat, sources, total in single_source[:3]:
        lines.append(f"  {sources[0]}: {cat} ({total} wynikow)")

    # SQLMap confirmation
    if sqlmap.get("vulnerable"):
        injectable = sqlmap.get("injectable_params", [])
        if not isinstance(injectable, list):
            injectable = []
        sqli_sources = category_sources.get("SQL Injection", {})
        sqli_scanners = sorted(sqli_sources.keys()) if sqli_sources else []
        param_str = ", ".join(injectable[:5]) if injectable else "unknown"
        if sqli_scanners:
            lines.append(f"  SQL Injection POTWIERDZONY: sqlmap ({param_str}) + {'+'.join(sqli_scanners)}")
        else:
            lines.append(f"  SQL Injection POTWIERDZONY: sqlmap ({param_str})")

    # Gobuster sensitive paths
    gob_findings = gobuster.get("findings", [])
    if isinstance(gob_findings, list) and gob_findings:
        sensitive_kw = ("/admin", "/backup", "/config", "/upload", "/api", "/debug", "/test", "/.env", "/.git")
        sensitive_paths = []
        for f in gob_findings:
            if not isinstance(f, dict):
                continue
            path = f.get("path", "")
            status = f.get("status", 0)
            if status in (200, 301, 302) and any(kw in path.lower() for kw in sensitive_kw):
                sensitive_paths.append(path)
        if sensitive_paths:
            lines.append(f"  Sciezki wrazliwe (gobuster): {', '.join(sensitive_paths[:5])}")

    # Nikto server misconfigurations
    nikto_findings = nikto.get("findings", [])
    if isinstance(nikto_findings, list) and nikto_findings:
        lines.append(f"  Misconfiguracje serwera (nikto): {len(nikto_findings)} znalezionych")

    return "\n".join(lines) if len(lines) > 1 else ""


def _correlate_network_smb_exposure(scan_results: dict) -> str:
    """Chain: SMB info -> null session -> shares -> relay targets -> LLMNR/NBT-NS poisoning."""
    netexec = scan_results.get("netexec", {})
    if not isinstance(netexec, dict) or netexec.get("skipped"):
        netexec = {}
    smbmap = scan_results.get("smbmap", {})
    if not isinstance(smbmap, dict) or smbmap.get("skipped"):
        smbmap = {}
    enum4linux = scan_results.get("enum4linux", {})
    if not isinstance(enum4linux, dict) or enum4linux.get("skipped"):
        enum4linux = {}
    responder = scan_results.get("responder", {})
    if not isinstance(responder, dict) or responder.get("skipped"):
        responder = {}

    smb_info = netexec.get("smb_info", {})
    if not isinstance(smb_info, dict):
        smb_info = {}

    has_smb = bool(smb_info) or netexec.get("null_session") or smbmap.get("total_shares", 0) > 0
    has_enum = bool(enum4linux.get("shares"))
    has_responder = bool(responder.get("protocols_detected"))

    if not has_smb and not has_enum and not has_responder:
        return ""

    lines = ["[4] EKSPOZYCJA SMB/SIECIOWA:"]

    # SMB host info
    if smb_info.get("os"):
        lines.append(f"  Host: {smb_info.get('hostname', '?')} ({smb_info.get('os', '?')})")

    # SMB risks
    risks = []
    signing = smb_info.get("signing")
    smbv1 = smb_info.get("smbv1")
    if signing is False:
        risks.append("SMB signing DISABLED")
    if smbv1 is True:
        risks.append("SMBv1 ENABLED")
    if risks:
        lines.append(f"  RYZYKO: {'; '.join(risks)}")

    # Null session from multiple sources
    null_sources = []
    if netexec.get("null_session"):
        null_sources.append("netexec")
    if smbmap.get("access_method") == "null" or (
        smbmap.get("total_shares", 0) > 0 and smbmap.get("readable_shares", 0) > 0
    ):
        null_sources.append("smbmap")
    if enum4linux.get("users") or enum4linux.get("shares"):
        null_sources.append("enum4linux")

    if null_sources:
        label = "POTWIERDZONY" if len(null_sources) >= 2 else "wykryty"
        lines.append(f"  Null session {label} ({'+'.join(null_sources)})")

    # Merge shares from all sources
    all_shares: dict[str, str] = {}
    for s in (netexec.get("shares") or []):
        if isinstance(s, dict) and isinstance(s.get("name"), str):
            all_shares[s["name"]] = str(s.get("access", ""))
    for s in (smbmap.get("shares") or []):
        if isinstance(s, dict) and isinstance(s.get("name"), str):
            existing = all_shares.get(s["name"], "")
            access = str(s.get("access", ""))
            if not existing or (access and "WRITE" in access.upper()):
                all_shares[s["name"]] = access
    for s in (enum4linux.get("shares") or []):
        if isinstance(s, dict) and isinstance(s.get("name"), str):
            if s["name"] not in all_shares:
                all_shares[s["name"]] = str(s.get("access", ""))

    if all_shares:
        share_list = [
            f"{name} [{access}]" if access else name
            for name, access in sorted(all_shares.items())[:8]
        ]
        lines.append(f"  Udzialy ({len(all_shares)}): {', '.join(share_list)}")

    # Relay targets
    relay_targets = netexec.get("relay_targets", [])
    if isinstance(relay_targets, list) and relay_targets:
        lines.append(f"  Relay targets: {len(relay_targets)} hostow")

    # Responder - LLMNR/NBT-NS poisoning
    protocols = responder.get("protocols_detected", [])
    if isinstance(protocols, list) and protocols:
        poison_protocols = [p for p in protocols if isinstance(p, str) and p in ("LLMNR", "NBT-NS", "MDNS", "WPAD")]
        if poison_protocols:
            lines.append(f"  Poisoning: {'+'.join(poison_protocols)} wykryte (responder)")

    # Build lateral chain
    chain_parts = []
    if isinstance(protocols, list) and any(
        isinstance(p, str) and p in ("LLMNR", "NBT-NS") for p in protocols
    ):
        chain_parts.append("LLMNR+NBT-NS")
    if signing is False or relay_targets:
        chain_parts.append("NTLM relay")
    if all_shares:
        chain_parts.append("dostep do udzialow")

    if len(chain_parts) >= 2:
        lines.append(f"  LANCUCH LATERALNY: {' -> '.join(chain_parts)}")

    return "\n".join(lines) if len(lines) > 1 else ""


def _build_correlation_graph(scan_results: dict) -> str:
    """Orchestrate cross-module correlation. Hard cap: 3000 chars (~750 tokens)."""
    sections = []

    s1 = _correlate_service_attack_surface(scan_results)
    if s1:
        sections.append(s1)

    s2 = _correlate_ad_attack_paths(scan_results)
    if s2:
        sections.append(s2)

    s3 = _correlate_web_exploit_chains(scan_results)
    if s3:
        sections.append(s3)

    s4 = _correlate_network_smb_exposure(scan_results)
    if s4:
        sections.append(s4)

    if not sections:
        return ""

    result = "\n".join(sections)
    if len(result) > 3000:
        result = result[:2997] + "..."
    return result


def _build_prompt(scan_results: dict, findings: list[dict], risk_score: int,
                   model_name: str = "claude-sonnet-4-20250514") -> str:
    """Build the single comprehensive prompt for unified AI analysis.

    Uses ContextManager to dynamically fit content within the model's
    context window.  *model_name* controls how aggressive the trimming is.
    """
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

    sev_counts: dict[str, int] = {}
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
    owasp_cats = [c.get("id", "") + " " + c.get("name", "")
                  for c in (owasp.get("categories") or []) if c.get("detected")]

    # Build cross-module correlation graph
    correlation_graph = _build_correlation_graph(scan_results)

    # ── Context-aware trimming ──────────────────────────────────
    scan_metadata = {
        "target": target, "profile": profile, "modules_ran": modules_ran,
        "sev_counts": sev_counts, "risk_score": risk_score,
        "mitre": mitre_techniques, "cwe": cwe_ids, "owasp": owasp_cats,
    }

    findings_for_prompt, ports_summary, correlation_graph = (
        ContextManager.build_context_aware_prompt(
            findings=findings,
            ports=ports,
            correlation_graph=correlation_graph,
            scan_metadata=scan_metadata,
            model_name=model_name,
        )
    )

    correlation_section = ""
    if correlation_graph:
        correlation_section = f"""
=== KORELACJE MIEDZYMODULOWE ===
Ponizsze lancuchy pokazuja POLACZONE sciezki ataku wykryte przez wiele modulow.
Uzyj ich jako podstawy dla attack_narrative i exploit_chain:
{correlation_graph}
"""

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
{correlation_section}
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
- attack_narrative: OPIERAJ SIE na korelacjach miedzymodulowych. Laczone sciezki > pojedyncze podatnosci.
- exploit_chain: uzyj lancuchow z sekcji KORELACJE jako szkieletu. Max 8 krokow, od rekonesansu do pelnego przejecia.
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

    # Try primary provider (Claude), then fallback to Ollama
    providers_to_try = ["claude", "ollama"]
    last_error = None

    for provider_name in providers_to_try:
        try:
            provider = get_provider(force=provider_name, task="ai_analysis")
            if not provider.is_available():
                log.info("[ai_analysis] %s not available, skipping", provider_name)
                continue

            # Resolve model name for context budgeting
            model_name = getattr(provider, "_model", provider_name)
            prompt = _build_prompt(scan_results, findings, risk_score,
                                   model_name=model_name)

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


# ── Reflector Pattern ──

_PROFILE_MODULES = {
    "SZCZENIAK": [
        "nmap", "nuclei", "gobuster", "whatweb", "testssl", "harvester",
        "ipinfo", "abuseipdb", "otx", "dnsrecon", "whois", "subfinder",
    ],
}
_PROFILE_MODULES["STRAZNIK"] = _PROFILE_MODULES["SZCZENIAK"] + [
    "zap", "wapiti", "sqlmap", "nikto", "httpx", "masscan", "amass",
    "katana", "dnsx", "naabu", "netexec", "enum4linux", "bloodhound",
    "smbmap", "searchsploit",
]
_PROFILE_MODULES["CERBER"] = _PROFILE_MODULES["STRAZNIK"] + [
    "wpscan", "joomscan", "cmsmap", "droopescan", "retirejs",
    "netdiscover", "arpscan", "fping", "traceroute", "nbtscan",
    "snmpwalk", "responder", "fierce", "onesixtyone", "ikescan",
    "sslyze", "impacket",
]

# Keys that indicate a module produced actual data
_DATA_KEYS = {
    "nmap": "ports", "nuclei": "findings", "zap": "alerts",
    "gobuster": "paths", "whatweb": "technologies", "testssl": "issues",
    "harvester": "emails", "sqlmap": "injectable_params",
    "nikto": "findings", "wapiti": "vulnerabilities",
    "subfinder": "subdomains", "amass": "subdomains",
    "httpx": "total_results", "masscan": "ports",
    "katana": "total_urls", "dnsx": "total_resolved",
    "naabu": "total_open_ports", "bloodhound": "attack_paths",
    "searchsploit": "exploits", "sslyze": "vulnerabilities",
    "smbmap": "total_shares", "impacket": "summary",
}


def _classify_module(name: str, scan_results: dict) -> str:
    """Classify a module's result as ok, empty, error, or missing."""
    data = scan_results.get(name)
    if data is None:
        return "missing"

    # Check for error indicators
    errors = data.get("errors") or data.get("error") or ""
    if errors and isinstance(errors, str) and errors.strip():
        # Has errors, but might also have data — check both
        pass

    # Check for actual data
    key = _DATA_KEYS.get(name)
    if key:
        val = data.get(key)
        if isinstance(val, list) and len(val) > 0:
            return "ok"
        if isinstance(val, dict) and val:
            return "ok"
        if isinstance(val, (int, float)) and val > 0:
            return "ok"

    # No specific data key — check if dict has anything beyond metadata
    skip_keys = {"target", "raw", "errors", "error", "skipped", "reason",
                 "command", "timeout", "scan_time", "duration"}
    has_data = any(
        k not in skip_keys and data.get(k)
        for k in data
        if not k.startswith("_")
    )
    if has_data:
        return "ok"

    if errors:
        return "error"
    return "empty"


def reflect_on_scan(scan_results: dict, profile: str = "STRAZNIK") -> dict:
    """Analyze what went wrong/right in a scan and recommend improvements.

    Never raises — returns partial result on any error.
    """
    from datetime import datetime, timezone

    try:
        modules = _PROFILE_MODULES.get(profile.upper(),
                                        _PROFILE_MODULES["STRAZNIK"])
        classified = {
            "ok": [], "empty": [], "error": [], "missing": [],
        }
        for mod in modules:
            status = _classify_module(mod, scan_results)
            classified[status].append(mod)

        result = {
            "modules_ok": classified["ok"],
            "modules_empty": classified["empty"],
            "modules_error": classified["error"],
            "modules_missing": classified["missing"],
            "analysis": {},
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Only call LLM if there are problems worth analyzing
        problem_count = len(classified["empty"]) + len(classified["error"]) + len(classified["missing"])
        if problem_count == 0:
            result["analysis"] = {
                "issues": [],
                "likely_causes": ["All modules returned data successfully"],
                "next_scan_recommendations": [],
            }
            return result

        target = scan_results.get("target", "unknown")
        prompt = f"""You are a penetration testing expert reviewing scan results for target: {target} (profile: {profile}).

MODULE STATUS:
- OK ({len(classified['ok'])}): {', '.join(classified['ok']) or 'none'}
- EMPTY results ({len(classified['empty'])}): {', '.join(classified['empty']) or 'none'}
- ERRORS ({len(classified['error'])}): {', '.join(classified['error']) or 'none'}
- MISSING from results ({len(classified['missing'])}): {', '.join(classified['missing']) or 'none'}

Analyze why modules failed or returned empty. Return ONLY JSON:
{{"issues": ["max 3 specific issues found"], "likely_causes": ["max 3 probable causes"], "next_scan_recommendations": ["max 3 actionable recommendations for rescanning this target"]}}"""

        try:
            provider = get_provider(task="ai_analysis")
            if provider.is_available():
                response_text = provider.chat(prompt, max_tokens=800)
                parsed = _parse_response(response_text)
                if parsed:
                    result["analysis"] = {
                        "issues": parsed.get("issues", [])[:3],
                        "likely_causes": parsed.get("likely_causes", [])[:3],
                        "next_scan_recommendations": parsed.get("next_scan_recommendations", [])[:3],
                    }
        except Exception as e:
            log.warning("[reflect_on_scan] LLM call failed: %s", e)

        return result

    except Exception as e:
        log.error("[reflect_on_scan] Unexpected error: %s", e)
        return {
            "modules_ok": [], "modules_empty": [], "modules_error": [],
            "modules_missing": [], "analysis": {},
            "generated_at": datetime.now(timezone.utc).isoformat()
            if 'datetime' in dir() else "",
        }
