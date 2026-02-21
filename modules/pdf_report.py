import os
import json
from datetime import datetime
from weasyprint import HTML, CSS

def _risk_color(risk: str) -> str:
    return {
        "NISKIE": "#3ddc84", "LOW": "#3ddc84",
        "ŚREDNIE": "#f5c518", "MEDIUM": "#f5c518",
        "WYSOKIE": "#ff8c00", "HIGH": "#ff8c00",
        "KRYTYCZNE": "#ff4444", "CRITICAL": "#ff4444",
    }.get(risk.upper(), "#4a8fd4")

def _ports_html(ports: list) -> str:
    if not ports:
        return "<p class='muted'>Brak otwartych portów.</p>"
    rows = ""
    for p in ports:
        rows += f"""<tr>
            <td class='mono'>{p.get('port','')}</td>
            <td>{p.get('service','')}</td>
            <td>{p.get('version','')}</td>
            <td>{p.get('state','')}</td>
        </tr>"""
    return f"""<table>
        <thead><tr><th>PORT</th><th>SERVICE</th><th>VERSION</th><th>STATE</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>"""

def _chains_html(chains_data: dict) -> str:
    chains = chains_data.get("chains", [])
    if not chains:
        return "<p class='muted'>Brak zidentyfikowanych łańcuchów exploitów.</p>"
    html = ""
    impact_color = {"KRYTYCZNY": "#ff4444", "WYSOKI": "#ff8c00", "ŚREDNI": "#f5c518"}
    for chain in chains:
        color = impact_color.get(chain.get("impact", ""), "#4a8fd4")
        steps_html = ""
        for step in chain.get("steps", []):
            steps_html += f"""<div class='chain-step'>
                <span class='step-num'>KROK {step.get('step','')}</span>
                <span class='step-action'>{step.get('action','')}</span>
                <span class='step-vuln muted'>{step.get('vulnerability','')} · {step.get('time','')}</span>
                <span class='step-result'>→ {step.get('result','')}</span>
            </div>"""
        html += f"""<div class='chain-block'>
            <div class='chain-header'>
                <span class='chain-name'>{chain.get('name','')}</span>
                <span class='chain-impact' style='color:{color}'>{chain.get('impact','')} · {chain.get('probability','')}%</span>
            </div>
            <div class='chain-meta muted'>Czas: {chain.get('total_time','')} · Priorytet: {chain.get('remediation_priority','')}</div>
            {steps_html}
            <div class='chain-final'>Dostęp końcowy: {chain.get('final_access','')}</div>
            <div class='chain-biz muted'>{chain.get('business_impact','')}</div>
        </div>"""
    return html

def _narrative_html(narrative_data: dict) -> str:
    if not narrative_data:
        return "<p class='muted'>Brak narracji.</p>"
    narrative = narrative_data.get("narrative") or narrative_data.get("note", "")
    executive = narrative_data.get("executive_summary", "")
    loss = narrative_data.get("potential_loss", "")
    fix = narrative_data.get("fix_cost", "")
    ttc = narrative_data.get("time_to_compromise", "")
    if not narrative:
        return f"<p class='muted'>{executive}</p>"
    narrative_formatted = narrative.replace("\n", "<br>").replace("**", "")
    return f"""<div class='narrative-box'>
        <div class='narrative-text'>{narrative_formatted}</div>
    </div>
    <div class='narrative-stats'>
        <div class='nstat'><span class='muted'>CZAS PRZEJĘCIA</span><span>{ttc}</span></div>
        <div class='nstat'><span class='muted'>POTENCJALNA STRATA</span><span class='danger'>{loss}</span></div>
        <div class='nstat'><span class='muted'>KOSZT NAPRAWY</span><span class='ok'>{fix}</span></div>
    </div>
    <div class='exec-summary'>{executive}</div>"""

def _gobuster_html(gobuster: dict) -> str:
    findings = gobuster.get("findings", [])
    if not findings:
        return "<p class='muted'>Brak znalezionych ścieżek.</p>"
    rows = ""
    for f in findings[:20]:
        rows += f"<tr><td class='mono'>{f.get('path','')}</td><td>{f.get('status','')}</td><td>{f.get('size','')}</td></tr>"
    return f"""<table>
        <thead><tr><th>ŚCIEŻKA</th><th>STATUS</th><th>ROZMIAR</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>"""

def _sqlmap_html(sqlmap: dict) -> str:
    if not sqlmap:
        return "<p class='muted'>Brak danych.</p>"
    vulnerable = sqlmap.get("vulnerable", False)
    color = "#ff4444" if vulnerable else "#3ddc84"
    label = "PODATNY" if vulnerable else "BRAK PODATNOŚCI"
    params = sqlmap.get("injectable_params", [])
    params_str = ", ".join(params) if params else "—"
    return f"""<div class='sqli-result' style='border-color:{color}'>
        <span class='sqli-label' style='color:{color}'>{label}</span>
        <span class='muted'>Parametry: {params_str}</span>
    </div>"""

def _testssl_html(testssl: dict) -> str:
    if not testssl:
        return "<p class='muted'>Brak danych TLS.</p>"
    issues = testssl.get("issues", [])
    grade = testssl.get("grade", "")
    if not issues and not grade:
        return "<p class='muted'>Brak problemów TLS.</p>"
    grade_color = {"A": "#3ddc84", "A+": "#3ddc84", "B": "#f5c518", "C": "#ff8c00", "F": "#ff4444"}.get(grade, "#4a8fd4")
    issues_html = ""
    for issue in issues[:10]:
        issues_html += f"<div class='issue'><span class='issue-num'>⚠</span><span>{issue}</span></div>"
    return f"""{'<div class="grade-box"><span class="muted">OCENA TLS</span><span class="grade" style="color:' + grade_color + '">' + grade + '</span></div>' if grade else ''}
    {issues_html if issues_html else '<p class="muted">Brak problemów TLS.</p>'}"""

def _nikto_html(nikto: dict) -> str:
    findings = nikto.get("findings", []) if isinstance(nikto, dict) else []
    if not findings:
        return "<p class='muted'>Brak wyników Nikto.</p>"
    rows = ""
    for f in findings[:30]:
        rows += f"<tr><td>{f.get('description','')}</td><td class='mono'>{f.get('url','')}</td><td>{f.get('osvdb','')}</td></tr>"
    extra = f"<p class='muted'>... i {len(findings)-30} więcej</p>" if len(findings) > 30 else ""
    return f"""<table>
        <thead><tr><th>OPIS</th><th>URL</th><th>OSVDB</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>{extra}"""

def _whatweb_html(whatweb: dict) -> str:
    if not whatweb:
        return "<p class='muted'>Brak danych WhatWeb.</p>"
    plugins = whatweb.get("plugins", whatweb.get("technologies", []))
    raw = whatweb.get("raw", "")
    if not plugins and not raw:
        return "<p class='muted'>Brak danych WhatWeb.</p>"
    html = ""
    if plugins:
        tags = ""
        for p in plugins[:30]:
            name = p if isinstance(p, str) else (p.get("name", "") or p.get("plugin", ""))
            ver = p.get("version", "") if isinstance(p, dict) else ""
            if name:
                ver_html = f' <span style="color:#4a8fd4">{ver}</span>' if ver else ''
                tags += f"<span style='font-size:11px;border:1px solid rgba(74,143,212,.3);padding:2px 8px;margin:2px;color:#e8f0fc'>{name}{ver_html}</span>"
        html += f"<div style='display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px'>{tags}</div>"
    elif raw:
        lines = [l.strip() for l in raw.split("\n") if l.strip()]
        tags = " ".join(f"<span style='font-size:10px;border:1px solid rgba(74,143,212,.3);padding:2px 8px;margin:2px;color:#e8f0fc'>{l[:80]}</span>" for l in lines[:20])
        html += f"<div style='display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px'>{tags}</div>"
    grid = ""
    for label, key in [("TARGET", "target"), ("HTTP STATUS", "http_status"), ("TITLE", "title"), ("COUNTRY", "country"), ("IP", "ip")]:
        val = whatweb.get(key, "") or whatweb.get(key.replace("http_", ""), "")
        if val:
            grid += f"<div><span class='muted'>{label}</span><br><span style='color:#e8f0fc'>{val}</span></div>"
    if grid:
        html += f"<div style='display:flex;flex-wrap:wrap;gap:16px'>{grid}</div>"
    return html if html else "<p class='muted'>Brak danych WhatWeb.</p>"

def _nuclei_html(nuclei: dict) -> str:
    findings = nuclei.get("findings", []) if isinstance(nuclei, dict) else []
    if not findings:
        return "<p class='muted'>Brak wyników Nuclei.</p>"
    rows = ""
    sev_color = {"critical": "#ff4444", "high": "#ff8c00", "medium": "#f5c518", "low": "#3ddc84", "info": "#4a8fd4"}
    for f in findings[:30]:
        sev = (f.get("severity", "") or "").lower()
        color = sev_color.get(sev, "#4a8fd4")
        rows += f"<tr><td>{f.get('name','') or f.get('template-id','')}</td><td style='color:{color}'>{sev.upper()}</td><td class='mono'>{f.get('matched-at','') or f.get('host','')}</td></tr>"
    extra = f"<p class='muted'>... i {len(findings)-30} więcej</p>" if len(findings) > 30 else ""
    return f"""<table>
        <thead><tr><th>VULNERABILITY</th><th>SEVERITY</th><th>MATCHED AT</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>{extra}"""

def _harvester_html(harvester: dict) -> str:
    if not harvester:
        return "<p class='muted'>Brak danych OSINT.</p>"
    emails = harvester.get("emails", []) or []
    subdomains = harvester.get("subdomains", []) or []
    if not emails and not subdomains:
        return "<p class='muted'>Brak znalezionych adresów i subdomen.</p>"
    html = ""
    if emails:
        items = "".join(f"<div class='mono' style='padding:2px 0'>{e}</div>" for e in emails[:20])
        html += f"<div style='margin-bottom:12px'><div class='muted' style='margin-bottom:4px'>EMAILS ({len(emails)})</div>{items}</div>"
    if subdomains:
        items = "".join(f"<div class='mono' style='padding:2px 0'>{s}</div>" for s in subdomains[:20])
        html += f"<div><div class='muted' style='margin-bottom:4px'>SUBDOMAINS ({len(subdomains)})</div>{items}</div>"
    return html

def _masscan_html(masscan: dict) -> str:
    ports = masscan.get("ports", []) if isinstance(masscan, dict) else []
    if not ports:
        return "<p class='muted'>Brak wyników Masscan.</p>"
    rows = ""
    for p in ports[:40]:
        rows += f"<tr><td class='mono'>{p.get('port','')}</td><td>{p.get('proto','')}</td><td>{p.get('status','')}</td></tr>"
    return f"""<table>
        <thead><tr><th>PORT</th><th>PROTOCOL</th><th>STATUS</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>"""

def _ipinfo_html(ipinfo: dict) -> str:
    if not ipinfo or not ipinfo.get("found"):
        return "<p class='muted'>Brak danych IPInfo.</p>"
    ii = ipinfo
    grid = ""
    for label, key in [("IP", "ip"), ("HOSTNAME", "hostname"), ("ORG", "org"), ("ASN", "asn"), ("COUNTRY", "country"), ("REGION", "region"), ("CITY", "city")]:
        val = ii.get(key, "")
        if val:
            grid += f"<div><span class='muted'>{label}</span><br><span style='color:#e8f0fc'>{val}</span></div>"
    return f"<div style='display:flex;flex-wrap:wrap;gap:16px'>{grid}</div>"

def _enum4linux_html(enum4linux: dict) -> str:
    if not enum4linux or enum4linux.get("skipped"):
        return "<p class='muted'>Pominięto (cel nie jest hostem SMB).</p>"
    html = ""
    osi = enum4linux.get("os_info", {})
    # OS info grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    if osi.get("os"):
        html += f"<div><span class='muted'>OS</span><br><span style='font-size:12px;font-weight:700;color:#e8f0fc'>{osi['os']}</span></div>"
    if osi.get("version"):
        html += f"<div><span class='muted'>VERSION</span><br><span style='font-size:11px;color:#b8ccec'>{osi['version']}</span></div>"
    if osi.get("domain"):
        html += f"<div><span class='muted'>DOMAIN</span><br><span style='font-size:14px;font-weight:700;color:#f5c518'>{osi['domain']}</span></div>"
    if osi.get("workgroup"):
        html += f"<div><span class='muted'>WORKGROUP</span><br><span style='font-size:12px;font-weight:700;color:#e8f0fc'>{osi['workgroup']}</span></div>"
    if osi.get("netbios_name"):
        html += f"<div><span class='muted'>NETBIOS NAME</span><br><span style='font-size:12px;font-weight:700;color:#e8f0fc;font-family:monospace'>{osi['netbios_name']}</span></div>"
    html += "</div>"
    # Vulnerability badges
    vulns = enum4linux.get("vulnerabilities", [])
    if vulns:
        sev_color = {"high": "#ff4444", "medium": "#ff8c00", "low": "#f5c518"}
        badges = ""
        for v in vulns:
            color = sev_color.get(v.get("severity", "medium"), "#f5c518")
            badges += f"<span style='font-size:10px;color:{color};border:1px solid {color};padding:2px 8px;margin-right:6px'>{v.get('severity','').upper()}: {v.get('title','')}</span>"
        html += f"<div style='margin-bottom:12px'>{badges}</div>"
    # Users table
    users = enum4linux.get("users", [])
    if users:
        rows = ""
        for u in users[:30]:
            rows += f"<tr><td class='mono' style='font-size:11px;color:#f5c518'>{u.get('username','')}</td><td style='font-size:10px'>{u.get('rid','')}</td><td style='font-size:10px'>{u.get('description','')}</td><td style='font-size:9px;color:#8a9bb5'>{u.get('flags','')}</td></tr>"
        extra = f"<p class='muted'>... i {len(users)-30} więcej</p>" if len(users) > 30 else ""
        html += f"<div style='margin-bottom:12px'><div class='muted' style='margin-bottom:4px'>USERS ({len(users)})</div><table><thead><tr><th>USERNAME</th><th>RID</th><th>DESCRIPTION</th><th>FLAGS</th></tr></thead><tbody>{rows}</tbody></table>{extra}</div>"
    # Groups table
    groups = enum4linux.get("groups", [])
    if groups:
        rows = ""
        for g in groups[:20]:
            members = ", ".join(g.get("members", [])) or "—"
            rows += f"<tr><td style='font-size:11px;font-weight:700'>{g.get('name','')}</td><td style='font-size:10px'>{g.get('rid','')}</td><td style='font-size:10px;color:#8a9bb5'>{members}</td></tr>"
        html += f"<div style='margin-bottom:12px'><div class='muted' style='margin-bottom:4px'>GROUPS ({len(groups)})</div><table><thead><tr><th>GROUP</th><th>RID</th><th>MEMBERS</th></tr></thead><tbody>{rows}</tbody></table></div>"
    # Shares table
    shares = enum4linux.get("shares", [])
    if shares:
        rows = ""
        for s in shares:
            acc = s.get("access", "NO ACCESS")
            acc_color = "#ff4444" if "WRITE" in acc else "#f5c518" if acc == "READ" else "#8a9bb5"
            rows += f"<tr><td class='mono' style='font-size:11px'>{s.get('name','')}</td><td style='font-size:10px'>{s.get('type','')}</td><td style='color:{acc_color};font-size:10px'>{acc}</td><td style='font-size:10px'>{s.get('comment','')}</td></tr>"
        html += f"<div style='margin-bottom:12px'><div class='muted' style='margin-bottom:4px'>SHARES ({len(shares)})</div><table><thead><tr><th>NAME</th><th>TYPE</th><th>ACCESS</th><th>COMMENT</th></tr></thead><tbody>{rows}</tbody></table></div>"
    # Password policy
    pol = enum4linux.get("password_policy", {})
    if pol:
        html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-top:10px'>"
        ml = pol.get("min_length")
        if ml is not None:
            ml_color = "#ff4444" if ml < 8 else "#f5c518" if ml < 12 else "#3ddc84"
            html += f"<div><span class='muted'>MIN LENGTH</span><br><span style='font-size:18px;font-weight:700;color:{ml_color}'>{ml}</span></div>"
        lt = pol.get("lockout_threshold")
        if lt is not None:
            lt_color = "#ff4444" if lt == 0 else "#f5c518" if lt < 5 else "#3ddc84"
            html += f"<div><span class='muted'>LOCKOUT THRESHOLD</span><br><span style='font-size:18px;font-weight:700;color:{lt_color}'>{lt}</span></div>"
        if pol.get("lockout_duration"):
            html += f"<div><span class='muted'>LOCKOUT DURATION</span><br><span style='font-size:14px;font-weight:700;color:#8a9bb5'>{pol['lockout_duration']} min</span></div>"
        if pol.get("max_age"):
            html += f"<div><span class='muted'>MAX AGE</span><br><span style='font-size:14px;font-weight:700;color:#8a9bb5'>{pol['max_age']} days</span></div>"
        cx = pol.get("complexity")
        if cx is not None:
            cx_color = "#3ddc84" if cx else "#ff4444"
            html += f"<div><span class='muted'>COMPLEXITY</span><br><span style='font-size:14px;font-weight:700;color:{cx_color}'>{'ENABLED' if cx else 'DISABLED'}</span></div>"
        html += "</div>"
    if not html.strip():
        html = "<p class='muted'>Brak danych SMB.</p>"
    return html

def _abuseipdb_html(abuseipdb: dict) -> str:
    if not abuseipdb or abuseipdb.get("skipped") or abuseipdb.get("error"):
        return "<p class='muted'>Brak danych AbuseIPDB.</p>"
    score = abuseipdb.get("abuse_confidence_score", 0)
    score_color = "#3ddc84" if score <= 25 else "#f5c518" if score <= 75 else "#ff4444"
    cats = abuseipdb.get("categories", [])
    cats_html = " ".join(f"<span style='color:#ff4444;font-size:10px;border:1px solid rgba(255,68,68,.3);padding:2px 6px;margin:2px'>{c}</span>" for c in cats) if cats else ""
    return f"""<div style='display:flex;gap:24px;align-items:center;margin-bottom:12px'>
        <div><span class='muted'>ABUSE SCORE</span><br><span style='font-size:28px;font-weight:700;color:{score_color}'>{score}</span><span class='muted'>/100</span></div>
        <div><span class='muted'>ISP</span><br>{abuseipdb.get('isp','—')}</div>
        <div><span class='muted'>COUNTRY</span><br>{abuseipdb.get('country_code','—')}</div>
        <div><span class='muted'>REPORTS</span><br>{abuseipdb.get('total_reports',0)}</div>
    </div>
    {f"<div style='margin-top:8px'>{cats_html}</div>" if cats_html else ""}"""

def _otx_html(otx: dict) -> str:
    if not otx or otx.get("skipped") or otx.get("error"):
        return "<p class='muted'>Brak danych AlienVault OTX.</p>"
    score = otx.get("threat_score", 0)
    score_color = "#3ddc84" if score <= 20 else "#f5c518" if score <= 60 else "#ff4444"
    malware = otx.get("malware_families", [])
    malware_html = " ".join(f"<span style='color:#ff4444;font-size:10px;border:1px solid rgba(255,68,68,.3);padding:2px 6px;margin:2px'>{m}</span>" for m in malware[:10]) if malware else ""
    return f"""<div style='display:flex;gap:24px;align-items:center;margin-bottom:12px'>
        <div><span class='muted'>THREAT SCORE</span><br><span style='font-size:28px;font-weight:700;color:{score_color}'>{score}</span></div>
        <div><span class='muted'>PULSES</span><br>{otx.get('pulse_count',0)}</div>
        <div><span class='muted'>COUNTRY</span><br>{otx.get('country','—')}</div>
        <div><span class='muted'>ASN</span><br>{otx.get('asn','—')}</div>
    </div>
    {f"<div style='margin-top:8px'><span class='muted'>MALWARE FAMILIES:</span> {malware_html}</div>" if malware_html else ""}"""

def _exploitdb_html(exploitdb: dict) -> str:
    exploits = exploitdb.get("exploits", [])
    if not exploits:
        return "<p class='muted'>Brak exploitów w bazie ExploitDB.</p>"
    sev_color = {"critical": "#ff4444", "high": "#ff8c00", "medium": "#f5c518", "low": "#8a9bb5"}
    badges = ""
    for sev in ["critical", "high", "medium", "low"]:
        cnt = exploitdb.get(f"{sev}_count", 0)
        if cnt:
            badges += f"<span style='color:{sev_color[sev]};font-size:10px;border:1px solid {sev_color[sev]};padding:2px 8px;margin-right:6px'>{sev.upper()}: {cnt}</span>"
    rows = ""
    for e in exploits[:20]:
        color = sev_color.get(e.get("severity", ""), "#8a9bb5")
        verified = "✓" if e.get("verified") else ""
        rows += f"<tr><td class='mono'>{e.get('edb_id','')}</td><td>{e.get('title','')}</td><td>{e.get('type','')}</td><td>{e.get('platform','')}</td><td style='color:{color}'>{e.get('severity','').upper()}</td><td style='color:#3ddc84'>{verified}</td></tr>"
    extra = f"<p class='muted'>... i {len(exploits)-20} więcej</p>" if len(exploits) > 20 else ""
    return f"""<div style='margin-bottom:10px'>{badges}</div>
    <table>
        <thead><tr><th>EDB-ID</th><th>TITLE</th><th>TYPE</th><th>PLATFORM</th><th>SEVERITY</th><th>VERIFIED</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>{extra}"""

def _nvd_html(nvd: dict) -> str:
    cves = nvd.get("cves", [])
    if not cves:
        return "<p class='muted'>Brak danych NVD.</p>"
    sev_color = {"CRITICAL": "#ff4444", "HIGH": "#ff8c00", "MEDIUM": "#f5c518", "LOW": "#8a9bb5"}
    badges = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = nvd.get(f"{sev.lower()}_count", 0)
        if cnt:
            badges += f"<span style='color:{sev_color[sev]};font-size:10px;border:1px solid {sev_color[sev]};padding:2px 8px;margin-right:6px'>{sev}: {cnt}</span>"
    rows = ""
    for c in cves[:20]:
        sev = c.get("cvss_severity", "UNKNOWN")
        color = sev_color.get(sev, "#4a8fd4")
        score = c.get("cvss_score")
        score_str = f"{score:.1f}" if score is not None else "—"
        desc = (c.get("description", "") or "")[:120]
        exploit = "<span style='color:#ff4444'>YES</span>" if c.get("exploit_available") else ""
        rows += f"<tr><td class='mono'>{c.get('cve_id','')}</td><td style='color:{color};font-weight:700'>{score_str}</td><td style='color:{color}'>{sev}</td><td style='font-size:10px'>{desc}</td><td>{exploit}</td></tr>"
    extra = f"<p class='muted'>... i {len(cves)-20} więcej</p>" if len(cves) > 20 else ""
    return f"""<div style='margin-bottom:10px'>{badges}</div>
    <table>
        <thead><tr><th>CVE ID</th><th>CVSS</th><th>SEVERITY</th><th>DESCRIPTION</th><th>EXPLOIT</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>{extra}"""

def _whois_html(whois: dict) -> str:
    if not whois or whois.get("error"):
        return "<p class='muted'>Brak danych WHOIS.</p>"
    if whois.get("type") == "domain":
        grid = ""
        for label, key in [("REGISTRAR", "registrar"), ("REGISTERED", "registration_date"), ("EXPIRES", "expiration_date"), ("UPDATED", "last_updated")]:
            val = whois.get(key, "")
            if val:
                val_display = val.split("T")[0] if "T" in str(val) else val
                grid += f"<div><span class='muted'>{label}</span><br><span style='color:#e8f0fc'>{val_display}</span></div>"
        expiry = whois.get("days_until_expiry")
        badges = ""
        if whois.get("is_expired"):
            badges += "<span style='color:#ff4444;border:1px solid #ff4444;padding:2px 8px;font-size:10px'>EXPIRED</span> "
        elif expiry is not None:
            exp_color = "#3ddc84" if expiry > 90 else "#f5c518" if expiry >= 30 else "#ff4444"
            badges += f"<span style='color:{exp_color};border:1px solid {exp_color};padding:2px 8px;font-size:10px'>EXPIRES IN {expiry} DAYS</span> "
        if whois.get("privacy_protected"):
            badges += "<span style='color:#9b59b6;border:1px solid #9b59b6;padding:2px 8px;font-size:10px'>PRIVACY PROTECTED</span>"
        ns = whois.get("name_servers", [])
        ns_html = "<br>".join(f"<span class='mono' style='font-size:11px'>{s}</span>" for s in ns) if ns else ""
        reg = whois.get("registrant", {})
        reg_html = ""
        if reg.get("organization") or reg.get("country"):
            reg_html = f"<div style='margin-top:10px'><span class='muted'>REGISTRANT:</span> {reg.get('organization','')} {reg.get('country','')}</div>"
        return f"""<div style='margin-bottom:10px'>{badges}</div>
        <div style='display:flex;flex-wrap:wrap;gap:16px;margin-bottom:12px'>{grid}</div>
        {reg_html}
        {f"<div style='margin-top:10px'><span class='muted'>NAME SERVERS</span><br>{ns_html}</div>" if ns_html else ""}"""
    else:
        grid = ""
        for label, key in [("ASN", "asn"), ("REGISTRY", "asn_registry"), ("COUNTRY", "asn_country_code"), ("DESCRIPTION", "asn_description")]:
            val = whois.get(key, "")
            if val:
                grid += f"<div><span class='muted'>{label}</span><br><span style='color:#e8f0fc'>{val}</span></div>"
        net = whois.get("network", {})
        if net.get("cidr"):
            grid += f"<div><span class='muted'>NETWORK</span><br><span style='color:#e8f0fc'>{net['cidr']}</span></div>"
        return f"<div style='display:flex;flex-wrap:wrap;gap:16px'>{grid}</div>"

def _dnsrecon_html(dnsrecon: dict) -> str:
    if not dnsrecon or dnsrecon.get("skipped"):
        return "<p class='muted'>Brak danych DNSRecon.</p>"
    html = ""
    # Zone transfer alert
    if dnsrecon.get("zone_transfer"):
        html += "<div style='border:1px solid #ff4444;background:rgba(255,68,68,.12);color:#ff4444;padding:10px 14px;margin-bottom:12px;font-size:12px'>⚠ CRITICAL: ZONE TRANSFER POSSIBLE</div>"
    # Missing SPF/DMARC warning
    missing = []
    if not dnsrecon.get("spf_configured"):
        missing.append("SPF")
    if not dnsrecon.get("dmarc_configured"):
        missing.append("DMARC")
    if missing:
        html += f"<div style='border:1px solid #f5c518;background:rgba(245,197,24,.08);color:#f5c518;padding:10px 14px;margin-bottom:12px;font-size:12px'>⚠ Missing: {', '.join(missing)}</div>"
    # SPF/DMARC badges
    spf_ok = dnsrecon.get("spf_configured", False)
    dmarc_ok = dnsrecon.get("dmarc_configured", False)
    spf_col = "#3ddc84" if spf_ok else "#ff4444"
    dmarc_col = "#3ddc84" if dmarc_ok else "#ff4444"
    html += f"<div style='margin-bottom:12px'><span style='color:{spf_col};font-size:10px;border:1px solid {spf_col};padding:2px 8px;margin-right:6px'>SPF {'✓' if spf_ok else '✗'}</span>"
    html += f"<span style='color:{dmarc_col};font-size:10px;border:1px solid {dmarc_col};padding:2px 8px'>DMARC {'✓' if dmarc_ok else '✗'}</span></div>"
    # A Records
    a_recs = dnsrecon.get("a_records", [])
    if a_recs:
        rows = "".join(f"<tr><td>{r.get('hostname','')}</td><td class='mono'>{r.get('ip','')}</td><td>{r.get('type','A')}</td></tr>" for r in a_recs[:20])
        html += f"<div class='muted' style='margin-bottom:4px'>A / AAAA RECORDS ({len(a_recs)})</div><table><thead><tr><th>HOSTNAME</th><th>IP</th><th>TYPE</th></tr></thead><tbody>{rows}</tbody></table>"
    # MX Records
    mx_recs = dnsrecon.get("mx_records", [])
    if mx_recs:
        rows = "".join(f"<tr><td>{r.get('exchange','')}</td><td>{r.get('priority','')}</td></tr>" for r in mx_recs)
        html += f"<div class='muted' style='margin:10px 0 4px'>MX RECORDS ({len(mx_recs)})</div><table><thead><tr><th>EXCHANGE</th><th>PRIORITY</th></tr></thead><tbody>{rows}</tbody></table>"
    # SRV Records
    srv_recs = dnsrecon.get("srv_records", [])
    if srv_recs:
        rows = "".join(f"<tr><td>{r.get('service','')}</td><td>{r.get('target','')}</td><td>{r.get('port','')}</td><td>{r.get('priority','')}</td></tr>" for r in srv_recs[:20])
        html += f"<div class='muted' style='margin:10px 0 4px'>SRV RECORDS ({len(srv_recs)})</div><table><thead><tr><th>SERVICE</th><th>TARGET</th><th>PORT</th><th>PRIORITY</th></tr></thead><tbody>{rows}</tbody></table>"
    # NS Records
    ns_recs = dnsrecon.get("ns_records", [])
    if ns_recs:
        ns_html = " ".join(f"<span class='mono' style='font-size:11px;margin-right:8px'>{ns}</span>" for ns in ns_recs)
        html += f"<div class='muted' style='margin:10px 0 4px'>NAME SERVERS ({len(ns_recs)})</div><div>{ns_html}</div>"
    # Subdomains
    subs = dnsrecon.get("subdomains", [])
    if subs:
        subs_html = " ".join(f"<span class='mono' style='font-size:10px;color:#7ab3e8'>{s}</span>" for s in subs[:30])
        extra = f" <span class='muted'>... i {len(subs)-30} więcej</span>" if len(subs) > 30 else ""
        html += f"<div class='muted' style='margin:10px 0 4px'>SUBDOMAINS ({len(subs)})</div><div>{subs_html}{extra}</div>"
    if not html:
        html = "<p class='muted'>Brak danych DNS.</p>"
    return html

def _amass_html(amass: dict) -> str:
    if not amass or amass.get("skipped") or not amass.get("total_count"):
        return "<p class='muted'>Brak danych Amass.</p>"
    html = ""
    # Stats
    html += f"<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>SUBDOMAINS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{amass.get('total_count',0)}</span></div>"
    html += f"<div><span class='muted'>UNIQUE IPs</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{len(amass.get('ip_addresses',[]))}</span></div>"
    html += f"<div><span class='muted'>ASNs</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{len(amass.get('asns',[]))}</span></div>"
    html += f"<div><span class='muted'>SOURCES</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{len(amass.get('sources',[]))}</span></div>"
    html += "</div>"
    # Sources
    sources = amass.get("sources", [])
    if sources:
        src_html = " ".join(f"<span style='color:#9b59b6;font-size:10px;border:1px solid rgba(155,89,182,.4);padding:2px 6px;margin:2px'>{s}</span>" for s in sources)
        html += f"<div style='margin-bottom:12px'><span class='muted'>SOURCES:</span> {src_html}</div>"
    # Subdomains
    subs = amass.get("subdomains", [])
    if subs:
        subs_html = " ".join(f"<span class='mono' style='font-size:10px;color:#7ab3e8'>{s}</span>" for s in subs[:50])
        extra = f" <span class='muted'>... i {len(subs)-50} więcej</span>" if len(subs) > 50 else ""
        html += f"<div class='muted' style='margin-bottom:4px'>SUBDOMAINS ({len(subs)})</div><div>{subs_html}{extra}</div>"
    # IPs
    ips = amass.get("ip_addresses", [])
    if ips:
        ips_html = " ".join(f"<span class='mono' style='font-size:10px'>{ip}</span>" for ip in ips[:30])
        extra = f" <span class='muted'>... i {len(ips)-30} więcej</span>" if len(ips) > 30 else ""
        html += f"<div class='muted' style='margin:10px 0 4px'>IP ADDRESSES ({len(ips)})</div><div>{ips_html}{extra}</div>"
    return html

def _subfinder_html(subfinder: dict) -> str:
    if not subfinder or subfinder.get("skipped") or not subfinder.get("total_count"):
        return "<p class='muted'>Brak danych Subfinder.</p>"
    html = ""
    # Stats
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>SUBDOMAINS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{subfinder.get('total_count',0)}</span></div>"
    html += f"<div><span class='muted'>SOURCES</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{len(subfinder.get('sources',[]))}</span></div>"
    ips = subfinder.get("ip_addresses", [])
    if ips:
        html += f"<div><span class='muted'>UNIQUE IPs</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{len(ips)}</span></div>"
    html += "</div>"
    # Sources
    sources = subfinder.get("sources", [])
    if sources:
        src_html = " ".join(f"<span style='color:#2ecc71;font-size:10px;border:1px solid rgba(46,204,113,.4);padding:2px 6px;margin:2px'>{s}</span>" for s in sources)
        html += f"<div style='margin-bottom:12px'><span class='muted'>SOURCES:</span> {src_html}</div>"
    # Subdomains
    subs = subfinder.get("subdomains", [])
    if subs:
        subs_html = " ".join(f"<span class='mono' style='font-size:10px;color:#7ab3e8'>{s}</span>" for s in subs[:60])
        extra = f" <span class='muted'>... i {len(subs)-60} więcej</span>" if len(subs) > 60 else ""
        html += f"<div class='muted' style='margin-bottom:4px'>SUBDOMAINS ({len(subs)})</div><div>{subs_html}{extra}</div>"
    # IPs
    if ips:
        ips_html = " ".join(f"<span class='mono' style='font-size:10px'>{ip}</span>" for ip in ips[:30])
        extra = f" <span class='muted'>... i {len(ips)-30} więcej</span>" if len(ips) > 30 else ""
        html += f"<div class='muted' style='margin:10px 0 4px'>IP ADDRESSES ({len(ips)})</div><div>{ips_html}{extra}</div>"
    return html

def _httpx_html(httpx: dict) -> str:
    if not httpx or httpx.get("skipped") or not httpx.get("total_results"):
        return "<p class='muted'>Brak danych httpx.</p>"
    summary = httpx.get("summary", {})
    html = ""
    # Stats
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>PROBED HOSTS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('probed', 0)}</span></div>"
    live = summary.get("live", 0)
    live_col = "#3ddc84" if live else "#ff4444"
    html += f"<div><span class='muted'>LIVE HOSTS</span><br><span style='font-size:20px;font-weight:700;color:{live_col}'>{live}</span></div>"
    html += f"<div><span class='muted'>TECHNOLOGIES</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('technologies_count', 0)}</span></div>"
    html += f"<div><span class='muted'>WEB SERVERS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('servers_count', 0)}</span></div>"
    html += "</div>"
    # Technologies badges
    techs = httpx.get("technologies", [])
    if techs:
        tech_html = " ".join(f"<span style='color:#4a8fd4;font-size:10px;border:1px solid rgba(74,143,212,.4);padding:2px 6px;margin:2px'>{t}</span>" for t in techs[:30])
        extra = f" <span class='muted'>... i {len(techs)-30} więcej</span>" if len(techs) > 30 else ""
        html += f"<div style='margin-bottom:12px'><span class='muted'>DETECTED TECHNOLOGIES:</span> {tech_html}{extra}</div>"
    # Web servers badges
    servers = httpx.get("web_servers", [])
    if servers:
        srv_html = " ".join(f"<span style='color:#9b59b6;font-size:10px;border:1px solid rgba(155,89,182,.4);padding:2px 6px;margin:2px'>{s}</span>" for s in servers)
        html += f"<div style='margin-bottom:12px'><span class='muted'>WEB SERVERS:</span> {srv_html}</div>"
    # Results table
    results = httpx.get("results", [])
    if results:
        status_color = lambda c: "#3ddc84" if 200 <= c < 300 else "#f5c518" if 300 <= c < 400 else "#ff8c00" if 400 <= c < 500 else "#ff4444"
        rows = ""
        for r in results[:40]:
            sc = r.get("status_code", 0)
            color = status_color(sc)
            title = (r.get("title", "") or "")[:60]
            tech_str = ", ".join(r.get("technologies", [])[:3])
            url = r.get("url", "")[:80]
            server = r.get("web_server", "")
            cdn = r.get("cdn", "")
            cdn_html = f" <span style='color:#9b59b6;font-size:9px'>[CDN: {cdn}]</span>" if cdn else ""
            rows += f"<tr><td style='color:{color};font-weight:700'>{sc}</td><td class='mono' style='font-size:10px'>{url}</td><td style='font-size:10px'>{title}</td><td style='font-size:10px'>{server}{cdn_html}</td><td style='font-size:10px'>{tech_str}</td></tr>"
        extra = f"<p class='muted'>... i {len(results)-40} więcej</p>" if len(results) > 40 else ""
        html += f"""<table>
            <thead><tr><th>STATUS</th><th>URL</th><th>TITLE</th><th>SERVER</th><th>TECHNOLOGIES</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>{extra}"""
    return html

def _naabu_html(naabu: dict) -> str:
    if not naabu or naabu.get("skipped") or not naabu.get("total_open_ports"):
        return "<p class='muted'>Brak danych Naabu.</p>"
    summary = naabu.get("summary", {})
    html = ""
    # Stats
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>SCANNED HOSTS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('scanned', 0)}</span></div>"
    hosts_open = summary.get("hosts_with_ports", 0)
    hosts_col = "#ff8c00" if hosts_open else "#3ddc84"
    html += f"<div><span class='muted'>HOSTS WITH OPEN PORTS</span><br><span style='font-size:20px;font-weight:700;color:{hosts_col}'>{hosts_open}</span></div>"
    html += f"<div><span class='muted'>TOTAL OPEN PORTS</span><br><span style='font-size:20px;font-weight:700;color:#ff8c00'>{summary.get('total_open', 0)}</span></div>"
    html += f"<div><span class='muted'>UNIQUE PORTS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('unique_ports', 0)}</span></div>"
    html += "</div>"
    # Port categories
    categories = naabu.get("categories", {})
    if categories:
        cat_colors = {"web": "#3ddc84", "mail": "#f5c518", "database": "#ff4444", "remote": "#ff8c00", "file": "#9b59b6", "dns": "#4a8fd4"}
        cat_html = ""
        for cat, ports in categories.items():
            color = cat_colors.get(cat, "#4a8fd4")
            ports_str = ", ".join(str(p) for p in ports)
            cat_html += f"<span style='color:{color};font-size:10px;border:1px solid {color};padding:2px 8px;margin:2px'>{cat.upper()}: {ports_str}</span> "
        html += f"<div style='margin-bottom:12px'><span class='muted'>PORT CATEGORIES:</span> {cat_html}</div>"
    # Unique ports badges
    unique_ports = naabu.get("unique_ports", [])
    if unique_ports:
        ports_html = " ".join(f"<span class='mono' style='font-size:10px;color:#e8f0fc;border:1px solid rgba(74,143,212,.3);padding:2px 6px;margin:2px'>{p}</span>" for p in unique_ports[:50])
        extra = f" <span class='muted'>... i {len(unique_ports)-50} więcej</span>" if len(unique_ports) > 50 else ""
        html += f"<div style='margin-bottom:12px'><span class='muted'>UNIQUE OPEN PORTS ({len(unique_ports)})</span><br>{ports_html}{extra}</div>"
    # Results table
    results = naabu.get("results", [])
    if results:
        rows = ""
        for r in results[:50]:
            port = r.get("port", 0)
            # Color high-risk ports
            p_color = "#ff4444" if port in (3306, 5432, 1433, 27017, 6379, 23, 445, 139) else "#ff8c00" if port in (22, 3389, 5900, 21) else "#3ddc84" if port in (80, 443) else "#e8f0fc"
            rows += f"<tr><td class='mono' style='color:{p_color};font-weight:700'>{port}</td><td>{r.get('host','')}</td><td>{r.get('protocol','tcp')}</td></tr>"
        extra = f"<p class='muted'>... i {len(results)-50} więcej</p>" if len(results) > 50 else ""
        html += f"""<table>
            <thead><tr><th>PORT</th><th>HOST</th><th>PROTOCOL</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>{extra}"""
    return html

def _katana_html(katana: dict) -> str:
    if not katana or katana.get("skipped") or not katana.get("total_urls"):
        return "<p class='muted'>Brak danych Katana.</p>"
    summary = katana.get("summary", {})
    html = ""
    # Stats
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>TOTAL URLs</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('total_urls', 0)}</span></div>"
    html += f"<div><span class='muted'>ENDPOINTS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('endpoints', 0)}</span></div>"
    js_cnt = summary.get("js_files", 0)
    html += f"<div><span class='muted'>JS FILES</span><br><span style='font-size:20px;font-weight:700;color:#f5c518'>{js_cnt}</span></div>"
    forms_cnt = summary.get("forms", 0)
    forms_col = "#ff8c00" if forms_cnt else "#3ddc84"
    html += f"<div><span class='muted'>FORMS</span><br><span style='font-size:20px;font-weight:700;color:{forms_col}'>{forms_cnt}</span></div>"
    api_cnt = summary.get("api_endpoints", 0)
    html += f"<div><span class='muted'>API ENDPOINTS</span><br><span style='font-size:20px;font-weight:700;color:#9b59b6'>{api_cnt}</span></div>"
    interesting_cnt = summary.get("interesting_files", 0)
    int_col = "#ff4444" if interesting_cnt else "#3ddc84"
    html += f"<div><span class='muted'>INTERESTING FILES</span><br><span style='font-size:20px;font-weight:700;color:{int_col}'>{interesting_cnt}</span></div>"
    html += "</div>"
    # Interesting files (security-relevant)
    interesting = katana.get("interesting_files", [])
    if interesting:
        rows = "".join(f"<tr><td class='mono' style='font-size:10px;color:#ff4444'>{f.get('url','')[:100]}</td><td>{f.get('method','GET')}</td><td>{f.get('status_code','')}</td></tr>" for f in interesting[:20])
        html += f"<div class='muted' style='margin-bottom:4px'>INTERESTING FILES ({len(interesting)})</div>"
        html += f"<table><thead><tr><th>URL</th><th>METHOD</th><th>STATUS</th></tr></thead><tbody>{rows}</tbody></table>"
    # API endpoints
    api = katana.get("api_endpoints", [])
    if api:
        rows = "".join(f"<tr><td class='mono' style='font-size:10px;color:#9b59b6'>{e.get('url','')[:100]}</td><td>{e.get('method','GET')}</td><td>{e.get('status_code','')}</td></tr>" for e in api[:20])
        extra = f"<p class='muted'>... i {len(api)-20} więcej</p>" if len(api) > 20 else ""
        html += f"<div class='muted' style='margin:10px 0 4px'>API ENDPOINTS ({len(api)})</div>"
        html += f"<table><thead><tr><th>URL</th><th>METHOD</th><th>STATUS</th></tr></thead><tbody>{rows}</tbody></table>{extra}"
    # Forms
    forms_list = katana.get("forms", [])
    if forms_list:
        rows = "".join(f"<tr><td class='mono' style='font-size:10px;color:#ff8c00'>{f.get('url','')[:100]}</td><td>{f.get('method','GET')}</td></tr>" for f in forms_list[:15])
        html += f"<div class='muted' style='margin:10px 0 4px'>FORMS ({len(forms_list)})</div>"
        html += f"<table><thead><tr><th>URL</th><th>METHOD</th></tr></thead><tbody>{rows}</tbody></table>"
    # JS files
    js = katana.get("js_files", [])
    if js:
        js_html = " ".join(f"<span class='mono' style='font-size:9px;color:#f5c518'>{urlparse_path(f.get('url',''))}</span>" for f in js[:30])
        extra = f" <span class='muted'>... i {len(js)-30} więcej</span>" if len(js) > 30 else ""
        html += f"<div class='muted' style='margin:10px 0 4px'>JAVASCRIPT FILES ({len(js)})</div><div>{js_html}{extra}</div>"
    # Endpoints sample
    eps = katana.get("endpoints", [])
    if eps:
        rows = "".join(f"<tr><td class='mono' style='font-size:10px'>{e.get('url','')[:100]}</td><td>{e.get('method','GET')}</td><td>{e.get('status_code','')}</td></tr>" for e in eps[:30])
        extra = f"<p class='muted'>... i {len(eps)-30} więcej</p>" if len(eps) > 30 else ""
        html += f"<div class='muted' style='margin:10px 0 4px'>CRAWLED ENDPOINTS ({len(eps)})</div>"
        html += f"<table><thead><tr><th>URL</th><th>METHOD</th><th>STATUS</th></tr></thead><tbody>{rows}</tbody></table>{extra}"
    return html

def urlparse_path(url):
    """Extract path from URL for display."""
    try:
        from urllib.parse import urlparse as _up
        return _up(url).path or url
    except Exception:
        return url

def _dnsx_html(dnsx: dict) -> str:
    if not dnsx or dnsx.get("skipped") or not dnsx.get("total_resolved"):
        return "<p class='muted'>Brak danych dnsx.</p>"
    summary = dnsx.get("summary", {})
    html = ""
    # Stats
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>QUERIED</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('queried', 0)}</span></div>"
    html += f"<div><span class='muted'>RESOLVED</span><br><span style='font-size:20px;font-weight:700;color:#3ddc84'>{summary.get('resolved', 0)}</span></div>"
    unresolved = summary.get("unresolved", 0)
    html += f"<div><span class='muted'>UNRESOLVED</span><br><span style='font-size:20px;font-weight:700;color:#ff8c00'>{unresolved}</span></div>"
    html += f"<div><span class='muted'>UNIQUE IPs</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('unique_ips', 0)}</span></div>"
    html += f"<div><span class='muted'>MX SERVERS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('mx_servers', 0)}</span></div>"
    html += f"<div><span class='muted'>NS SERVERS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{summary.get('ns_servers', 0)}</span></div>"
    html += "</div>"
    # Record type badges
    record_types = dnsx.get("record_types", [])
    if record_types:
        rt_html = " ".join(f"<span style='color:#4a8fd4;font-size:10px;border:1px solid rgba(74,143,212,.4);padding:2px 8px;margin:2px'>{rt}</span>" for rt in record_types)
        html += f"<div style='margin-bottom:12px'><span class='muted'>RECORD TYPES:</span> {rt_html}</div>"
    # Dangling CNAMEs (subdomain takeover risk)
    dangling = dnsx.get("dangling_cnames", [])
    if dangling:
        rows = "".join(f"<tr><td style='color:#ff4444;font-weight:700'>{d.get('host','')}</td><td class='mono' style='font-size:10px'>{', '.join(d.get('cname', []))}</td></tr>" for d in dangling[:20])
        html += f"<div style='margin-bottom:12px;border:1px solid rgba(255,68,68,.3);padding:10px'><span style='color:#ff4444;font-size:11px;font-weight:700'>DANGLING CNAMEs — POTENTIAL SUBDOMAIN TAKEOVER ({len(dangling)})</span>"
        html += f"<table><thead><tr><th>HOST</th><th>CNAME TARGET</th></tr></thead><tbody>{rows}</tbody></table></div>"
    # Security TXT records
    sec_txt = dnsx.get("security_txt", [])
    if sec_txt:
        txt_html = "".join(f"<div style='font-size:10px;padding:4px 8px;border-bottom:1px solid rgba(74,143,212,.1);word-break:break-all'>{t}</div>" for t in sec_txt[:15])
        html += f"<div class='muted' style='margin-bottom:4px'>SECURITY-RELEVANT TXT RECORDS ({len(sec_txt)})</div>{txt_html}"
    # MX servers
    mx = dnsx.get("all_mx", [])
    if mx:
        mx_html = " ".join(f"<span class='mono' style='font-size:10px;color:#f5c518'>{m}</span>" for m in mx[:20])
        html += f"<div class='muted' style='margin:10px 0 4px'>MX SERVERS ({len(mx)})</div><div>{mx_html}</div>"
    # NS servers
    ns = dnsx.get("all_ns", [])
    if ns:
        ns_html = " ".join(f"<span class='mono' style='font-size:10px;color:#9b59b6'>{n}</span>" for n in ns[:20])
        html += f"<div class='muted' style='margin:10px 0 4px'>NS SERVERS ({len(ns)})</div><div>{ns_html}</div>"
    # Results table (top entries)
    results = dnsx.get("results", [])
    if results:
        rows = ""
        for r in results[:40]:
            a_str = ", ".join(r.get("a", [])[:3])
            cname_str = ", ".join(r.get("cname", [])[:2])
            rows += f"<tr><td class='mono' style='font-size:10px'>{r.get('host','')}</td><td style='font-size:10px'>{a_str}</td><td style='font-size:10px;color:#f5c518'>{cname_str}</td></tr>"
        extra = f"<p class='muted'>... i {len(results)-40} więcej</p>" if len(results) > 40 else ""
        html += f"<div class='muted' style='margin:10px 0 4px'>DNS RECORDS ({len(results)})</div>"
        html += f"<table><thead><tr><th>HOST</th><th>A RECORDS</th><th>CNAME</th></tr></thead><tbody>{rows}</tbody></table>{extra}"
    return html

def _netdiscover_html(netdiscover: dict) -> str:
    if not netdiscover or netdiscover.get("skipped") or not netdiscover.get("total_hosts"):
        return "<p class='muted'>Brak danych netdiscover.</p>"
    html = ""
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>TOTAL HOSTS</span><br><span style='font-size:20px;font-weight:700;color:#3ddc84'>{netdiscover.get('total_hosts', 0)}</span></div>"
    html += f"<div><span class='muted'>NETWORK RANGE</span><br><span style='font-size:16px;font-weight:700;color:#e8f0fc;font-family:Courier New,monospace'>{netdiscover.get('network_range', 'N/A')}</span></div>"
    html += "</div>"
    hosts = netdiscover.get("hosts", [])
    if hosts:
        rows = ""
        for h in hosts[:50]:
            rows += f"<tr><td class='mono' style='font-size:11px;color:#3ddc84'>{h.get('ip','')}</td><td class='mono' style='font-size:10px'>{h.get('mac','')}</td><td style='font-size:10px'>{h.get('vendor','')}</td><td style='font-size:10px;color:#8a9bb5'>{h.get('hostname','') or '—'}</td></tr>"
        extra = f"<p class='muted'>... i {len(hosts)-50} więcej</p>" if len(hosts) > 50 else ""
        html += f"<table><thead><tr><th>IP</th><th>MAC</th><th>VENDOR</th><th>HOSTNAME</th></tr></thead><tbody>{rows}</tbody></table>{extra}"
    return html

def _arpscan_html(arpscan: dict) -> str:
    if not arpscan or arpscan.get("skipped") or not arpscan.get("total_hosts"):
        return "<p class='muted'>Brak danych arp-scan.</p>"
    html = ""
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>TOTAL HOSTS</span><br><span style='font-size:20px;font-weight:700;color:#3ddc84'>{arpscan.get('total_hosts', 0)}</span></div>"
    html += f"<div><span class='muted'>NETWORK RANGE</span><br><span style='font-size:16px;font-weight:700;color:#e8f0fc;font-family:Courier New,monospace'>{arpscan.get('network_range', 'N/A')}</span></div>"
    duplicates = arpscan.get("duplicates", [])
    if duplicates:
        html += f"<div><span class='muted' style='color:#ff4444'>DUPLICATES (ARP SPOOFING?)</span><br><span style='font-size:20px;font-weight:700;color:#ff4444'>{len(duplicates)}</span></div>"
    html += "</div>"
    # Duplicates warning
    if duplicates:
        rows = ""
        for d in duplicates[:20]:
            rows += f"<tr><td style='color:#ff4444;font-weight:700'>{d.get('ip','')}</td><td class='mono' style='font-size:10px'>{d.get('mac_1','')}</td><td style='font-size:10px'>{d.get('vendor_1','')}</td><td class='mono' style='font-size:10px'>{d.get('mac_2','')}</td><td style='font-size:10px'>{d.get('vendor_2','')}</td></tr>"
        html += f"<div style='border:1px solid rgba(255,68,68,.3);padding:10px;margin-bottom:12px'><span style='color:#ff4444;font-size:11px;font-weight:700'>DUPLICATE IPs — POSSIBLE ARP SPOOFING ({len(duplicates)})</span>"
        html += f"<table><thead><tr><th>IP</th><th>MAC #1</th><th>VENDOR #1</th><th>MAC #2</th><th>VENDOR #2</th></tr></thead><tbody>{rows}</tbody></table></div>"
    # Hosts table
    hosts = arpscan.get("hosts", [])
    if hosts:
        rows = ""
        for h in hosts[:50]:
            rows += f"<tr><td class='mono' style='font-size:11px;color:#3ddc84'>{h.get('ip','')}</td><td class='mono' style='font-size:10px'>{h.get('mac','')}</td><td style='font-size:10px'>{h.get('vendor','')}</td></tr>"
        extra = f"<p class='muted'>... i {len(hosts)-50} więcej</p>" if len(hosts) > 50 else ""
        html += f"<table><thead><tr><th>IP</th><th>MAC</th><th>VENDOR</th></tr></thead><tbody>{rows}</tbody></table>{extra}"
    return html

def _fping_html(fping: dict) -> str:
    if not fping or fping.get("skipped") or not fping.get("total_alive"):
        return "<p class='muted'>Brak danych fping.</p>"
    html = ""
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>ALIVE</span><br><span style='font-size:20px;font-weight:700;color:#3ddc84'>{fping.get('total_alive', 0)}</span></div>"
    html += f"<div><span class='muted'>UNREACHABLE</span><br><span style='font-size:20px;font-weight:700;color:#ff4444'>{fping.get('total_unreachable', 0)}</span></div>"
    html += f"<div><span class='muted'>TOTAL SCANNED</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{fping.get('total_scanned', 0)}</span></div>"
    html += f"<div><span class='muted'>NETWORK RANGE</span><br><span style='font-size:14px;font-weight:700;color:#e8f0fc;font-family:Courier New,monospace'>{fping.get('network_range', 'N/A')}</span></div>"
    avg_lat = fping.get("avg_latency_ms")
    if avg_lat is not None:
        html += f"<div><span class='muted'>AVG LATENCY</span><br><span style='font-size:20px;font-weight:700;color:#f5c518'>{avg_lat} ms</span></div>"
    max_lat = fping.get("max_latency_ms")
    if max_lat is not None:
        html += f"<div><span class='muted'>MAX LATENCY</span><br><span style='font-size:20px;font-weight:700;color:#ff8c00'>{max_lat} ms</span></div>"
    unstable = fping.get("unstable_count", 0)
    if unstable:
        html += f"<div><span class='muted' style='color:#ff8c00'>UNSTABLE</span><br><span style='font-size:20px;font-weight:700;color:#ff8c00'>{unstable}</span></div>"
    html += "</div>"
    # Latency table
    latency = fping.get("latency", [])
    if latency:
        rows = ""
        for l in latency[:50]:
            status = l.get("status", "stable")
            sc = "#3ddc84" if status == "stable" else "#ff8c00" if status == "unstable" else "#ff4444"
            min_ms = l.get("min_ms", "—")
            avg_ms = l.get("avg_ms", "—")
            max_ms = l.get("max_ms", "—")
            loss_color = "#ff8c00" if l.get("loss_pct", 0) > 0 else "#8a9bb5"
            rows += f"<tr><td class='mono' style='font-size:11px;color:#3ddc84'>{l.get('ip','')}</td><td>{l.get('sent','')}</td><td>{l.get('recv','')}</td><td style='color:{loss_color}'>{l.get('loss_pct',0)}%</td><td style='font-size:10px'>{min_ms}</td><td style='font-size:10px'>{avg_ms}</td><td style='font-size:10px'>{max_ms}</td><td style='color:{sc};font-weight:700;font-size:10px;text-transform:uppercase'>{status}</td></tr>"
        extra = f"<p class='muted'>... i {len(latency)-50} więcej</p>" if len(latency) > 50 else ""
        html += f"<table><thead><tr><th>IP</th><th>SENT</th><th>RECV</th><th>LOSS %</th><th>MIN ms</th><th>AVG ms</th><th>MAX ms</th><th>STATUS</th></tr></thead><tbody>{rows}</tbody></table>{extra}"
    return html

def _traceroute_html(traceroute: dict) -> str:
    if not traceroute or traceroute.get("skipped") or not traceroute.get("total_hops"):
        return "<p class='muted'>Brak danych traceroute.</p>"
    html = ""
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    html += f"<div><span class='muted'>TOTAL HOPS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{traceroute.get('total_hops', 0)}</span></div>"
    html += f"<div><span class='muted'>DESTINATION</span><br><span style='font-size:13px;font-weight:700;color:#e8f0fc;font-family:Courier New,monospace'>{traceroute.get('destination', 'N/A')}</span></div>"
    html += f"<div><span class='muted'>DESTINATION IP</span><br><span style='font-size:14px;font-weight:700;color:#3ddc84;font-family:Courier New,monospace'>{traceroute.get('destination_ip', 'N/A')}</span></div>"
    reached = traceroute.get("reached", False)
    rc = "#3ddc84" if reached else "#ff4444"
    html += f"<div><span class='muted'>REACHED</span><br><span style='font-size:20px;font-weight:700;color:{rc}'>{'YES' if reached else 'NO'}</span></div>"
    avg_rtt = traceroute.get("avg_rtt_ms")
    if avg_rtt is not None:
        html += f"<div><span class='muted'>AVG RTT</span><br><span style='font-size:20px;font-weight:700;color:#f5c518'>{avg_rtt} ms</span></div>"
    max_rtt = traceroute.get("max_rtt_ms")
    if max_rtt is not None:
        html += f"<div><span class='muted'>MAX RTT</span><br><span style='font-size:20px;font-weight:700;color:#ff8c00'>{max_rtt} ms</span></div>"
    timeout_hops = traceroute.get("timeout_hops", 0)
    if timeout_hops:
        html += f"<div><span class='muted' style='color:#ff8c00'>TIMEOUTS</span><br><span style='font-size:20px;font-weight:700;color:#ff8c00'>{timeout_hops}</span></div>"
    html += "</div>"
    # Issues
    issues = traceroute.get("issues", [])
    if issues:
        iss_html = "".join(f"<div style='font-size:11px;padding:3px 0;color:#8a9bb5;border-bottom:1px solid rgba(74,143,212,.1)'>{iss}</div>" for iss in issues[:20])
        html += f"<div style='border:1px solid rgba(255,140,0,.3);padding:10px;margin-bottom:12px'><span style='color:#ff8c00;font-size:11px;font-weight:700'>PATH ISSUES ({len(issues)})</span>{iss_html}</div>"
    # Hops table
    hops = traceroute.get("hops", [])
    if hops:
        rows = ""
        for h in hops:
            ip_color = "#3ddc84" if h.get("ip") else "#ff4444"
            ip_text = h.get("ip") or "* * *"
            loss_color = "#ff8c00" if h.get("loss") else "#8a9bb5"
            rows += f"<tr><td style='font-weight:700;color:#4a8fd4'>{h.get('hop','')}</td><td class='mono' style='font-size:11px;color:{ip_color}'>{ip_text}</td><td style='font-size:10px'>{h.get('min_rtt_ms','—') if h.get('min_rtt_ms') is not None else '—'}</td><td style='font-size:10px'>{h.get('avg_rtt_ms','—') if h.get('avg_rtt_ms') is not None else '—'}</td><td style='font-size:10px'>{h.get('max_rtt_ms','—') if h.get('max_rtt_ms') is not None else '—'}</td><td style='font-size:10px;color:{loss_color}'>{'YES' if h.get('loss') else '—'}</td></tr>"
        html += f"<table><thead><tr><th>HOP</th><th>IP</th><th>MIN ms</th><th>AVG ms</th><th>MAX ms</th><th>LOSS</th></tr></thead><tbody>{rows}</tbody></table>"
    return html

def _nbtscan_html(nbtscan: dict) -> str:
    if not nbtscan or nbtscan.get("skipped") or not nbtscan.get("total_hosts"):
        return "<p class='muted'>Brak danych NBTscan.</p>"
    html = ""
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    html += f"<div><span class='muted'>TOTAL HOSTS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{nbtscan.get('total_hosts', 0)}</span></div>"
    html += f"<div><span class='muted'>NETWORK RANGE</span><br><span style='font-size:13px;font-weight:700;color:#4a8fd4;font-family:Courier New,monospace'>{nbtscan.get('network_range', 'N/A')}</span></div>"
    wgs = nbtscan.get("workgroups", [])
    if wgs:
        html += f"<div><span class='muted'>WORKGROUPS</span><br><span style='font-size:20px;font-weight:700;color:#7ab3e8'>{len(wgs)}</span></div>"
    html += f"<div><span class='muted'>FILE SERVERS</span><br><span style='font-size:20px;font-weight:700;color:#f5c518'>{nbtscan.get('total_servers', 0)}</span></div>"
    dcs = nbtscan.get("total_dcs", 0)
    dc_color = "#ff4444" if dcs > 0 else "#8a9bb5"
    html += f"<div><span class='muted'>DOMAIN CONTROLLERS</span><br><span style='font-size:20px;font-weight:700;color:{dc_color}'>{dcs}</span></div>"
    html += "</div>"
    # Workgroup badges
    if wgs:
        badges = " ".join(f"<span style='font-size:10px;color:#7ab3e8;border:1px solid rgba(122,179,232,.3);padding:2px 8px;margin-right:4px'>{w}</span>" for w in wgs)
        html += f"<div style='margin-bottom:10px'>{badges}</div>"
    # DC warning
    dc_list = nbtscan.get("domain_controllers", [])
    if dc_list:
        dc_items = "".join(f"<div style='font-size:11px;padding:3px 0;color:#ff8c00;border-bottom:1px solid rgba(255,68,68,.1)'>{ip}</div>" for ip in dc_list[:10])
        html += f"<div style='border:1px solid rgba(255,68,68,.3);padding:10px;margin-bottom:12px'><span style='color:#ff4444;font-size:11px;font-weight:700'>DOMAIN CONTROLLERS DETECTED</span>{dc_items}</div>"
    # Hosts table
    hosts = nbtscan.get("hosts", [])
    if hosts:
        rows = ""
        for h in hosts[:50]:
            svcs = h.get("services", [])
            svc_badges = " ".join(f"<span style='font-size:9px;color:#3ddc84;border:1px solid rgba(61,220,132,.3);padding:1px 5px'>{s}</span>" for s in svcs)
            is_dc = h.get("is_dc", False)
            ip_color = "#ff4444" if is_dc else "#3ddc84"
            rows += f"<tr><td class='mono' style='font-size:11px;color:{ip_color}'>{h.get('ip','')}</td><td style='font-size:11px;color:#e8f0fc'>{h.get('netbios_name','')}</td><td style='font-size:10px;color:#8a9bb5'>{h.get('mac','')}</td><td style='font-size:10px'>{h.get('workgroup','')}</td><td>{svc_badges}</td></tr>"
        extra = f"<p class='muted'>... i {len(hosts)-50} więcej</p>" if len(hosts) > 50 else ""
        html += f"<table><thead><tr><th>IP</th><th>NETBIOS NAME</th><th>MAC</th><th>WORKGROUP</th><th>SERVICES</th></tr></thead><tbody>{rows}</tbody></table>{extra}"
    return html

def _snmpwalk_html(snmpwalk: dict) -> str:
    if not snmpwalk or snmpwalk.get("skipped") or not snmpwalk.get("total_interfaces"):
        return "<p class='muted'>Brak danych SNMP.</p>"
    html = ""
    si = snmpwalk.get("system_info", {})
    # Info grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    if si.get("sysName"):
        html += f"<div><span class='muted'>SYSTEM NAME</span><br><span style='font-size:16px;font-weight:700;color:#e8f0fc'>{si['sysName']}</span></div>"
    if si.get("sysDescr"):
        desc = si['sysDescr'][:80]
        html += f"<div><span class='muted'>SYSTEM DESCRIPTION</span><br><span style='font-size:11px;color:#b8ccec'>{desc}</span></div>"
    if si.get("sysUpTime"):
        html += f"<div><span class='muted'>UPTIME</span><br><span style='font-size:13px;font-weight:700;color:#3ddc84'>{si['sysUpTime']}</span></div>"
    html += f"<div><span class='muted'>TOTAL INTERFACES</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{snmpwalk.get('total_interfaces', 0)}</span></div>"
    active = snmpwalk.get("active_interfaces", 0)
    act_color = "#3ddc84" if active > 0 else "#8a9bb5"
    html += f"<div><span class='muted'>ACTIVE INTERFACES</span><br><span style='font-size:20px;font-weight:700;color:{act_color}'>{active}</span></div>"
    total_svc = snmpwalk.get("total_services", 0)
    if total_svc:
        html += f"<div><span class='muted'>SERVICES</span><br><span style='font-size:20px;font-weight:700;color:#f5c518'>{total_svc}</span></div>"
    html += "</div>"
    # Extra system info
    extras = []
    if si.get("sysContact"):
        extras.append(f"Contact: {si['sysContact']}")
    if si.get("sysLocation"):
        extras.append(f"Location: {si['sysLocation']}")
    if si.get("sysObjectID"):
        extras.append(f"OID: {si['sysObjectID']}")
    if extras:
        html += "<div style='margin-bottom:10px;font-size:11px;color:#8a9bb5'>" + " &middot; ".join(extras) + "</div>"
    # SNMP meta
    html += f"<div style='margin-bottom:12px;font-size:10px;color:#4a8fd4'>SNMP {snmpwalk.get('snmp_version', 'v2c')} · community: {snmpwalk.get('community_string', 'public')}</div>"
    # Interfaces table
    ifaces = snmpwalk.get("interfaces", [])
    if ifaces:
        rows = ""
        for iface in ifaces[:30]:
            admin = iface.get("admin_status", "")
            oper = iface.get("oper_status", "")
            admin_color = "#3ddc84" if admin == "up" else "#ff4444" if admin == "down" else "#f5c518"
            oper_color = "#3ddc84" if oper == "up" else "#ff4444" if oper == "down" else "#f5c518"
            rows += f"<tr><td class='mono' style='font-size:11px'>{iface.get('index','')}</td><td style='font-size:11px;color:#e8f0fc'>{iface.get('name','')}</td><td style='font-size:10px'>{iface.get('speed','')}</td><td style='font-size:10px'>{iface.get('mtu','')}</td><td class='mono' style='font-size:10px'>{iface.get('mac','')}</td><td style='color:{admin_color};font-size:10px'>{admin}</td><td style='color:{oper_color};font-size:10px'>{oper}</td><td style='font-size:10px'>{iface.get('in_octets','0')}</td><td style='font-size:10px'>{iface.get('out_octets','0')}</td></tr>"
        extra = f"<p class='muted'>... i {len(ifaces)-30} więcej</p>" if len(ifaces) > 30 else ""
        html += f"<table><thead><tr><th>IDX</th><th>NAME</th><th>SPEED</th><th>MTU</th><th>MAC</th><th>ADMIN</th><th>OPER</th><th>IN OCTETS</th><th>OUT OCTETS</th></tr></thead><tbody>{rows}</tbody></table>{extra}"
    # Services list
    services = snmpwalk.get("services", [])
    if services:
        svc_badges = " ".join(f"<span style='font-size:9px;color:#7ab3e8;border:1px solid rgba(122,179,232,.3);padding:1px 5px;margin:1px'>{s}</span>" for s in services[:40])
        extra_svc = f" <span class='muted'>... +{len(services)-40}</span>" if len(services) > 40 else ""
        html += f"<div style='margin-top:10px'><span class='muted'>RUNNING SERVICES ({len(services)})</span><br>{svc_badges}{extra_svc}</div>"
    return html

def _netexec_html(netexec: dict) -> str:
    if not netexec or netexec.get("skipped") or not netexec.get("smb_info"):
        return "<p class='muted'>Brak danych NetExec.</p>"
    html = ""
    smb = netexec.get("smb_info", {})
    # SMB info grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    if smb.get("hostname"):
        html += f"<div><span class='muted'>HOSTNAME</span><br><span style='font-size:16px;font-weight:700;color:#e8f0fc'>{smb['hostname']}</span></div>"
    if smb.get("os"):
        html += f"<div><span class='muted'>OS</span><br><span style='font-size:11px;color:#b8ccec'>{smb['os']}</span></div>"
    if smb.get("domain"):
        html += f"<div><span class='muted'>DOMAIN</span><br><span style='font-size:14px;font-weight:700;color:#f5c518'>{smb['domain']}</span></div>"
    html += f"<div><span class='muted'>SHARES</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{netexec.get('total_shares', 0)}</span></div>"
    html += f"<div><span class='muted'>USERS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{netexec.get('total_users', 0)}</span></div>"
    html += "</div>"
    # Vulnerability badges
    vulns = netexec.get("vulnerabilities", [])
    if vulns:
        sev_color = {"critical": "#ff4444", "high": "#ff4444", "medium": "#ff8c00", "low": "#f5c518"}
        badges = ""
        for v in vulns:
            color = sev_color.get(v.get("severity", "medium"), "#f5c518")
            badges += f"<span style='font-size:10px;color:{color};border:1px solid {color};padding:2px 8px;margin-right:6px'>{v.get('severity','').upper()}: {v.get('title','')}</span>"
        html += f"<div style='margin-bottom:12px'>{badges}</div>"
    # Relay targets
    relay = netexec.get("relay_targets", [])
    if relay:
        items = "".join(f"<div style='font-size:11px;padding:2px 0;color:#ff4444;font-family:monospace;border-bottom:1px solid rgba(255,68,68,.1)'>{ip}</div>" for ip in relay[:20])
        extra = f"<p class='muted'>... i {len(relay)-20} więcej</p>" if len(relay) > 20 else ""
        html += f"<div style='border:1px solid rgba(255,68,68,.3);padding:10px;margin-bottom:12px'><span style='color:#ff4444;font-size:11px;font-weight:700'>NTLM RELAY TARGETS — NO SMB SIGNING ({len(relay)})</span>{items}{extra}</div>"
    # Shares table
    shares = netexec.get("shares", [])
    if shares:
        rows = ""
        for s in shares:
            acc = s.get("access", "NO ACCESS")
            acc_color = "#ff4444" if "WRITE" in acc else "#f5c518" if acc == "READ" else "#8a9bb5"
            rows += f"<tr><td class='mono' style='font-size:11px'>{s.get('name','')}</td><td style='color:{acc_color};font-size:10px'>{acc}</td></tr>"
        html += f"<table><thead><tr><th>SHARE</th><th>ACCESS</th></tr></thead><tbody>{rows}</tbody></table>"
    # Users
    users = netexec.get("users", [])
    if users:
        rows = ""
        for u in users[:30]:
            rows += f"<tr><td class='mono' style='font-size:11px;color:#f5c518'>{u.get('username','')}</td><td style='font-size:10px'>{u.get('description','')}</td></tr>"
        extra = f"<p class='muted'>... i {len(users)-30} więcej</p>" if len(users) > 30 else ""
        html += f"<div style='margin-top:8px'><table><thead><tr><th>USERNAME</th><th>DESCRIPTION</th></tr></thead><tbody>{rows}</tbody></table>{extra}</div>"
    # Password policy
    pol = netexec.get("password_policy", {})
    if pol:
        html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-top:10px'>"
        if pol.get("min_length") is not None:
            ml_color = "#ff4444" if pol["min_length"] < 8 else "#f5c518" if pol["min_length"] < 12 else "#3ddc84"
            html += f"<div><span class='muted'>MIN LENGTH</span><br><span style='font-size:18px;font-weight:700;color:{ml_color}'>{pol['min_length']}</span></div>"
        if pol.get("complexity") is not None:
            cx_color = "#3ddc84" if pol["complexity"] else "#ff4444"
            cx_text = "ENABLED" if pol["complexity"] else "DISABLED"
            html += f"<div><span class='muted'>COMPLEXITY</span><br><span style='font-size:14px;font-weight:700;color:{cx_color}'>{cx_text}</span></div>"
        if pol.get("lockout_threshold") is not None:
            lt_color = "#ff4444" if pol["lockout_threshold"] == 0 else "#f5c518" if pol["lockout_threshold"] < 5 else "#3ddc84"
            html += f"<div><span class='muted'>LOCKOUT THRESHOLD</span><br><span style='font-size:18px;font-weight:700;color:{lt_color}'>{pol['lockout_threshold']}</span></div>"
        html += "</div>"
    return html

def _cwe_html(cwe: dict) -> str:
    cwes = cwe.get("cwes", [])
    if not cwes:
        return "<p class='muted'>Brak mapowań CWE.</p>"
    lik_color = {"High": "#ff4444", "Medium": "#f5c518", "Low": "#8a9bb5"}
    badges = ""
    for level in ["High", "Medium", "Low"]:
        cnt = cwe.get(f"{level.lower()}_count", 0)
        if cnt:
            badges += f"<span style='color:{lik_color[level]};font-size:10px;border:1px solid {lik_color[level]};padding:2px 8px;margin-right:6px'>{level.upper()}: {cnt}</span>"
    rows = ""
    for c in cwes[:30]:
        color = lik_color.get(c.get("likelihood", "Medium"), "#8a9bb5")
        desc = (c.get("description", "") or "")[:100]
        rows += f"<tr><td class='mono'><a href='{c.get('url','')}' style='color:#4a8fd4'>{c.get('cwe_id','')}</a></td><td>{c.get('name','')}</td><td>{c.get('category','')}</td><td style='color:{color}'>{c.get('likelihood','').upper()}</td><td style='font-size:10px'>{desc}</td></tr>"
    return f"""<div style='margin-bottom:10px'>{badges}</div>
    <table>
        <thead><tr><th>CWE ID</th><th>NAME</th><th>CATEGORY</th><th>LIKELIHOOD</th><th>DESCRIPTION</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>"""

def _owasp_html(owasp: dict) -> str:
    categories = owasp.get("categories", [])
    if not categories:
        return "<p class='muted'>Brak mapowań OWASP.</p>"
    risk_color = {"Critical": "#ff4444", "High": "#ff8c00", "Medium": "#f5c518", "None": "#8a9bb5"}
    html = f"<div style='margin-bottom:10px'><span class='muted'>DETECTED:</span> <span style='font-size:14px;font-weight:700;color:#e8f0fc'>{owasp.get('detected_count',0)} / {owasp.get('total',10)}</span></div>"
    for cat in categories:
        det = cat.get("detected", False)
        color = risk_color.get(cat.get("risk_level", "None"), "#8a9bb5")
        opacity = "1" if det else "0.45"
        badge = f"<span style='color:{color};font-size:10px;border:1px solid {color};padding:2px 8px'>{cat['risk_level'].upper()}</span>" if det else "<span style='color:#8a9bb5;font-size:10px;border:1px solid #8a9bb5;padding:2px 8px'>NOT DETECTED</span>"
        triggers = ""
        if det and cat.get("triggered_by"):
            triggers = "<br>" + " ".join(f"<span style='font-size:9px;color:#7ab3e8;border:1px solid rgba(74,143,212,.2);padding:1px 6px;margin:1px'>{t}</span>" for t in cat["triggered_by"][:5])
        html += f"<div style='border:1px solid rgba(74,143,212,{0.2 if det else 0.08});padding:10px;margin-bottom:6px;opacity:{opacity}'><span style='font-size:12px;color:{'#e8f0fc' if det else '#8a9bb5'}'><b>{cat['id']}</b> — {cat['name']}</span> {badge}{triggers}</div>"
    return html

def _wpscan_html(wpscan: dict) -> str:
    if not wpscan or wpscan.get("skipped"):
        return "<p class='muted'>WordPress not detected or WPScan skipped.</p>"
    html = ""
    # Version info
    wpv = wpscan.get("wordpress_version", {})
    ver = wpv.get("version", "unknown")
    status = wpv.get("status", "unknown")
    ver_color = {"latest": "#3ddc84", "outdated": "#ff4444"}.get(status, "#f5c518")
    html += f"<div style='margin-bottom:12px'><span style='font-size:16px;font-weight:700;color:#e8f0fc'>WordPress {ver}</span> "
    html += f"<span style='color:{ver_color};font-size:10px;border:1px solid {ver_color};padding:2px 8px'>{status.upper()}</span></div>"
    # Stats
    html += f"<div style='display:flex;gap:24px;margin-bottom:12px'>"
    vuln_count = wpscan.get("vulnerabilities_count", 0)
    vuln_col = "#ff4444" if vuln_count else "#3ddc84"
    html += f"<div><span class='muted'>VULNERABILITIES</span><br><span style='font-size:18px;font-weight:700;color:{vuln_col}'>{vuln_count}</span></div>"
    html += f"<div><span class='muted'>PLUGINS</span><br><span style='font-size:18px;font-weight:700;color:#e8f0fc'>{wpscan.get('plugins_count', 0)}</span></div>"
    html += f"<div><span class='muted'>THEMES</span><br><span style='font-size:18px;font-weight:700;color:#e8f0fc'>{wpscan.get('themes_count', 0)}</span></div>"
    html += f"<div><span class='muted'>USERS</span><br><span style='font-size:18px;font-weight:700;color:#e8f0fc'>{wpscan.get('users_count', 0)}</span></div>"
    html += "</div>"
    # Plugins
    plugins = wpscan.get("plugins", [])
    if plugins:
        rows = ""
        for p in plugins[:20]:
            vulns = p.get("vulnerabilities", [])
            v_col = "#ff4444" if vulns else "#3ddc84"
            v_text = f"{len(vulns)} VULN" if vulns else "CLEAN"
            vuln_detail = ""
            for v in vulns[:3]:
                fixed = f" (fixed in {v['fixed_in']})" if v.get("fixed_in") else ""
                vuln_detail += f"<br><span style='font-size:9px;color:#8a9bb5'>{v.get('title','')}{fixed}</span>"
            rows += f"<tr><td>{p['name']}</td><td class='mono'>{p.get('version','?')}</td><td style='color:{v_col}'>{v_text}{vuln_detail}</td></tr>"
        html += f"<div class='muted' style='margin-bottom:4px'>PLUGINS ({len(plugins)})</div>"
        html += f"<table><thead><tr><th>PLUGIN</th><th>VERSION</th><th>VULNERABILITIES</th></tr></thead><tbody>{rows}</tbody></table>"
    # Users
    users = wpscan.get("users", [])
    if users:
        users_html = " ".join(f"<span class='mono' style='font-size:10px;color:#f5c518;border:1px solid #f5c518;padding:1px 6px'>{u['username']}</span>" for u in users[:20])
        html += f"<div style='margin:10px 0;border:1px solid #f5c518;background:rgba(245,197,24,.08);padding:8px 12px;font-size:11px;color:#f5c518'>⚠ {len(users)} users enumerated</div>"
        html += f"<div>{users_html}</div>"
    # Interesting findings
    findings = wpscan.get("interesting_findings", [])
    if findings:
        html += f"<div class='muted' style='margin:10px 0 4px'>INTERESTING FINDINGS ({len(findings)})</div>"
        for f in findings[:10]:
            html += f"<div style='font-size:10px;border:1px solid rgba(74,143,212,.15);padding:6px 10px;margin-bottom:4px'>"
            html += f"<span class='mono' style='color:#4a8fd4'>{f.get('type','')}</span> "
            if f.get("url"):
                html += f"<span style='color:#7ab3e8'>{f['url']}</span> "
            if f.get("description"):
                html += f"<span style='color:#8a9bb5'>{f['description'][:100]}</span>"
            html += "</div>"
    return html or "<p class='muted'>Brak danych WPScan.</p>"

def _retirejs_html(retirejs: dict) -> str:
    libs = retirejs.get("libraries", [])
    if not libs:
        return "<p class='muted'>Brak wyników Retire.js.</p>"
    summary = retirejs.get("summary", {})
    sev_color = {"critical": "#ff4444", "high": "#ff8c00", "medium": "#f5c518", "low": "#3ddc84"}
    # Summary badges
    badges = ""
    for level in ["critical", "high", "medium", "low"]:
        cnt = summary.get(level, 0)
        if cnt:
            badges += f"<span style='color:{sev_color[level]};font-size:10px;border:1px solid {sev_color[level]};padding:2px 8px;margin-right:6px'>{level.upper()}: {cnt}</span>"
    # Stats
    html = f"<div style='margin-bottom:10px'>{badges}</div>"
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>JS LIBRARIES</span><br><span style='font-size:18px;font-weight:700;color:#e8f0fc'>{summary.get('total_libs', 0)}</span></div>"
    vuln_cnt = summary.get("vulnerable_libs", 0)
    vuln_col = "#ff4444" if vuln_cnt else "#3ddc84"
    html += f"<div><span class='muted'>VULNERABLE</span><br><span style='font-size:18px;font-weight:700;color:{vuln_col}'>{vuln_cnt}</span></div>"
    html += f"<div><span class='muted'>TOTAL VULNS</span><br><span style='font-size:18px;font-weight:700;color:#ff8c00'>{summary.get('total_vulns', 0)}</span></div>"
    html += "</div>"
    # Libraries table
    rows = ""
    for lib in libs[:25]:
        component = lib.get("component", "")
        version = lib.get("version", "")
        vulns = lib.get("vulnerabilities", [])
        if vulns:
            highest_sev = "low"
            for v in vulns:
                s = v.get("severity", "low")
                if s == "critical":
                    highest_sev = "critical"
                    break
                elif s == "high" and highest_sev not in ("critical",):
                    highest_sev = "high"
                elif s == "medium" and highest_sev not in ("critical", "high"):
                    highest_sev = "medium"
            color = sev_color.get(highest_sev, "#f5c518")
            cves_all = []
            summaries = []
            for v in vulns:
                cves_all.extend(v.get("cve", []))
                if v.get("summary"):
                    summaries.append(v["summary"])
            cve_html = " ".join(f"<a href='https://nvd.nist.gov/vuln/detail/{c}' style='color:#4a8fd4;font-size:10px'>{c}</a>" for c in cves_all[:4])
            desc = "; ".join(summaries[:2])[:120]
            rows += f"<tr><td style='color:{color};font-weight:700'>{highest_sev.upper()}</td><td>{component}</td><td class='mono'>{version}</td><td>{cve_html}</td><td style='font-size:10px'>{desc}</td></tr>"
        else:
            rows += f"<tr><td style='color:#3ddc84'>OK</td><td>{component}</td><td class='mono'>{version}</td><td></td><td class='muted'>No known vulnerabilities</td></tr>"
    extra = f"<p class='muted'>... i {len(libs)-25} więcej</p>" if len(libs) > 25 else ""
    html += f"""<table>
        <thead><tr><th>STATUS</th><th>LIBRARY</th><th>VERSION</th><th>CVE</th><th>DETAILS</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>{extra}"""
    return html

def _droopescan_html(droopescan: dict) -> str:
    if not droopescan or droopescan.get("skipped"):
        return "<p class='muted'>No supported CMS detected or Droopescan skipped.</p>"
    html = ""
    # CMS badge
    cms = droopescan.get("cms_detected", "unknown")
    cms_color = {"Drupal": "#0678be", "Joomla": "#f44321", "WordPress": "#21759b", "SilverStripe": "#005ae1", "Moodle": "#f98012"}.get(cms, "#4a8fd4")
    html += f"<div style='margin-bottom:12px'><span style='font-size:10px;padding:4px 12px;border:1px solid {cms_color};color:{cms_color}'>{cms.upper()}</span></div>"
    # Possible versions
    versions = droopescan.get("cms_version", [])
    if versions:
        ver_tags = " ".join(f"<span class='mono' style='font-size:10px;color:#e8f0fc;border:1px solid rgba(74,143,212,.3);padding:2px 6px;margin:2px'>{v}</span>" for v in versions[:15])
        extra = f" <span class='muted'>... i {len(versions)-15} więcej</span>" if len(versions) > 15 else ""
        html += f"<div style='margin-bottom:12px'><span class='muted'>POSSIBLE VERSIONS ({len(versions)})</span><br>{ver_tags}{extra}</div>"
    # Summary stats
    summary = droopescan.get("summary", {})
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    html += f"<div><span class='muted'>PLUGINS</span><br><span style='font-size:18px;font-weight:700;color:#e8f0fc'>{summary.get('plugins_count', 0)}</span></div>"
    html += f"<div><span class='muted'>THEMES</span><br><span style='font-size:18px;font-weight:700;color:#e8f0fc'>{summary.get('themes_count', 0)}</span></div>"
    html += f"<div><span class='muted'>INTERESTING URLs</span><br><span style='font-size:18px;font-weight:700;color:#f5c518'>{summary.get('interesting_count', 0)}</span></div>"
    html += "</div>"
    # Plugins table
    plugins = droopescan.get("plugins", [])
    if plugins:
        rows = "".join(f"<tr><td>{p.get('name','')}</td><td class='mono' style='font-size:10px'>{p.get('url','')}</td></tr>" for p in plugins[:30])
        extra = f"<p class='muted'>... i {len(plugins)-30} więcej</p>" if len(plugins) > 30 else ""
        html += f"<div class='muted' style='margin-bottom:4px'>PLUGINS ({len(plugins)})</div>"
        html += f"<table><thead><tr><th>PLUGIN</th><th>URL</th></tr></thead><tbody>{rows}</tbody></table>{extra}"
    # Themes table
    themes = droopescan.get("themes", [])
    if themes:
        rows = "".join(f"<tr><td>{t.get('name','')}</td><td class='mono' style='font-size:10px'>{t.get('url','')}</td></tr>" for t in themes[:20])
        html += f"<div class='muted' style='margin:10px 0 4px'>THEMES ({len(themes)})</div>"
        html += f"<table><thead><tr><th>THEME</th><th>URL</th></tr></thead><tbody>{rows}</tbody></table>"
    # Interesting URLs
    interesting = droopescan.get("interesting_urls", [])
    if interesting:
        rows = "".join(f"<tr><td class='mono' style='font-size:10px;color:#f5c518'>{u.get('url','')}</td><td style='font-size:10px'>{u.get('description','')}</td></tr>" for u in interesting[:15])
        html += f"<div class='muted' style='margin:10px 0 4px'>INTERESTING URLs ({len(interesting)})</div>"
        html += f"<table><thead><tr><th>URL</th><th>DESCRIPTION</th></tr></thead><tbody>{rows}</tbody></table>"
    return html or "<p class='muted'>Brak danych Droopescan.</p>"

def _cmsmap_html(cmsmap: dict) -> str:
    if not cmsmap or cmsmap.get("skipped"):
        return "<p class='muted'>No CMS detected or CMSmap skipped.</p>"
    html = ""
    # CMS detected badge
    cms = cmsmap.get("cms_detected", "unknown")
    cms_ver = cmsmap.get("cms_version", "")
    cms_color = {"WordPress": "#21759b", "Joomla": "#f44321", "Drupal": "#0678be"}.get(cms, "#4a8fd4")
    ver_str = f" {cms_ver}" if cms_ver else ""
    html += f"<div style='margin-bottom:12px'><span style='font-size:10px;padding:4px 12px;border:1px solid {cms_color};color:{cms_color};background:rgba({",".join(str(int(cms_color[i:i+2],16)) for i in (1,3,5))},.12)'>{cms.upper()}{ver_str}</span></div>"
    # Summary stats
    summary = cmsmap.get("summary", {})
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    total = summary.get("total_vulns", 0)
    total_col = "#ff4444" if total else "#3ddc84"
    html += f"<div><span class='muted'>VULNERABILITIES</span><br><span style='font-size:18px;font-weight:700;color:{total_col}'>{total}</span></div>"
    for lbl, key, color in [("HIGH", "high", "#ff4444"), ("MEDIUM", "medium", "#f5c518"), ("LOW", "low", "#3ddc84")]:
        cnt = summary.get(key, 0)
        if cnt:
            html += f"<div><span class='muted'>{lbl}</span><br><span style='font-size:18px;font-weight:700;color:{color}'>{cnt}</span></div>"
    html += "</div>"
    # Users alert
    users = cmsmap.get("users", [])
    if users:
        users_tags = " ".join(f"<span class='mono' style='font-size:10px;color:#f5c518;border:1px solid #f5c518;padding:1px 6px'>{u}</span>" for u in users[:20])
        html += f"<div style='border:1px solid #f5c518;background:rgba(245,197,24,.08);padding:8px 12px;margin-bottom:12px;font-size:11px;color:#f5c518'>&#9888; {len(users)} users enumerated: {users_tags}</div>"
    # Vulnerabilities table
    vulns = cmsmap.get("vulnerabilities", [])
    if vulns:
        sev_color = {"High": "#ff4444", "Medium": "#f5c518", "Low": "#3ddc84"}
        rows = ""
        for v in vulns[:25]:
            color = sev_color.get(v.get("severity", "Medium"), "#f5c518")
            cve = v.get("cve", "")
            cve_html = ""
            if cve:
                for c in cve.split(", "):
                    cve_html += f"<a href='https://nvd.nist.gov/vuln/detail/{c}' style='color:#4a8fd4;font-size:10px'>{c}</a> "
            rows += f"<tr><td style='color:{color};font-weight:700'>{v.get('severity','').upper()}</td><td>{v.get('title','')}</td><td>{cve_html}</td><td style='font-size:10px'>{v.get('description','')}</td></tr>"
        extra = f"<p class='muted'>... i {len(vulns)-25} więcej</p>" if len(vulns) > 25 else ""
        html += f"""<div class='muted' style='margin-bottom:4px'>VULNERABILITIES ({len(vulns)})</div>
        <table>
            <thead><tr><th>SEVERITY</th><th>TITLE</th><th>CVE</th><th>DESCRIPTION</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>{extra}"""
    # Plugins table
    plugins = cmsmap.get("plugins", [])
    if plugins:
        rows = ""
        for p in plugins[:20]:
            v_col = "#ff4444" if p.get("vulnerable") else "#3ddc84"
            v_text = "VULNERABLE" if p.get("vulnerable") else "OK"
            rows += f"<tr><td>{p.get('name','')}</td><td class='mono'>{p.get('version','?')}</td><td style='color:{v_col}'>{v_text}</td></tr>"
        html += f"<div class='muted' style='margin:10px 0 4px'>PLUGINS ({len(plugins)})</div>"
        html += f"<table><thead><tr><th>PLUGIN</th><th>VERSION</th><th>STATUS</th></tr></thead><tbody>{rows}</tbody></table>"
    # Themes table
    themes = cmsmap.get("themes", [])
    if themes:
        rows = ""
        for t in themes[:10]:
            v_col = "#ff4444" if t.get("vulnerable") else "#3ddc84"
            v_text = "VULNERABLE" if t.get("vulnerable") else "OK"
            rows += f"<tr><td>{t.get('name','')}</td><td class='mono'>{t.get('version','?')}</td><td style='color:{v_col}'>{v_text}</td></tr>"
        html += f"<div class='muted' style='margin:10px 0 4px'>THEMES ({len(themes)})</div>"
        html += f"<table><thead><tr><th>THEME</th><th>VERSION</th><th>STATUS</th></tr></thead><tbody>{rows}</tbody></table>"
    return html or "<p class='muted'>Brak danych CMSmap.</p>"

def _joomscan_html(joomscan: dict) -> str:
    if not joomscan or joomscan.get("skipped"):
        return "<p class='muted'>Joomla not detected or Joomscan skipped.</p>"
    html = ""
    # Version info
    jver = joomscan.get("joomla_version", "")
    if jver:
        html += f"<div style='margin-bottom:12px'><span style='font-size:16px;font-weight:700;color:#e8f0fc'>Joomla {jver}</span></div>"
    # Admin URL alert
    admin_url = joomscan.get("admin_url", "")
    if admin_url:
        html += f"<div style='border:1px solid #ff4444;background:rgba(255,68,68,.12);color:#ff4444;padding:10px 14px;margin-bottom:12px;font-size:12px'>&#9888; ADMIN PANEL FOUND: <span class='mono' style='color:#e8f0fc'>{admin_url}</span></div>"
    # Config files alert
    config_files = joomscan.get("config_files", [])
    if config_files:
        items = " ".join(f"<span class='mono' style='font-size:10px;color:#f5c518;border:1px solid rgba(245,197,24,.4);padding:2px 6px;margin:2px'>{cf}</span>" for cf in config_files[:10])
        html += f"<div style='border:1px solid #f5c518;background:rgba(245,197,24,.08);padding:10px 14px;margin-bottom:12px;font-size:12px;color:#f5c518'>&#9888; CONFIG FILES: {items}</div>"
    # Backup files alert
    backup_files = joomscan.get("backup_files", [])
    if backup_files:
        items = " ".join(f"<span class='mono' style='font-size:10px;color:#f5c518;border:1px solid rgba(245,197,24,.4);padding:2px 6px;margin:2px'>{bf}</span>" for bf in backup_files[:10])
        html += f"<div style='border:1px solid #f5c518;background:rgba(245,197,24,.08);padding:10px 14px;margin-bottom:12px;font-size:12px;color:#f5c518'>&#9888; BACKUP FILES: {items}</div>"
    # Summary stats
    summary = joomscan.get("summary", {})
    html += "<div style='display:flex;gap:24px;margin-bottom:12px'>"
    vuln_count = summary.get("total_vulns", 0)
    vuln_col = "#ff4444" if vuln_count else "#3ddc84"
    html += f"<div><span class='muted'>VULNERABILITIES</span><br><span style='font-size:18px;font-weight:700;color:{vuln_col}'>{vuln_count}</span></div>"
    html += f"<div><span class='muted'>COMPONENTS</span><br><span style='font-size:18px;font-weight:700;color:#e8f0fc'>{summary.get('components_count', 0)}</span></div>"
    html += "</div>"
    # Vulnerabilities table
    vulns = joomscan.get("vulnerabilities", [])
    if vulns:
        sev_color = {"High": "#ff4444", "Medium": "#f5c518", "Low": "#3ddc84"}
        rows = ""
        for v in vulns[:20]:
            color = sev_color.get(v.get("severity", "Medium"), "#f5c518")
            rows += f"<tr><td style='color:{color};font-weight:700'>{v.get('severity','').upper()}</td><td>{v.get('title','')}</td><td class='mono' style='font-size:10px'>{(v.get('url','') or '')[:80]}</td><td style='font-size:10px'>{v.get('description','')}</td></tr>"
        extra = f"<p class='muted'>... i {len(vulns)-20} więcej</p>" if len(vulns) > 20 else ""
        html += f"""<div class='muted' style='margin-bottom:4px'>VULNERABILITIES ({len(vulns)})</div>
        <table>
            <thead><tr><th>SEVERITY</th><th>TITLE</th><th>URL</th><th>DESCRIPTION</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>{extra}"""
    # Components list
    components = joomscan.get("components", [])
    if components:
        rows = ""
        for c in components[:20]:
            rows += f"<tr><td>{c.get('name','')}</td><td class='mono'>{c.get('version','?')}</td></tr>"
        html += f"<div class='muted' style='margin:10px 0 4px'>COMPONENTS ({len(components)})</div>"
        html += f"<table><thead><tr><th>COMPONENT</th><th>VERSION</th></tr></thead><tbody>{rows}</tbody></table>"
    return html or "<p class='muted'>Brak danych Joomscan.</p>"

def _wapiti_html(wapiti: dict) -> str:
    vulns = wapiti.get("vulnerabilities", [])
    if not vulns:
        return "<p class='muted'>Brak wyników Wapiti.</p>"
    summary = wapiti.get("summary", {})
    sev_color = {"Critical": "#ff4444", "High": "#ff8c00", "Medium": "#f5c518", "Low": "#3ddc84"}
    badges = ""
    for level in ["Critical", "High", "Medium", "Low"]:
        cnt = summary.get(level.lower(), 0)
        if cnt:
            badges += f"<span style='color:{sev_color[level]};font-size:10px;border:1px solid {sev_color[level]};padding:2px 8px;margin-right:6px'>{level.upper()}: {cnt}</span>"
    rows = ""
    for v in vulns[:30]:
        color = sev_color.get(v.get("level", "Medium"), "#f5c518")
        wstg_refs = v.get("wstg", [])
        wstg_html = ""
        if wstg_refs:
            wstg_links = []
            for ref in wstg_refs[:2]:
                wstg_links.append(f"<a href='https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/{ref}' style='color:#4a8fd4;font-size:10px'>{ref}</a>")
            wstg_html = ", ".join(wstg_links)
        param = v.get("parameter", "") or ""
        rows += f"<tr><td style='color:{color};font-weight:700'>{v.get('level','').upper()}</td><td>{v.get('name','')}</td><td class='mono' style='font-size:10px'>{(v.get('url','') or '')[:80]}</td><td class='mono'>{param[:40]}</td><td>{wstg_html}</td></tr>"
    extra = f"<p class='muted'>... i {len(vulns)-30} więcej</p>" if len(vulns) > 30 else ""
    return f"""<div style='margin-bottom:10px'>{badges}</div>
    <table>
        <thead><tr><th>LEVEL</th><th>VULNERABILITY</th><th>URL</th><th>PARAMETER</th><th>WSTG</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>{extra}"""

def _zap_html(zap: dict) -> str:
    alerts = zap.get("alerts", [])
    if not alerts:
        return "<p class='muted'>Brak wyników OWASP ZAP.</p>"
    summary = zap.get("summary", {})
    risk_color = {"High": "#ff4444", "Medium": "#ff8c00", "Low": "#f5c518", "Informational": "#8a9bb5"}
    badges = ""
    for level in ["High", "Medium", "Low", "Informational"]:
        cnt = summary.get(level.lower(), 0)
        if cnt:
            label = "INFO" if level == "Informational" else level.upper()
            badges += f"<span style='color:{risk_color[level]};font-size:10px;border:1px solid {risk_color[level]};padding:2px 8px;margin-right:6px'>{label}: {cnt}</span>"
    spider = zap.get("spider_urls_found", 0)
    spider_html = f"<div class='muted' style='margin:6px 0'>Spider crawled {spider} URLs</div>" if spider else ""
    rows = ""
    for a in alerts[:30]:
        color = risk_color.get(a.get("risk", "Informational"), "#8a9bb5")
        url = (a.get("url", "") or "")[:80]
        cwe = a.get("cweid", "")
        cwe_html = f"<a href='https://cwe.mitre.org/data/definitions/{cwe}.html' style='color:#4a8fd4'>CWE-{cwe}</a>" if cwe and cwe != "0" else ""
        rows += f"<tr><td style='color:{color};font-weight:700'>{a.get('risk','').upper()}</td><td>{a.get('alert_name','')}</td><td class='mono' style='font-size:10px'>{url}</td><td>{a.get('confidence','')}</td><td>{cwe_html}</td></tr>"
    extra = f"<p class='muted'>... i {len(alerts)-30} więcej</p>" if len(alerts) > 30 else ""
    return f"""<div style='margin-bottom:10px'>{badges}</div>
    {spider_html}
    <table>
        <thead><tr><th>RISK</th><th>ALERT</th><th>URL</th><th>CONFIDENCE</th><th>CWE</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>{extra}"""

def _bloodhound_html(bloodhound: dict) -> str:
    if not bloodhound or bloodhound.get("skipped"):
        return "<p class='muted'>Brak danych BloodHound (AD niedostępne lub brak uprawnień).</p>"
    html = ""
    # Stats grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    html += f"<div><span class='muted'>USERS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{bloodhound.get('total_users', 0)}</span></div>"
    html += f"<div><span class='muted'>COMPUTERS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{bloodhound.get('total_computers', 0)}</span></div>"
    html += f"<div><span class='muted'>GROUPS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{bloodhound.get('total_groups', 0)}</span></div>"
    if bloodhound.get("total_domains"):
        html += f"<div><span class='muted'>DOMAINS</span><br><span style='font-size:20px;font-weight:700;color:#f5c518'>{bloodhound['total_domains']}</span></div>"
    if bloodhound.get("total_sessions"):
        html += f"<div><span class='muted'>SESSIONS</span><br><span style='font-size:20px;font-weight:700;color:#8a9bb5'>{bloodhound['total_sessions']}</span></div>"
    ap_cnt = bloodhound.get("total_attack_paths", 0)
    if ap_cnt:
        html += f"<div><span class='muted'>ATTACK PATHS</span><br><span style='font-size:20px;font-weight:700;color:#ff4444'>{ap_cnt}</span></div>"
    html += "</div>"
    # Severity badges
    crit = bloodhound.get("critical_count", 0)
    high = bloodhound.get("high_count", 0)
    med = bloodhound.get("medium_count", 0)
    if crit or high or med:
        badges = ""
        if crit:
            badges += f"<span style='font-size:10px;color:#ff4444;border:1px solid #ff4444;padding:2px 8px;margin-right:6px;background:rgba(255,68,68,.12)'>CRITICAL: {crit}</span>"
        if high:
            badges += f"<span style='font-size:10px;color:#ff4444;border:1px solid #ff4444;padding:2px 8px;margin-right:6px;background:rgba(255,68,68,.08)'>HIGH: {high}</span>"
        if med:
            badges += f"<span style='font-size:10px;color:#f5c518;border:1px solid #f5c518;padding:2px 8px;margin-right:6px;background:rgba(245,197,24,.08)'>MEDIUM: {med}</span>"
        html += f"<div style='margin-bottom:12px'>{badges}</div>"
    # Attack paths
    attack_paths = bloodhound.get("attack_paths", [])
    if attack_paths:
        for ap in attack_paths:
            sev = ap.get("severity", "medium")
            color = "#ff4444" if sev in ("critical", "high") else "#f5c518"
            affected = ap.get("affected", [])
            aff_html = " ".join(f"<span style='font-size:9px;color:#f5c518;border:1px solid rgba(245,197,24,.3);padding:1px 5px'>{a}</span>" for a in affected[:8])
            mitre_badge = f"<span style='font-size:9px;color:#4a8fd4;border:1px solid rgba(74,143,212,.3);padding:1px 5px'>{ap.get('mitre','')}</span> " if ap.get("mitre") else ""
            html += f"<div style='border:1px solid {color};padding:10px;margin-bottom:6px'>"
            html += f"<div style='display:flex;justify-content:space-between'><span style='font-weight:700;color:#e8f0fc;font-size:12px'>{ap.get('title','')}</span>"
            html += f"<span style='font-size:10px;color:{color};border:1px solid {color};padding:1px 6px'>{sev.upper()}</span></div>"
            html += f"<div style='font-size:11px;color:#8a9bb5;margin:4px 0'>{ap.get('description','')}</div>"
            html += f"{mitre_badge}{aff_html}</div>"
    # Users table (top risky)
    users = bloodhound.get("users", [])
    risky_users = [u for u in users if u.get("has_spn") or u.get("admin_count") or u.get("dont_require_preauth") or u.get("password_not_required")]
    if risky_users:
        rows = ""
        for u in risky_users[:20]:
            flags = []
            if u.get("has_spn"):
                flags.append("SPN")
            if u.get("dont_require_preauth"):
                flags.append("NO_PREAUTH")
            if u.get("password_not_required"):
                flags.append("PWD_NOT_REQ")
            if u.get("password_never_expires"):
                flags.append("NEVER_EXPIRES")
            flags_str = ", ".join(flags) or "—"
            name_color = "#ff4444" if u.get("admin_count") else "#f5c518" if u.get("has_spn") else "#e8f0fc"
            rows += f"<tr><td style='font-size:11px;font-weight:700;color:{name_color}'>{u.get('name','')}</td><td style='font-size:10px'>{u.get('domain','')}</td><td style='color:{'#ff4444' if u.get('admin_count') else '#8a9bb5'};font-size:10px'>{'YES' if u.get('admin_count') else '—'}</td><td style='font-size:9px;color:#ff8c00'>{flags_str}</td></tr>"
        html += f"<div style='margin-top:10px'><div class='muted' style='margin-bottom:4px'>HIGH-RISK USERS ({len(risky_users)})</div><table><thead><tr><th>USER</th><th>DOMAIN</th><th>ADMIN</th><th>FLAGS</th></tr></thead><tbody>{rows}</tbody></table></div>"
    # Computers with unconstrained delegation
    comps = bloodhound.get("computers", [])
    uc_comps = [c for c in comps if c.get("unconstraineddelegation")]
    if uc_comps:
        rows = ""
        for c in uc_comps[:15]:
            rows += f"<tr><td class='mono' style='font-size:11px'>{c.get('name','')}</td><td style='font-size:10px'>{c.get('os','')}</td><td style='color:#ff4444;font-size:10px'>YES</td></tr>"
        html += f"<div style='margin-top:10px'><div class='muted' style='margin-bottom:4px'>UNCONSTRAINED DELEGATION ({len(uc_comps)})</div><table><thead><tr><th>COMPUTER</th><th>OS</th><th>UNCONSTRAINED</th></tr></thead><tbody>{rows}</tbody></table></div>"
    if not html.strip():
        html = "<p class='muted'>Brak danych AD.</p>"
    return html

def _responder_html(responder: dict) -> str:
    if not responder or responder.get("skipped"):
        return "<p class='muted'>Brak danych Responder (narzędzie niedostępne lub brak wykrytych protokołów).</p>"
    html = ""
    # Stats grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    html += f"<div><span class='muted'>PROTOCOLS</span><br><span style='font-size:20px;font-weight:700;color:#ff4444'>{responder.get('total_protocols', 0)}</span></div>"
    html += f"<div><span class='muted'>REQUESTS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{responder.get('total_requests', 0)}</span></div>"
    vuln_cnt = responder.get("total_vulnerabilities", 0)
    vuln_col = "#ff4444" if vuln_cnt else "#3ddc84"
    html += f"<div><span class='muted'>VULNERABILITIES</span><br><span style='font-size:20px;font-weight:700;color:{vuln_col}'>{vuln_cnt}</span></div>"
    html += f"<div><span class='muted'>INTERFACE</span><br><span style='font-size:14px;font-weight:700;color:#8a9bb5'>{responder.get('interface', 'N/A')}</span></div>"
    html += f"<div><span class='muted'>DURATION</span><br><span style='font-size:14px;font-weight:700;color:#8a9bb5'>{responder.get('duration_seconds', 0)}s</span></div>"
    html += "</div>"
    # Severity badges
    crit = responder.get("critical_count", 0)
    high = responder.get("high_count", 0)
    med = responder.get("medium_count", 0)
    if crit or high or med:
        badges = ""
        if crit:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #ff4444;color:#ff4444;background:rgba(255,68,68,.12);margin-right:6px'>CRITICAL: {crit}</span>"
        if high:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #ff4444;color:#ff4444;background:rgba(255,68,68,.08);margin-right:6px'>HIGH: {high}</span>"
        if med:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #f5c518;color:#f5c518;background:rgba(245,197,24,.08);margin-right:6px'>MEDIUM: {med}</span>"
        html += f"<div style='margin-bottom:12px'>{badges}</div>"
    # Detected protocols
    protos = responder.get("protocols_detected", [])
    if protos:
        proto_badges = ""
        for p in protos:
            p_col = "#ff4444" if p in ("NTLM", "LLMNR", "NBT-NS", "WPAD") else "#f5c518"
            proto_badges += f"<span style='display:inline-block;font-size:11px;padding:3px 10px;border:1px solid {p_col};color:{p_col};margin-right:4px;margin-bottom:4px'>{p}</span>"
        html += f"<div style='margin-bottom:12px'><div class='muted' style='margin-bottom:4px'>POISONABLE PROTOCOLS ({len(protos)})</div>{proto_badges}</div>"
    # Vulnerabilities
    vulns = responder.get("vulnerabilities", [])
    if vulns:
        for v in vulns:
            sev = v.get("severity", "medium")
            v_col = "#ff4444" if sev in ("critical", "high") else "#f5c518"
            mitre_badge = f"<span style='font-size:9px;padding:2px 6px;border:1px solid #5eead4;color:#5eead4;margin-left:6px'>{v['mitre']}</span>" if v.get("mitre") else ""
            html += f"<div style='border:1px solid {v_col};padding:10px;margin-bottom:6px'>"
            html += f"<div style='display:flex;justify-content:space-between;margin-bottom:4px'><span style='font-weight:700;color:#e8f0fc;font-size:11px'>{v['title']}</span><span style='font-size:9px;padding:2px 6px;border:1px solid {v_col};color:{v_col}'>{sev.upper()}</span></div>"
            html += f"<div style='font-size:10px;color:#8a9bb5;margin-bottom:4px'>{v.get('description','')}</div>"
            html += mitre_badge
            if v.get("remediation"):
                html += f"<div style='font-size:9px;color:#3ddc84;margin-top:6px;border-left:2px solid #3ddc84;padding-left:6px'>{v['remediation']}</div>"
            html += "</div>"
    # Browsers
    browsers = responder.get("browsers_detected", [])
    if browsers:
        rows = ""
        for b in browsers[:20]:
            rows += f"<tr><td class='mono' style='font-size:11px'>{b.get('name','')}</td><td style='font-size:10px'>{b.get('suffix','')}</td></tr>"
        html += f"<div style='margin-top:10px'><div class='muted' style='margin-bottom:4px'>NETWORK HOSTS ({len(browsers)})</div><table><thead><tr><th>NAME</th><th>SUFFIX</th></tr></thead><tbody>{rows}</tbody></table></div>"
    if not html.strip():
        html = "<p class='muted'>Brak danych.</p>"
    return html

def _fierce_html(fierce: dict) -> str:
    if not fierce or fierce.get("skipped"):
        return "<p class='muted'>Brak danych Fierce (narzędzie niedostępne lub cel to adres IP).</p>"
    html = ""
    # Stats grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    html += f"<div><span class='muted'>SUBDOMAINS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{fierce.get('total_subdomains', 0)}</span></div>"
    html += f"<div><span class='muted'>NAMESERVERS</span><br><span style='font-size:20px;font-weight:700;color:#8a9bb5'>{fierce.get('total_nameservers', 0)}</span></div>"
    html += f"<div><span class='muted'>NEARBY IPs</span><br><span style='font-size:20px;font-weight:700;color:#8a9bb5'>{fierce.get('total_nearby', 0)}</span></div>"
    zt = fierce.get("zone_transfer", {})
    if zt.get("attempted"):
        zt_col = "#ff4444" if zt.get("successful") else "#3ddc84"
        zt_txt = "SUCCESSFUL" if zt.get("successful") else "FAILED"
        html += f"<div><span class='muted'>ZONE TRANSFER</span><br><span style='font-size:14px;font-weight:700;color:{zt_col}'>{zt_txt}</span></div>"
    if fierce.get("wildcard"):
        html += f"<div><span class='muted'>WILDCARD</span><br><span style='font-size:14px;font-weight:700;color:#f5c518'>{fierce['wildcard']}</span></div>"
    html += "</div>"
    # Zone transfer warning
    if zt.get("successful"):
        html += "<div style='border:1px solid #ff4444;padding:10px;margin-bottom:10px'>"
        html += "<span style='font-weight:700;color:#ff4444;font-size:11px'>ZONE TRANSFER SUCCESSFUL</span>"
        html += "<div style='font-size:10px;color:#8a9bb5;margin-top:4px'>DNS zone transfer is enabled — all DNS records are exposed. This is a critical misconfiguration.</div>"
        html += "</div>"
    # Nameservers
    ns_list = fierce.get("nameservers", [])
    if ns_list:
        ns_badges = ""
        for ns in ns_list:
            ns_badges += f"<span style='display:inline-block;font-size:10px;padding:2px 8px;border:1px solid #5eead4;color:#5eead4;margin-right:4px;margin-bottom:4px'>{ns}</span>"
        html += f"<div style='margin-bottom:10px'><div class='muted' style='margin-bottom:4px'>NAMESERVERS ({len(ns_list)})</div>{ns_badges}</div>"
    # Subdomains table
    subs = fierce.get("subdomains", [])
    if subs:
        rows = ""
        for s in subs[:30]:
            rows += f"<tr><td class='mono' style='font-size:10px;font-weight:700'>{s.get('name','')}</td><td class='mono' style='font-size:10px'>{s.get('ip','')}</td><td style='font-size:9px;color:#5eead4'>{s.get('source','')}</td></tr>"
        extra = f"<div class='muted' style='margin-top:6px;font-size:9px'>... i {len(subs)-30} więcej</div>" if len(subs) > 30 else ""
        html += f"<div style='margin-top:10px'><div class='muted' style='margin-bottom:4px'>SUBDOMAINS ({len(subs)})</div><table><thead><tr><th>SUBDOMAIN</th><th>IP</th><th>SOURCE</th></tr></thead><tbody>{rows}</tbody></table>{extra}</div>"
    # Nearby IPs
    nearby = fierce.get("nearby_ips", [])
    if nearby:
        rows = ""
        for n in nearby[:20]:
            rows += f"<tr><td class='mono' style='font-size:10px'>{n.get('ip','')}</td><td class='mono' style='font-size:10px'>{n.get('hostname','')}</td></tr>"
        extra = f"<div class='muted' style='margin-top:6px;font-size:9px'>... i {len(nearby)-20} więcej</div>" if len(nearby) > 20 else ""
        html += f"<div style='margin-top:10px'><div class='muted' style='margin-bottom:4px'>NEARBY IPs ({len(nearby)})</div><table><thead><tr><th>IP</th><th>HOSTNAME</th></tr></thead><tbody>{rows}</tbody></table>{extra}</div>"
    if not html.strip():
        html = "<p class='muted'>Brak danych.</p>"
    return html

def _smbmap_html(smbmap: dict) -> str:
    if not smbmap or smbmap.get("skipped"):
        return "<p class='muted'>Brak danych SMBMap (narzędzie niedostępne lub SMB nieosiągalny).</p>"
    html = ""
    # Stats grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    html += f"<div><span class='muted'>SHARES</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{smbmap.get('total_shares', 0)}</span></div>"
    r_cnt = smbmap.get("readable_shares", 0)
    w_cnt = smbmap.get("writable_shares", 0)
    html += f"<div><span class='muted'>READABLE</span><br><span style='font-size:20px;font-weight:700;color:{'#f5c518' if r_cnt else '#8a9bb5'}'>{r_cnt}</span></div>"
    html += f"<div><span class='muted'>WRITABLE</span><br><span style='font-size:20px;font-weight:700;color:{'#ff4444' if w_cnt else '#8a9bb5'}'>{w_cnt}</span></div>"
    f_cnt = smbmap.get("total_files", 0)
    html += f"<div><span class='muted'>FILES</span><br><span style='font-size:20px;font-weight:700;color:{'#f5c518' if f_cnt else '#8a9bb5'}'>{f_cnt}</span></div>"
    method = (smbmap.get("access_method") or "N/A").upper()
    m_col = "#ff4444" if method == "NULL" else "#f5c518"
    html += f"<div><span class='muted'>ACCESS</span><br><span style='font-size:14px;font-weight:700;color:{m_col}'>{method} SESSION</span></div>"
    v_cnt = smbmap.get("total_vulnerabilities", 0)
    html += f"<div><span class='muted'>VULNS</span><br><span style='font-size:20px;font-weight:700;color:{'#ff4444' if v_cnt else '#3ddc84'}'>{v_cnt}</span></div>"
    html += "</div>"
    # Severity badges
    crit = smbmap.get("critical_count", 0)
    high = smbmap.get("high_count", 0)
    med = smbmap.get("medium_count", 0)
    if crit or high or med:
        badges = ""
        if crit:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #ff4444;color:#ff4444;background:rgba(255,68,68,.12);margin-right:6px'>CRITICAL: {crit}</span>"
        if high:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #ff4444;color:#ff4444;background:rgba(255,68,68,.08);margin-right:6px'>HIGH: {high}</span>"
        if med:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #f5c518;color:#f5c518;background:rgba(245,197,24,.08);margin-right:6px'>MEDIUM: {med}</span>"
        html += f"<div style='margin-bottom:12px'>{badges}</div>"
    # Shares table
    shares = smbmap.get("shares", [])
    if shares:
        rows = ""
        for s in shares:
            r_col = "#3ddc84" if s.get("read") else "#8a9bb5"
            w_col = "#ff4444" if s.get("write") else "#8a9bb5"
            n_col = "#ff4444" if s.get("write") else "#f5c518" if s.get("read") else "#8a9bb5"
            rows += f"<tr><td style='font-weight:700;font-size:10px;color:{n_col}'>{s.get('name','')}</td><td style='font-size:9px'>{s.get('access','')}</td><td style='color:{r_col};font-size:10px'>{'YES' if s.get('read') else '—'}</td><td style='color:{w_col};font-size:10px;font-weight:{'700' if s.get('write') else '400'}'>{'YES' if s.get('write') else '—'}</td></tr>"
        html += f"<div style='margin-bottom:10px'><div class='muted' style='margin-bottom:4px'>SHARES ({len(shares)})</div><table><thead><tr><th>SHARE</th><th>ACCESS</th><th>READ</th><th>WRITE</th></tr></thead><tbody>{rows}</tbody></table></div>"
    # Interesting files
    files = smbmap.get("interesting_files", [])
    if files:
        rows = ""
        for f in files[:20]:
            fn_col = "#ff4444" if f.get("sensitive") else "#e8f0fc"
            rows += f"<tr><td style='font-size:9px;color:#5eead4'>{f.get('share','')}</td><td style='font-weight:700;font-size:10px;color:{fn_col}'>{f.get('filename','')}</td><td style='font-size:9px'>{f.get('size','—')}</td><td style='color:{'#ff4444' if f.get('sensitive') else '#8a9bb5'};font-size:9px'>{'YES' if f.get('sensitive') else '—'}</td></tr>"
        extra = f"<div class='muted' style='margin-top:6px;font-size:9px'>... i {len(files)-20} więcej</div>" if len(files) > 20 else ""
        html += f"<div style='margin-top:10px'><div class='muted' style='margin-bottom:4px'>INTERESTING FILES ({len(files)})</div><table><thead><tr><th>SHARE</th><th>FILENAME</th><th>SIZE</th><th>SENSITIVE</th></tr></thead><tbody>{rows}</tbody></table>{extra}</div>"
    # Vulnerabilities
    vulns = smbmap.get("vulnerabilities", [])
    if vulns:
        for v in vulns:
            sev = v.get("severity", "medium")
            v_col = "#ff4444" if sev in ("critical", "high") else "#f5c518"
            mitre_badge = f"<span style='font-size:9px;padding:2px 6px;border:1px solid #5eead4;color:#5eead4;margin-left:6px'>{v['mitre']}</span>" if v.get("mitre") else ""
            html += f"<div style='border:1px solid {v_col};padding:10px;margin-bottom:6px'>"
            html += f"<div style='display:flex;justify-content:space-between;margin-bottom:4px'><span style='font-weight:700;color:#e8f0fc;font-size:11px'>{v['title']}</span><span style='font-size:9px;padding:2px 6px;border:1px solid {v_col};color:{v_col}'>{sev.upper()}</span></div>"
            html += f"<div style='font-size:10px;color:#8a9bb5;margin-bottom:4px'>{v.get('description','')}</div>"
            html += mitre_badge
            if v.get("remediation"):
                html += f"<div style='font-size:9px;color:#3ddc84;margin-top:6px;border-left:2px solid #3ddc84;padding-left:6px'>{v['remediation']}</div>"
            html += "</div>"
    if not html.strip():
        html = "<p class='muted'>Brak danych.</p>"
    return html

def _onesixtyone_html(onesixtyone: dict) -> str:
    if not onesixtyone or onesixtyone.get("skipped"):
        return "<p class='muted'>Brak danych onesixtyone (narzędzie niedostępne lub SNMP nieosiągalny).</p>"
    html = ""
    # Stats grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    found = onesixtyone.get("total_found", 0)
    html += f"<div><span class='muted'>FOUND</span><br><span style='font-size:20px;font-weight:700;color:#ff4444'>{found}</span></div>"
    html += f"<div><span class='muted'>TESTED</span><br><span style='font-size:20px;font-weight:700;color:#8a9bb5'>{onesixtyone.get('total_tested', 0)}</span></div>"
    v_cnt = onesixtyone.get("total_vulnerabilities", 0)
    html += f"<div><span class='muted'>VULNS</span><br><span style='font-size:20px;font-weight:700;color:{'#ff4444' if v_cnt else '#3ddc84'}'>{v_cnt}</span></div>"
    html += "</div>"
    # Severity badges
    crit = onesixtyone.get("critical_count", 0)
    high = onesixtyone.get("high_count", 0)
    med = onesixtyone.get("medium_count", 0)
    if crit or high or med:
        badges = ""
        if crit:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #ff4444;color:#ff4444;background:rgba(255,68,68,.12);margin-right:6px'>CRITICAL: {crit}</span>"
        if high:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #ff4444;color:#ff4444;background:rgba(255,68,68,.08);margin-right:6px'>HIGH: {high}</span>"
        if med:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #f5c518;color:#f5c518;background:rgba(245,197,24,.08);margin-right:6px'>MEDIUM: {med}</span>"
        html += f"<div style='margin-bottom:12px'>{badges}</div>"
    # Community strings table
    communities = onesixtyone.get("communities_found", [])
    if communities:
        rows = ""
        for c in communities:
            risk = c.get("risk", "medium")
            r_col = "#ff4444" if risk in ("critical", "high") else "#f5c518"
            t_col = "#ff4444" if c.get("type") in ("write_access", "privileged") else "#f5c518" if c.get("type") == "default_read" else "#8a9bb5"
            type_label = (c.get("type") or "").replace("_", " ").upper()
            rows += f"<tr><td style='font-weight:700;font-size:11px;color:#e8f0fc'>{c.get('community','')}</td><td style='font-size:9px;color:{t_col}'>{type_label}</td><td style='font-size:9px;color:{r_col};font-weight:700'>{risk.upper()}</td><td style='font-size:9px;color:#8a9bb5'>{c.get('system_description','—')}</td></tr>"
        html += f"<div style='margin-bottom:10px'><div class='muted' style='margin-bottom:4px'>VALID COMMUNITY STRINGS ({len(communities)})</div><table><thead><tr><th>STRING</th><th>TYPE</th><th>RISK</th><th>SYSTEM</th></tr></thead><tbody>{rows}</tbody></table></div>"
    # Vulnerabilities
    vulns = onesixtyone.get("vulnerabilities", [])
    if vulns:
        for v in vulns:
            sev = v.get("severity", "medium")
            v_col = "#ff4444" if sev in ("critical", "high") else "#f5c518"
            mitre_badge = f"<span style='font-size:9px;padding:2px 6px;border:1px solid #5eead4;color:#5eead4;margin-left:6px'>{v['mitre']}</span>" if v.get("mitre") else ""
            html += f"<div style='border:1px solid {v_col};padding:10px;margin-bottom:6px'>"
            html += f"<div style='display:flex;justify-content:space-between;margin-bottom:4px'><span style='font-weight:700;color:#e8f0fc;font-size:11px'>{v['title']}</span><span style='font-size:9px;padding:2px 6px;border:1px solid {v_col};color:{v_col}'>{sev.upper()}</span></div>"
            html += f"<div style='font-size:10px;color:#8a9bb5;margin-bottom:4px'>{v.get('description','')}</div>"
            html += mitre_badge
            if v.get("remediation"):
                html += f"<div style='font-size:9px;color:#3ddc84;margin-top:6px;border-left:2px solid #3ddc84;padding-left:6px'>{v['remediation']}</div>"
            html += "</div>"
    if not html.strip():
        html = "<p class='muted'>Brak danych.</p>"
    return html

def _ikescan_html(ikescan: dict) -> str:
    if not ikescan or ikescan.get("skipped"):
        return "<p class='muted'>Brak danych ike-scan (narzędzie niedostępne lub brak usługi IKE).</p>"
    html = ""
    main = ikescan.get("main_mode") or {}
    agg = ikescan.get("aggressive_mode") or {}
    nat_t = ikescan.get("nat_t") or {}
    # Stats grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    m_col = "#3ddc84" if main.get("responded") else "#8a9bb5"
    html += f"<div><span class='muted'>MAIN MODE</span><br><span style='font-size:14px;font-weight:700;color:{m_col}'>{'ACTIVE' if main.get('responded') else 'N/A'}</span></div>"
    a_col = "#ff4444" if agg.get("responded") and agg.get("handshake") == "aggressive" else "#8a9bb5"
    html += f"<div><span class='muted'>AGGRESSIVE</span><br><span style='font-size:14px;font-weight:700;color:{a_col}'>{'ACTIVE' if agg.get('responded') and agg.get('handshake') == 'aggressive' else 'N/A'}</span></div>"
    n_col = "#f5c518" if nat_t.get("responded") else "#8a9bb5"
    html += f"<div><span class='muted'>NAT-T</span><br><span style='font-size:14px;font-weight:700;color:{n_col}'>{'ACTIVE' if nat_t.get('responded') else 'N/A'}</span></div>"
    html += f"<div><span class='muted'>TRANSFORMS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{ikescan.get('total_transforms', 0)}</span></div>"
    v_cnt = ikescan.get("total_vulnerabilities", 0)
    html += f"<div><span class='muted'>VULNS</span><br><span style='font-size:20px;font-weight:700;color:{'#ff4444' if v_cnt else '#3ddc84'}'>{v_cnt}</span></div>"
    if ikescan.get("implementation"):
        html += f"<div><span class='muted'>VENDOR</span><br><span style='font-size:14px;font-weight:700;color:#f5c518'>{ikescan['implementation']}</span></div>"
    html += "</div>"
    # Severity badges
    crit = ikescan.get("critical_count", 0)
    high = ikescan.get("high_count", 0)
    med = ikescan.get("medium_count", 0)
    if crit or high or med:
        badges = ""
        if crit:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #ff4444;color:#ff4444;background:rgba(255,68,68,.12);margin-right:6px'>CRITICAL: {crit}</span>"
        if high:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #ff4444;color:#ff4444;background:rgba(255,68,68,.08);margin-right:6px'>HIGH: {high}</span>"
        if med:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #f5c518;color:#f5c518;background:rgba(245,197,24,.08);margin-right:6px'>MEDIUM: {med}</span>"
        html += f"<div style='margin-bottom:12px'>{badges}</div>"
    # Transforms table
    transforms = ikescan.get("transforms", [])
    if transforms:
        rows = ""
        for t in transforms:
            s_col = "#ff4444" if t.get("strength") == "weak" else "#f5c518" if t.get("strength") == "moderate" else "#3ddc84"
            rows += f"<tr><td style='font-weight:700;font-size:10px'>{t.get('encryption','—')}</td><td style='font-size:9px'>{t.get('hash','—')}</td><td style='font-size:9px'>{t.get('dh_group','—')}</td><td style='font-size:9px'>{t.get('auth','—')}</td><td style='color:{s_col};font-size:9px;font-weight:700'>{t.get('strength','').upper()}</td></tr>"
        html += f"<div style='margin-bottom:10px'><div class='muted' style='margin-bottom:4px'>IKE TRANSFORMS ({len(transforms)})</div><table><thead><tr><th>ENCRYPTION</th><th>HASH</th><th>DH GROUP</th><th>AUTH</th><th>STRENGTH</th></tr></thead><tbody>{rows}</tbody></table></div>"
    # Vulnerabilities
    vulns = ikescan.get("vulnerabilities", [])
    if vulns:
        for v in vulns:
            sev = v.get("severity", "medium")
            v_col = "#ff4444" if sev in ("critical", "high") else "#f5c518" if sev == "medium" else "#8a9bb5"
            mitre_badge = f"<span style='font-size:9px;padding:2px 6px;border:1px solid #5eead4;color:#5eead4;margin-left:6px'>{v['mitre']}</span>" if v.get("mitre") else ""
            html += f"<div style='border:1px solid {v_col};padding:10px;margin-bottom:6px'>"
            html += f"<div style='display:flex;justify-content:space-between;margin-bottom:4px'><span style='font-weight:700;color:#e8f0fc;font-size:11px'>{v['title']}</span><span style='font-size:9px;padding:2px 6px;border:1px solid {v_col};color:{v_col}'>{sev.upper()}</span></div>"
            html += f"<div style='font-size:10px;color:#8a9bb5;margin-bottom:4px'>{v.get('description','')}</div>"
            html += mitre_badge
            if v.get("remediation"):
                html += f"<div style='font-size:9px;color:#3ddc84;margin-top:6px;border-left:2px solid #3ddc84;padding-left:6px'>{v['remediation']}</div>"
            html += "</div>"
    if not html.strip():
        html = "<p class='muted'>Brak danych.</p>"
    return html

def _sslyze_html(sslyze: dict) -> str:
    if not sslyze or sslyze.get("skipped"):
        return "<p class='muted'>Brak danych SSLyze (narzędzie niedostępne lub brak usługi SSL/TLS).</p>"
    html = ""
    # Stats grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    html += f"<div><span class='muted'>ACCEPTED CIPHERS</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{sslyze.get('total_accepted_ciphers', 0)}</span></div>"
    wk = sslyze.get("total_weak_ciphers", 0)
    html += f"<div><span class='muted'>WEAK CIPHERS</span><br><span style='font-size:20px;font-weight:700;color:{'#ff4444' if wk else '#3ddc84'}'>{wk}</span></div>"
    v_cnt = sslyze.get("total_vulnerabilities", 0)
    html += f"<div><span class='muted'>VULNERABILITIES</span><br><span style='font-size:20px;font-weight:700;color:{'#ff4444' if v_cnt else '#3ddc84'}'>{v_cnt}</span></div>"
    # Protocol badges
    protocols = sslyze.get("protocols", {})
    for p in ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"]:
        pd = protocols.get(p, {})
        if pd.get("supported"):
            p_col = "#ff4444" if p in ("SSLv2", "SSLv3") else "#f5c518" if p in ("TLSv1.0", "TLSv1.1") else "#3ddc84"
            html += f"<div><span class='muted'>{p}</span><br><span style='font-size:14px;font-weight:700;color:{p_col}'>ENABLED ({pd.get('cipher_count', 0)})</span></div>"
    html += "</div>"
    # Certificate info
    cert = sslyze.get("certificate", {})
    if cert.get("subject") or cert.get("issuer"):
        html += "<div class='muted' style='margin-bottom:4px'>CERTIFICATE</div>"
        html += "<div style='display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;background:rgba(0,0,0,.2);padding:10px'>"
        if cert.get("subject"):
            html += f"<div><span class='muted'>SUBJECT</span><br><span style='font-size:10px;color:#e8f0fc;word-break:break-all'>{cert['subject']}</span></div>"
        if cert.get("issuer"):
            html += f"<div><span class='muted'>ISSUER</span><br><span style='font-size:10px;color:#8a9bb5'>{cert['issuer']}</span></div>"
        if cert.get("not_before"):
            html += f"<div><span class='muted'>VALID FROM</span><br><span style='font-size:10px;color:#8a9bb5'>{cert['not_before']}</span></div>"
        if cert.get("not_after"):
            html += f"<div><span class='muted'>VALID UNTIL</span><br><span style='font-size:10px;color:#8a9bb5'>{cert['not_after']}</span></div>"
        if cert.get("key_type"):
            ks = f" {cert['key_size']}-bit" if cert.get("key_size") else ""
            html += f"<div><span class='muted'>KEY</span><br><span style='font-size:10px;color:#e8f0fc'>{cert['key_type']}{ks}</span></div>"
        hm = cert.get("hostname_match")
        hm_col = "#ff4444" if hm is False else "#3ddc84" if hm is True else "#8a9bb5"
        hm_txt = "MISMATCH" if hm is False else "MATCH" if hm is True else "N/A"
        html += f"<div><span class='muted'>HOSTNAME</span><br><span style='font-size:14px;font-weight:700;color:{hm_col}'>{hm_txt}</span></div>"
        html += "</div>"
    # Severity badges
    crit = sslyze.get("critical_count", 0)
    high = sslyze.get("high_count", 0)
    med = sslyze.get("medium_count", 0)
    low = sslyze.get("low_count", 0)
    if crit or high or med or low:
        badges = ""
        if crit:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #ff4444;color:#ff4444;background:rgba(255,68,68,.12);margin-right:6px'>CRITICAL: {crit}</span>"
        if high:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #ff4444;color:#ff4444;background:rgba(255,68,68,.08);margin-right:6px'>HIGH: {high}</span>"
        if med:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #f5c518;color:#f5c518;background:rgba(245,197,24,.08);margin-right:6px'>MEDIUM: {med}</span>"
        if low:
            badges += f"<span style='display:inline-block;font-size:10px;padding:3px 10px;border:1px solid #5eead4;color:#5eead4;background:rgba(0,180,216,.08);margin-right:6px'>LOW: {low}</span>"
        html += f"<div style='margin-bottom:12px'>{badges}</div>"
    # Weak ciphers table
    weak_ciphers = sslyze.get("weak_ciphers", [])
    if weak_ciphers:
        rows = ""
        for c in weak_ciphers[:20]:
            rows += f"<tr><td style='font-size:9px;color:#ff4444'>{c.get('name', '')}</td><td style='font-size:9px'>{c.get('protocol', '')}</td></tr>"
        if len(weak_ciphers) > 20:
            rows += f"<tr><td colspan='2' style='font-size:9px;color:#8a9bb5'>...and {len(weak_ciphers)-20} more</td></tr>"
        html += f"<div style='margin-bottom:10px'><div class='muted' style='margin-bottom:4px'>WEAK CIPHERS ({len(weak_ciphers)})</div><table><thead><tr><th>CIPHER SUITE</th><th>PROTOCOL</th></tr></thead><tbody>{rows}</tbody></table></div>"
    # Vulnerabilities
    vulns = sslyze.get("vulnerabilities", [])
    if vulns:
        for v in vulns:
            sev = v.get("severity", "medium")
            v_col = "#ff4444" if sev in ("critical", "high") else "#f5c518" if sev == "medium" else "#5eead4"
            mitre_badge = f"<span style='font-size:9px;padding:2px 6px;border:1px solid #5eead4;color:#5eead4;margin-left:6px'>{v['mitre']}</span>" if v.get("mitre") else ""
            html += f"<div style='border:1px solid {v_col};padding:10px;margin-bottom:6px'>"
            html += f"<div style='display:flex;justify-content:space-between;margin-bottom:4px'><span style='font-weight:700;color:#e8f0fc;font-size:11px'>{v['title']}</span><span style='font-size:9px;padding:2px 6px;border:1px solid {v_col};color:{v_col}'>{sev.upper()}</span></div>"
            html += f"<div style='font-size:10px;color:#8a9bb5;margin-bottom:4px'>{v.get('description','')}</div>"
            html += mitre_badge
            if v.get("remediation"):
                html += f"<div style='font-size:9px;color:#3ddc84;margin-top:6px;border-left:2px solid #3ddc84;padding-left:6px'>{v['remediation']}</div>"
            html += "</div>"
    if not html.strip():
        html = "<p class='muted'>Brak danych.</p>"
    return html

def _searchsploit_html(searchsploit: dict) -> str:
    if not searchsploit or searchsploit.get("skipped"):
        return "<p class='muted'>Brak danych SearchSploit (narzędzie niedostępne lub brak serwisów z wersjami).</p>"
    html = ""
    summary = searchsploit.get("summary", {})
    # Stats grid
    html += "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'>"
    html += f"<div><span class='muted'>TOTAL</span><br><span style='font-size:20px;font-weight:700;color:#ff4444'>{searchsploit.get('total_exploits', 0)}</span></div>"
    rem = summary.get("remote", 0)
    html += f"<div><span class='muted'>REMOTE</span><br><span style='font-size:20px;font-weight:700;color:{'#ff4444' if rem else '#3ddc84'}'>{rem}</span></div>"
    loc = summary.get("local", 0)
    html += f"<div><span class='muted'>LOCAL</span><br><span style='font-size:20px;font-weight:700;color:{'#f5c518' if loc else '#3ddc84'}'>{loc}</span></div>"
    dos = summary.get("dos", 0)
    html += f"<div><span class='muted'>DoS</span><br><span style='font-size:20px;font-weight:700;color:{'#f5c518' if dos else '#3ddc84'}'>{dos}</span></div>"
    wap = summary.get("webapps", 0)
    html += f"<div><span class='muted'>WEBAPPS</span><br><span style='font-size:20px;font-weight:700;color:{'#f5c518' if wap else '#3ddc84'}'>{wap}</span></div>"
    html += f"<div><span class='muted'>SERVICES</span><br><span style='font-size:20px;font-weight:700;color:#e8f0fc'>{searchsploit.get('services_scanned', 0)}</span></div>"
    html += "</div>"
    # Remote alert
    if rem > 0:
        crit_svcs = ", ".join(searchsploit.get("critical_services", []))
        html += f"<div style='border:1px solid #ff4444;background:rgba(255,68,68,.08);padding:10px;margin-bottom:12px'>"
        html += f"<span style='font-weight:700;color:#ff4444;font-size:11px'>&#9888; REMOTE EXPLOITS FOUND</span>"
        html += f"<div style='font-size:10px;color:#8a9bb5;margin-top:4px'>{rem} remote exploits for: {crit_svcs}</div>"
        html += "</div>"
    # By service tables
    by_service = searchsploit.get("by_service", {})
    for svc, exs in by_service.items():
        html += f"<div class='muted' style='margin:10px 0 4px'>{svc.upper()} ({len(exs)} exploits)</div>"
        rows = ""
        for e in exs[:15]:
            t_col = "#ff4444" if e.get("type") == "remote" else "#f5c518" if e.get("type") in ("local", "dos") else "#5eead4"
            rows += f"<tr><td style='font-size:9px;color:#5eead4'><a href='{e.get('url','')}' style='color:#5eead4'>{e.get('edb_id','')}</a></td>"
            rows += f"<td style='font-size:9px;color:#e8f0fc'>{e.get('title','')[:80]}</td>"
            rows += f"<td><span style='font-size:8px;padding:1px 5px;border:1px solid {t_col};color:{t_col}'>{e.get('type','').upper()}</span></td>"
            rows += f"<td style='font-size:9px'>{e.get('platform','')}</td>"
            rows += f"<td style='font-size:9px;color:#8a9bb5'>{e.get('date','')}</td></tr>"
        if len(exs) > 15:
            rows += f"<tr><td colspan='5' style='font-size:9px;color:#8a9bb5'>...and {len(exs)-15} more</td></tr>"
        html += f"<table><thead><tr><th>EDB-ID</th><th>TITLE</th><th>TYPE</th><th>PLATFORM</th><th>DATE</th></tr></thead><tbody>{rows}</tbody></table>"
    if not html.strip():
        html = "<p class='muted'>Brak danych.</p>"
    return html

def _mitre_html(mitre: dict) -> str:
    techniques = mitre.get("techniques", [])
    if not techniques:
        return "<p class='muted'>Brak mapowań MITRE ATT&CK.</p>"
    conf_color = {"high": "#ff4444", "medium": "#f5c518", "low": "#8a9bb5"}
    badges = ""
    for level in ["high", "medium", "low"]:
        cnt = mitre.get(f"{level}_count", 0)
        if cnt:
            badges += f"<span style='color:{conf_color[level]};font-size:10px;border:1px solid {conf_color[level]};padding:2px 8px;margin-right:6px'>{level.upper()}: {cnt}</span>"
    rows = ""
    for t in techniques[:25]:
        conf = t.get("confidence", "low")
        color = conf_color.get(conf, "#8a9bb5")
        rows += f"<tr><td class='mono'>{t.get('technique_id','')}</td><td>{t.get('technique_name','')}</td><td>{t.get('tactic','')}</td><td style='color:{color}'>{conf.upper()}</td><td style='font-size:10px'>{t.get('triggered_by','')}</td></tr>"
    return f"""<div style='margin-bottom:10px'>{badges}</div>
    <table>
        <thead><tr><th>TECHNIQUE</th><th>NAME</th><th>TACTIC</th><th>CONFIDENCE</th><th>TRIGGERED BY</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>"""

def generate_report(scan_data: dict) -> bytes:
    target = scan_data.get("target", "unknown")
    analysis = scan_data.get("analysis", {})
    risk = analysis.get("risk_level", scan_data.get("risk_level", "N/A"))
    findings_count = scan_data.get("findings_count", 0)
    summary = analysis.get("summary", scan_data.get("summary", ""))
    top_issues = analysis.get("top_issues", scan_data.get("top_issues", []))
    recommendations = analysis.get("recommendations", scan_data.get("recommendations", ""))
    completed_at = scan_data.get("completed_at", datetime.utcnow().isoformat())
    ports = scan_data.get("ports", [])
    whatweb = scan_data.get("whatweb", {})
    gobuster = scan_data.get("gobuster", {})
    testssl = scan_data.get("testssl", {})
    sqlmap = scan_data.get("sqlmap", {})
    exploit_chains = scan_data.get("exploit_chains", {})
    hacker_narrative = scan_data.get("hacker_narrative", {})
    fp_filter = scan_data.get("fp_filter", {})
    nuclei = scan_data.get("nuclei", {})
    nikto = scan_data.get("nikto", {})
    harvester = scan_data.get("harvester", {})
    masscan = scan_data.get("masscan", {})
    ipinfo = scan_data.get("ipinfo", {})
    enum4linux = scan_data.get("enum4linux", {})
    abuseipdb = scan_data.get("abuseipdb", {})
    otx = scan_data.get("otx", {})
    exploitdb = scan_data.get("exploitdb", {})
    nvd = scan_data.get("nvd", {})
    whois = scan_data.get("whois", {})
    mitre = scan_data.get("mitre", {})
    dnsrecon = scan_data.get("dnsrecon", {})
    amass = scan_data.get("amass", {})
    cwe = scan_data.get("cwe", {})
    owasp = scan_data.get("owasp", {})
    wpscan = scan_data.get("wpscan", {})
    zap = scan_data.get("zap", {})
    wapiti = scan_data.get("wapiti", {})
    joomscan = scan_data.get("joomscan", {})
    cmsmap = scan_data.get("cmsmap", {})
    droopescan = scan_data.get("droopescan", {})
    retirejs = scan_data.get("retirejs", {})
    subfinder = scan_data.get("subfinder", {})
    httpx = scan_data.get("httpx", {})
    naabu = scan_data.get("naabu", {})
    katana = scan_data.get("katana", {})
    dnsx = scan_data.get("dnsx", {})
    netdiscover = scan_data.get("netdiscover", {})
    arpscan = scan_data.get("arpscan", {})
    fping = scan_data.get("fping", {})
    traceroute = scan_data.get("traceroute", {})
    nbtscan = scan_data.get("nbtscan", {})
    snmpwalk = scan_data.get("snmpwalk", {})
    netexec = scan_data.get("netexec", {})
    bloodhound = scan_data.get("bloodhound", {})
    responder = scan_data.get("responder", {})
    fierce = scan_data.get("fierce", {})
    smbmap = scan_data.get("smbmap", {})
    onesixtyone = scan_data.get("onesixtyone", {})
    ikescan = scan_data.get("ikescan", {})
    sslyze = scan_data.get("sslyze", {})
    searchsploit = scan_data.get("searchsploit", {})

    color = _risk_color(risk)

    issues_html = ""
    for i, issue in enumerate(top_issues, 1):
        issues_html += f'<div class="issue"><span class="issue-num">{i:02d}</span><span>{issue}</span></div>'

    fp_html = ""
    if fp_filter.get("original_count", 0) > 0:
        fp_html = f"""<div class='fp-bar'>
            <span class='muted'>FILTRACJA FP:</span>
            <span>{fp_filter.get('filtered_count',0)} / {fp_filter.get('original_count',0)} findings</span>
            <span class='ok'>usunięto {fp_filter.get('removed',0)} fałszywych alarmów</span>
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Rajdhani', sans-serif; background:#080c18; color:#b8ccec; padding:40px; font-size:13px; }}
  .mono {{ font-family: monospace; }}
  .muted {{ color:#4a8fd4; font-size:11px; }}
  .danger {{ color:#ff4444; }}
  .ok {{ color:#3ddc84; }}

  .header {{ border-bottom:2px solid #4a8fd4; padding-bottom:24px; margin-bottom:32px; display:flex; justify-content:space-between; align-items:flex-end; }}
  .brand {{ font-size:36px; font-weight:700; letter-spacing:0.3em; color:#e8f0fc; }}
  .brand-sub {{ font-size:10px; color:#4a8fd4; letter-spacing:0.3em; margin-top:4px; }}
  .report-meta {{ text-align:right; font-size:10px; color:#4a8fd4; line-height:1.8; }}

  .risk-banner {{ background:rgba(74,143,212,0.08); border:1px solid {color}; padding:16px 24px; margin-bottom:24px; display:flex; justify-content:space-between; align-items:center; }}
  .risk-value {{ font-size:22px; font-weight:700; letter-spacing:0.2em; color:{color}; }}
  .risk-stats {{ font-size:11px; color:#4a8fd4; text-align:right; line-height:1.8; }}

  .section {{ margin-bottom:28px; page-break-inside:avoid; }}
  .section-title {{ font-size:10px; color:#4a8fd4; letter-spacing:0.3em; border-bottom:1px solid rgba(74,143,212,0.2); padding-bottom:6px; margin-bottom:14px; }}
  .summary-text {{ font-size:13px; line-height:1.75; }}
  .rec-text {{ font-size:13px; line-height:1.85; white-space:pre-wrap; }}

  .issue {{ display:flex; gap:14px; padding:10px 0; border-bottom:1px solid rgba(74,143,212,0.1); font-size:13px; line-height:1.6; }}
  .issue:last-child {{ border-bottom:none; }}
  .issue-num {{ font-size:10px; color:#4a8fd4; flex-shrink:0; margin-top:2px; min-width:22px; }}

  table {{ width:100%; border-collapse:collapse; font-size:11px; margin-top:8px; }}
  th {{ text-align:left; font-size:9px; letter-spacing:0.2em; color:#4a8fd4; padding:6px 8px; border-bottom:1px solid rgba(74,143,212,0.3); }}
  td {{ padding:8px; border-bottom:1px solid rgba(74,143,212,0.08); }}

  .chain-block {{ background:rgba(74,143,212,0.05); border:1px solid rgba(74,143,212,0.2); padding:14px; margin-bottom:14px; }}
  .chain-header {{ display:flex; justify-content:space-between; margin-bottom:6px; }}
  .chain-name {{ font-size:14px; font-weight:600; color:#e8f0fc; }}
  .chain-impact {{ font-size:11px; font-weight:600; }}
  .chain-meta {{ font-size:10px; margin-bottom:10px; }}
  .chain-step {{ padding:6px 0; border-bottom:1px solid rgba(74,143,212,0.08); display:flex; flex-direction:column; gap:2px; }}
  .step-num {{ font-size:9px; color:#4a8fd4; letter-spacing:0.2em; }}
  .step-action {{ font-size:12px; color:#e8f0fc; }}
  .step-vuln {{ font-size:10px; }}
  .step-result {{ font-size:11px; color:#3ddc84; }}
  .chain-final {{ font-size:12px; color:#ff8c00; margin-top:8px; }}
  .chain-biz {{ font-size:11px; margin-top:4px; }}

  .narrative-box {{ background:rgba(74,143,212,0.04); border-left:3px solid #4a8fd4; padding:16px; margin-bottom:16px; }}
  .narrative-text {{ font-size:13px; line-height:1.9; font-style:italic; }}
  .narrative-stats {{ display:flex; gap:24px; margin-bottom:12px; }}
  .nstat {{ display:flex; flex-direction:column; gap:2px; }}
  .nstat span:last-child {{ font-size:14px; font-weight:600; }}
  .exec-summary {{ background:rgba(74,143,212,0.08); border:1px solid rgba(74,143,212,0.3); padding:12px; font-size:13px; line-height:1.7; }}

  .fp-bar {{ display:flex; gap:16px; align-items:center; background:rgba(61,220,132,0.06); border:1px solid rgba(61,220,132,0.2); padding:8px 14px; margin-bottom:14px; font-size:11px; }}
  .sqli-result {{ border:1px solid; padding:12px; display:flex; gap:16px; align-items:center; }}
  .sqli-label {{ font-size:14px; font-weight:700; }}
  .grade-box {{ display:flex; gap:12px; align-items:center; margin-bottom:12px; }}
  .grade {{ font-size:28px; font-weight:700; }}

  .footer {{ margin-top:48px; padding-top:16px; border-top:1px solid rgba(74,143,212,0.2); font-size:9px; color:rgba(74,143,212,0.3); text-align:center; letter-spacing:0.2em; }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="brand">CYRBER</div>
    <div class="brand-sub">AUTONOMOUS SECURITY RECONNAISSANCE PLATFORM</div>
  </div>
  <div class="report-meta">
    SECURITY ASSESSMENT REPORT<br>
    TARGET: {target}<br>
    DATE: {completed_at[:10]}<br>
    GENERATED: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC
  </div>
</div>

<div class="risk-banner">
  <div>
    <div class="muted">OVERALL THREAT LEVEL</div>
    <div class="risk-value">{risk}</div>
  </div>
  <div class="risk-stats">
    FINDINGS: {findings_count}<br>
    TARGET: {target}
  </div>
</div>

{fp_html}

<div class="section">
  <div class="section-title">// PERSPEKTYWA HAKERA</div>
  {_narrative_html(hacker_narrative)}
</div>

<div class="section">
  <div class="section-title">// EXECUTIVE SUMMARY</div>
  <div class="summary-text">{summary}</div>
</div>

<div class="section">
  <div class="section-title">// KRYTYCZNE FINDINGS</div>
  {issues_html if issues_html else "<p class='muted'>Brak krytycznych findings.</p>"}
</div>

<div class="section">
  <div class="section-title">// ŁAŃCUCHY EXPLOITÓW</div>
  {_chains_html(exploit_chains)}
</div>

<div class="section">
  <div class="section-title">// OTWARTE PORTY</div>
  {_ports_html(ports)}
</div>

<div class="section">
  <div class="section-title">// KATALOGI I ŚCIEŻKI (GOBUSTER)</div>
  {_gobuster_html(gobuster)}
</div>

<div class="section">
  <div class="section-title">// WHATWEB — TECHNOLOGIES</div>
  {_whatweb_html(whatweb)}
</div>

<div class="section">
  <div class="section-title">// WPSCAN — WORDPRESS SECURITY</div>
  {_wpscan_html(wpscan)}
</div>

<div class="section">
  <div class="section-title">// SQL INJECTION (SQLMAP)</div>
  {_sqlmap_html(sqlmap)}
</div>

<div class="section">
  <div class="section-title">// BEZPIECZEŃSTWO TLS (TESTSSL)</div>
  {_testssl_html(testssl)}
</div>

<div class="section">
  <div class="section-title">// NUCLEI — VULNERABILITY SCANNER</div>
  {_nuclei_html(nuclei)}
</div>

<div class="section">
  <div class="section-title">// NIKTO — WEB VULNERABILITIES</div>
  {_nikto_html(nikto)}
</div>

<div class="section">
  <div class="section-title">// THEHARVESTER — OSINT</div>
  {_harvester_html(harvester)}
</div>

<div class="section">
  <div class="section-title">// MASSCAN — FAST PORT SCAN</div>
  {_masscan_html(masscan)}
</div>

<div class="section">
  <div class="section-title">// IPINFO — IP ENRICHMENT</div>
  {_ipinfo_html(ipinfo)}
</div>

<div class="section">
  <div class="section-title">// WHOIS — {'DOMAIN REGISTRATION' if whois.get('type') == 'domain' else 'IP OWNERSHIP'}</div>
  {_whois_html(whois)}
</div>

<div class="section">
  <div class="section-title">// DNSRECON — DNS RECONNAISSANCE</div>
  {_dnsrecon_html(dnsrecon)}
</div>

<div class="section">
  <div class="section-title">// AMASS — SUBDOMAIN ENUMERATION ({amass.get('total_count', 0)} subdomains)</div>
  {_amass_html(amass)}
</div>

<div class="section">
  <div class="section-title">// ENUM4LINUX-NG — SMB/AD ENUMERATION ({enum4linux.get('summary', {{}}).get('users_count', 0)} users, {enum4linux.get('summary', {{}}).get('shares_count', 0)} shares, {enum4linux.get('summary', {{}}).get('groups_count', 0)} groups)</div>
  {_enum4linux_html(enum4linux)}
</div>

<div class="section">
  <div class="section-title">// ABUSEIPDB — IP REPUTATION</div>
  {_abuseipdb_html(abuseipdb)}
</div>

<div class="section">
  <div class="section-title">// ALIENVAULT OTX — THREAT INTELLIGENCE</div>
  {_otx_html(otx)}
</div>

<div class="section">
  <div class="section-title">// EXPLOIT-DB — PUBLIC EXPLOITS ({len(exploitdb.get('exploits', []))})</div>
  {_exploitdb_html(exploitdb)}
</div>

<div class="section">
  <div class="section-title">// NVD — CVE DETAILS ({len(nvd.get('cves', []))})</div>
  {_nvd_html(nvd)}
</div>

<div class="section">
  <div class="section-title">// CWE — COMMON WEAKNESS ENUMERATION ({len(cwe.get('cwes', []))} weaknesses)</div>
  {_cwe_html(cwe)}
</div>

<div class="section">
  <div class="section-title">// OWASP TOP 10 2021 ({owasp.get('detected_count', 0)}/10 detected)</div>
  {_owasp_html(owasp)}
</div>

<div class="section">
  <div class="section-title">// OWASP ZAP — DYNAMIC ANALYSIS ({zap.get('summary', {}).get('total', 0)} alerts)</div>
  {_zap_html(zap)}
</div>

<div class="section">
  <div class="section-title">// WAPITI — WEB APPLICATION SCANNER ({wapiti.get('summary', {}).get('total', 0)} vulnerabilities)</div>
  {_wapiti_html(wapiti)}
</div>

<div class="section">
  <div class="section-title">// JOOMSCAN — JOOMLA SECURITY ({joomscan.get('summary', {}).get('total_vulns', 0)} vulnerabilities)</div>
  {_joomscan_html(joomscan)}
</div>

<div class="section">
  <div class="section-title">// CMSMAP — CMS SCANNER ({cmsmap.get('cms_detected', 'N/A')} · {cmsmap.get('summary', {}).get('total_vulns', 0)} vulnerabilities)</div>
  {_cmsmap_html(cmsmap)}
</div>

<div class="section">
  <div class="section-title">// DROOPESCAN — CMS ENUMERATION ({droopescan.get('cms_detected', 'N/A')} · {droopescan.get('summary', {}).get('plugins_count', 0)} plugins)</div>
  {_droopescan_html(droopescan)}
</div>

<div class="section">
  <div class="section-title">// RETIRE.JS — VULNERABLE JAVASCRIPT ({retirejs.get('summary', {}).get('vulnerable_libs', 0)} vulnerable / {retirejs.get('summary', {}).get('total_libs', 0)} libs)</div>
  {_retirejs_html(retirejs)}
</div>

<div class="section">
  <div class="section-title">// SUBFINDER — PASSIVE SUBDOMAIN ENUMERATION ({subfinder.get('total_count', 0)} subdomains)</div>
  {_subfinder_html(subfinder)}
</div>

<div class="section">
  <div class="section-title">// HTTPX — HTTP PROBING ({httpx.get('summary', {}).get('live', 0)} live / {httpx.get('summary', {}).get('probed', 0)} probed)</div>
  {_httpx_html(httpx)}
</div>

<div class="section">
  <div class="section-title">// NAABU — FAST PORT SCANNER ({naabu.get('summary', {}).get('total_open', 0)} open ports / {naabu.get('summary', {}).get('scanned', 0)} hosts)</div>
  {_naabu_html(naabu)}
</div>

<div class="section">
  <div class="section-title">// KATANA — WEB CRAWLER ({katana.get('summary', {}).get('total_urls', 0)} URLs / {katana.get('summary', {}).get('interesting_files', 0)} interesting)</div>
  {_katana_html(katana)}
</div>

<div class="section">
  <div class="section-title">// DNSX — DNS RESOLUTION ({dnsx.get('summary', {}).get('resolved', 0)} resolved / {dnsx.get('summary', {}).get('queried', 0)} queried)</div>
  {_dnsx_html(dnsx)}
</div>

<div class="section">
  <div class="section-title">// NETDISCOVER — NETWORK DISCOVERY ({netdiscover.get('total_hosts', 0)} hosts on {netdiscover.get('network_range', 'N/A')})</div>
  {_netdiscover_html(netdiscover)}
</div>

<div class="section">
  <div class="section-title">// ARP-SCAN — ARP HOST DISCOVERY ({arpscan.get('total_hosts', 0)} hosts on {arpscan.get('network_range', 'N/A')})</div>
  {_arpscan_html(arpscan)}
</div>

<div class="section">
  <div class="section-title">// FPING — ICMP PING SWEEP ({fping.get('total_alive', 0)} alive / {fping.get('total_scanned', 0)} scanned)</div>
  {_fping_html(fping)}
</div>

<div class="section">
  <div class="section-title">// TRACEROUTE — NETWORK PATH ({traceroute.get('total_hops', 0)} hops to {traceroute.get('destination', '?')})</div>
  {_traceroute_html(traceroute)}
</div>

<div class="section">
  <div class="section-title">// NBTSCAN — NETBIOS ENUMERATION ({nbtscan.get('total_hosts', 0)} hosts, {nbtscan.get('total_servers', 0)} servers, {nbtscan.get('total_dcs', 0)} DCs)</div>
  {_nbtscan_html(nbtscan)}
</div>

<div class="section">
  <div class="section-title">// SNMPWALK — SNMP ENUMERATION ({snmpwalk.get('total_interfaces', 0)} interfaces, {snmpwalk.get('active_interfaces', 0)} active, {snmpwalk.get('total_services', 0)} services)</div>
  {_snmpwalk_html(snmpwalk)}
</div>

<div class="section">
  <div class="section-title">// NETEXEC — SMB ENUMERATION ({netexec.get('smb_info', {{}}).get('hostname', 'N/A')} · {netexec.get('total_shares', 0)} shares, {netexec.get('total_users', 0)} users, {netexec.get('total_vulnerabilities', 0)} vulns)</div>
  {_netexec_html(netexec)}
</div>

<div class="section">
  <div class="section-title">// BLOODHOUND — AD ATTACK PATHS ({bloodhound.get('total_users', 0)} users, {bloodhound.get('total_computers', 0)} computers, {bloodhound.get('total_attack_paths', 0)} attack paths)</div>
  {_bloodhound_html(bloodhound)}
</div>

<div class="section">
  <div class="section-title">// RESPONDER — NETWORK POISONING DETECTION ({responder.get('total_protocols', 0)} protocols, {responder.get('total_vulnerabilities', 0)} vulns)</div>
  {_responder_html(responder)}
</div>

<div class="section">
  <div class="section-title">// FIERCE — DNS RECONNAISSANCE ({fierce.get('total_subdomains', 0)} subdomains, {fierce.get('total_nameservers', 0)} NS, {fierce.get('total_nearby', 0)} nearby)</div>
  {_fierce_html(fierce)}
</div>

<div class="section">
  <div class="section-title">// SMBMAP — SMB SHARE ENUMERATION ({smbmap.get('total_shares', 0)} shares, {smbmap.get('readable_shares', 0)} readable, {smbmap.get('writable_shares', 0)} writable)</div>
  {_smbmap_html(smbmap)}
</div>

<div class="section">
  <div class="section-title">// ONESIXTYONE — SNMP COMMUNITY STRINGS ({onesixtyone.get('total_found', 0)} found / {onesixtyone.get('total_tested', 0)} tested)</div>
  {_onesixtyone_html(onesixtyone)}
</div>

<div class="section">
  <div class="section-title">// IKE-SCAN — VPN GATEWAY ({ikescan.get('implementation', 'Unknown')} · {ikescan.get('total_transforms', 0)} transforms)</div>
  {_ikescan_html(ikescan)}
</div>

<div class="section">
  <div class="section-title">// SSLyze — SSL/TLS ANALYSIS ({sslyze.get('total_accepted_ciphers', 0)} ciphers · {sslyze.get('total_weak_ciphers', 0)} weak · {sslyze.get('total_vulnerabilities', 0)} vulns)</div>
  {_sslyze_html(sslyze)}
</div>

<div class="section">
  <div class="section-title">// SEARCHSPLOIT — EXPLOIT-DB ({searchsploit.get('total_exploits', 0)} exploits · {searchsploit.get('services_scanned', 0)} services · {searchsploit.get('summary', {}).get('remote', 0)} remote)</div>
  {_searchsploit_html(searchsploit)}
</div>

<div class="section">
  <div class="section-title">// MITRE ATT&CK MAPPING ({len(mitre.get('techniques', []))} techniques)</div>
  {_mitre_html(mitre)}
</div>

<div class="section">
  <div class="section-title">// REKOMENDACJE</div>
  <div class="rec-text">{recommendations}</div>
</div>

<div class="footer">
  CYRBER · AUTONOMOUS RECON · CONFIDENTIAL · FOR AUTHORIZED USE ONLY · v0.2.0
</div>

</body>
</html>"""

    pdf = HTML(string=html_content, base_url=".").write_pdf()
    return pdf


def generate_osint_report(scan_data: dict) -> bytes:
    """Generate PDF report for OSINT scan results."""
    target = scan_data.get("target", "unknown")
    search_type = scan_data.get("search_type", "domain")
    summary = scan_data.get("summary", {})
    completed_at = scan_data.get("completed_at", datetime.utcnow().isoformat())

    # Emails section
    emails = scan_data.get("emails", [])
    emails_html = ""
    if emails:
        items = "".join(f"<div class='mono' style='padding:2px 0;color:#9b59b6'>{e}</div>" for e in emails[:50])
        emails_html = f"<div class='muted' style='margin-bottom:4px'>EMAILS ({len(emails)})</div>{items}"
    else:
        emails_html = "<p class='muted'>No emails discovered.</p>"

    # Subdomains section
    subdomains = scan_data.get("subdomains", [])
    subs_html = ""
    if subdomains:
        tags = " ".join(f"<span class='mono' style='font-size:10px;color:#7ab3e8'>{s}</span>" for s in subdomains[:80])
        extra = f" <span class='muted'>... and {len(subdomains)-80} more</span>" if len(subdomains) > 80 else ""
        subs_html = f"<div class='muted' style='margin-bottom:4px'>SUBDOMAINS ({len(subdomains)})</div><div>{tags}{extra}</div>"
    else:
        subs_html = "<p class='muted'>No subdomains discovered.</p>"

    # IP addresses section
    ips = scan_data.get("ip_addresses", [])
    ips_html = ""
    if ips:
        items = " ".join(f"<span class='mono' style='font-size:11px'>{ip}</span>" for ip in ips[:50])
        ips_html = f"<div class='muted' style='margin-bottom:4px'>IP ADDRESSES ({len(ips)})</div><div>{items}</div>"
    else:
        ips_html = "<p class='muted'>No IP addresses discovered.</p>"

    # DNS records section
    dns_records = scan_data.get("dns_records", {})
    dns_html = ""
    a_recs = dns_records.get("a_records", [])
    if a_recs:
        rows = "".join(f"<tr><td>{r.get('hostname','')}</td><td class='mono'>{r.get('ip','')}</td><td>{r.get('type','A')}</td></tr>" for r in a_recs[:20])
        dns_html += f"<div class='muted' style='margin-bottom:4px'>A / AAAA RECORDS ({len(a_recs)})</div><table><thead><tr><th>HOSTNAME</th><th>IP</th><th>TYPE</th></tr></thead><tbody>{rows}</tbody></table>"
    mx_recs = dns_records.get("mx_records", [])
    if mx_recs:
        rows = "".join(f"<tr><td>{r.get('exchange','')}</td><td>{r.get('priority','')}</td></tr>" for r in mx_recs)
        dns_html += f"<div class='muted' style='margin:10px 0 4px'>MX RECORDS ({len(mx_recs)})</div><table><thead><tr><th>EXCHANGE</th><th>PRIORITY</th></tr></thead><tbody>{rows}</tbody></table>"
    ns_recs = dns_records.get("ns_records", [])
    if ns_recs:
        ns_items = " ".join(f"<span class='mono' style='font-size:11px;margin-right:8px'>{ns}</span>" for ns in ns_recs)
        dns_html += f"<div class='muted' style='margin:10px 0 4px'>NAME SERVERS ({len(ns_recs)})</div><div>{ns_items}</div>"
    txt_recs = dns_records.get("txt_records", [])
    if txt_recs:
        txt_items = "".join(f"<div style='margin-bottom:4px'><span style='color:#4a8fd4;font-size:10px'>{r.get('type','TXT')}</span> <span style='font-size:10px;word-break:break-all'>{r.get('value','')}</span></div>" for r in txt_recs[:10])
        dns_html += f"<div class='muted' style='margin:10px 0 4px'>TXT RECORDS ({len(txt_recs)})</div>{txt_items}"
    if not dns_html:
        dns_html = "<p class='muted'>No DNS records.</p>"

    # WHOIS section
    whois_info = scan_data.get("whois_info", {})
    whois_html = _whois_html(whois_info) if whois_info else "<p class='muted'>No WHOIS data.</p>"

    # Risk indicators section
    risk_indicators = scan_data.get("risk_indicators", [])
    risk_html = ""
    if risk_indicators:
        sev_color = {"critical": "#ff4444", "high": "#ff8c00", "medium": "#f5c518", "info": "#8a9bb5"}
        for ri in risk_indicators:
            color = sev_color.get(ri.get("severity", "info"), "#8a9bb5")
            risk_html += f"<div style='border:1px solid {color};background:rgba({color},0.08);padding:10px 14px;margin-bottom:8px;font-size:12px'><span style='color:{color};font-weight:700'>{ri.get('severity','').upper()}</span> — {ri.get('title','')} <span class='muted' style='display:block;margin-top:2px'>{ri.get('description','')}</span></div>"
    else:
        risk_html = "<p class='muted'>No risk indicators.</p>"

    # Breaches section (email search type)
    breaches = scan_data.get("breaches", [])
    breaches_html = ""
    if breaches:
        rows = ""
        for b in breaches[:20]:
            rows += f"<tr><td style='color:#ff4444;font-weight:700'>{b.get('name','')}</td><td>{b.get('domain','')}</td><td>{b.get('breach_date','')}</td><td>{b.get('pwn_count',0):,}</td></tr>"
        breaches_html = f"""<div class='section'>
            <div class='section-title'>// DATA BREACHES ({len(breaches)})</div>
            <table><thead><tr><th>BREACH</th><th>DOMAIN</th><th>DATE</th><th>RECORDS</th></tr></thead><tbody>{rows}</tbody></table>
        </div>"""

    # Accounts section (username search type)
    accounts = scan_data.get("accounts", [])
    accounts_html = ""
    if accounts:
        rows = "".join(f"<tr><td>{a.get('platform','')}</td><td class='mono' style='font-size:10px'>{a.get('url','')}</td></tr>" for a in accounts[:30])
        extra = f"<p class='muted'>... and {len(accounts)-30} more</p>" if len(accounts) > 30 else ""
        accounts_html = f"""<div class='section'>
            <div class='section-title'>// SOCIAL ACCOUNTS ({len(accounts)})</div>
            <table><thead><tr><th>PLATFORM</th><th>URL</th></tr></thead><tbody>{rows}</tbody></table>{extra}
        </div>"""

    # Phone info section
    phone_info = scan_data.get("phone_info", {})
    phone_html = ""
    if phone_info.get("number"):
        grid = ""
        for label, key in [("NUMBER", "number"), ("COUNTRY", "country"), ("CARRIER", "carrier"), ("LINE TYPE", "line_type"), ("LOCATION", "location")]:
            val = phone_info.get(key, "")
            if val:
                grid += f"<div><span class='muted'>{label}</span><br><span style='color:#e8f0fc'>{val}</span></div>"
        phone_html = f"""<div class='section'>
            <div class='section-title'>// PHONE INFORMATION</div>
            <div style='display:flex;flex-wrap:wrap;gap:16px'>{grid}</div>
        </div>"""

    # Data sources
    data_sources = scan_data.get("data_sources", [])
    sources_html = ""
    if data_sources:
        items = " ".join(f"<span style='font-size:10px;border:1px solid rgba(155,89,182,.4);padding:2px 8px;margin:2px;color:#9b59b6'>{s.get('source','')}</span>" for s in data_sources if "/" not in s.get("source", ""))
        sources_html = f"<div>{items}</div>"

    # Summary stats
    stat_items = ""
    type_labels = {
        "domain": [("EMAILS", "total_emails"), ("SUBDOMAINS", "total_subdomains"), ("IPs", "total_ips"), ("RISKS", "risk_count")],
        "email": [("BREACHES", "total_breaches"), ("PASTES", "total_pastes"), ("RELATED", "total_related_emails"), ("RISKS", "risk_count")],
        "username": [("ACCOUNTS", "total_accounts"), ("RISKS", "risk_count")],
        "person": [("EMAILS", "total_emails"), ("HOSTS", "total_hosts"), ("RISKS", "risk_count")],
        "phone": [("COUNTRY", "country"), ("RISKS", "risk_count")],
    }
    for label, key in type_labels.get(search_type, type_labels["domain"]):
        val = summary.get(key, 0)
        stat_items += f"<div style='text-align:center'><div class='muted'>{label}</div><div style='font-size:22px;font-weight:700;color:#e8f0fc'>{val}</div></div>"

    html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Rajdhani', sans-serif; background:#080c18; color:#b8ccec; padding:40px; font-size:13px; }}
  .mono {{ font-family: monospace; }}
  .muted {{ color:#4a8fd4; font-size:11px; }}
  .header {{ border-bottom:2px solid #4a8fd4; padding-bottom:24px; margin-bottom:32px; display:flex; justify-content:space-between; align-items:flex-end; }}
  .brand {{ font-size:36px; font-weight:700; letter-spacing:0.3em; color:#e8f0fc; }}
  .brand-sub {{ font-size:10px; color:#4a8fd4; letter-spacing:0.3em; margin-top:4px; }}
  .report-meta {{ text-align:right; font-size:10px; color:#4a8fd4; line-height:1.8; }}
  .section {{ margin-bottom:28px; page-break-inside:avoid; }}
  .section-title {{ font-size:10px; color:#4a8fd4; letter-spacing:0.3em; border-bottom:1px solid rgba(74,143,212,0.2); padding-bottom:6px; margin-bottom:14px; }}
  table {{ width:100%; border-collapse:collapse; font-size:11px; margin-top:8px; }}
  th {{ text-align:left; font-size:9px; letter-spacing:0.2em; color:#4a8fd4; padding:6px 8px; border-bottom:1px solid rgba(74,143,212,0.3); }}
  td {{ padding:8px; border-bottom:1px solid rgba(74,143,212,0.08); }}
  .footer {{ margin-top:48px; padding-top:16px; border-top:1px solid rgba(74,143,212,0.2); font-size:9px; color:rgba(74,143,212,0.3); text-align:center; letter-spacing:0.2em; }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="brand">CYRBER</div>
    <div class="brand-sub">OPEN SOURCE INTELLIGENCE REPORT</div>
  </div>
  <div class="report-meta">
    OSINT ASSESSMENT<br>
    TARGET: {target}<br>
    TYPE: {search_type.upper()}<br>
    DATE: {completed_at[:10] if completed_at else datetime.utcnow().strftime('%Y-%m-%d')}<br>
    GENERATED: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC
  </div>
</div>

<div class="section">
  <div class="section-title">// SUMMARY</div>
  <div style="display:flex;gap:32px;margin-bottom:16px">{stat_items}</div>
</div>

<div class="section">
  <div class="section-title">// RISK INDICATORS ({len(risk_indicators)})</div>
  {risk_html}
</div>

<div class="section">
  <div class="section-title">// EMAILS ({len(emails)})</div>
  {emails_html}
</div>

<div class="section">
  <div class="section-title">// SUBDOMAINS ({len(subdomains)})</div>
  {subs_html}
</div>

<div class="section">
  <div class="section-title">// IP ADDRESSES ({len(ips)})</div>
  {ips_html}
</div>

<div class="section">
  <div class="section-title">// DNS RECORDS</div>
  {dns_html}
</div>

<div class="section">
  <div class="section-title">// WHOIS</div>
  {whois_html}
</div>

{breaches_html}
{accounts_html}
{phone_html}

<div class="section">
  <div class="section-title">// DATA SOURCES ({len(data_sources)})</div>
  {sources_html}
</div>

<div class="footer">
  CYRBER · OSINT REPORT · CONFIDENTIAL · FOR AUTHORIZED USE ONLY · v0.2.0
</div>

</body>
</html>"""

    pdf = HTML(string=html_content, base_url=".").write_pdf()
    return pdf
