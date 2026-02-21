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
    users = enum4linux.get("users", [])
    if users:
        rows = "".join(f"<tr><td>{u.get('username','')}</td><td>{u.get('rid','')}</td></tr>" for u in users[:20])
        html += f"<div style='margin-bottom:12px'><div class='muted' style='margin-bottom:4px'>USERS ({len(users)})</div><table><thead><tr><th>USERNAME</th><th>RID</th></tr></thead><tbody>{rows}</tbody></table></div>"
    shares = enum4linux.get("shares", [])
    if shares:
        rows = "".join(f"<tr><td>{s.get('name','')}</td><td>{s.get('type','')}</td><td>{s.get('comment','')}</td></tr>" for s in shares)
        html += f"<div style='margin-bottom:12px'><div class='muted' style='margin-bottom:4px'>SHARES ({len(shares)})</div><table><thead><tr><th>NAME</th><th>TYPE</th><th>COMMENT</th></tr></thead><tbody>{rows}</tbody></table></div>"
    if not html:
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
  <div class="section-title">// ENUM4LINUX — SMB ENUMERATION</div>
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
