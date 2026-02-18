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
    gobuster = scan_data.get("gobuster", {})
    testssl = scan_data.get("testssl", {})
    sqlmap = scan_data.get("sqlmap", {})
    exploit_chains = scan_data.get("exploit_chains", {})
    hacker_narrative = scan_data.get("hacker_narrative", {})
    fp_filter = scan_data.get("fp_filter", {})

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
  <div class="section-title">// SQL INJECTION (SQLMAP)</div>
  {_sqlmap_html(sqlmap)}
</div>

<div class="section">
  <div class="section-title">// BEZPIECZEŃSTWO TLS (TESTSSL)</div>
  {_testssl_html(testssl)}
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
