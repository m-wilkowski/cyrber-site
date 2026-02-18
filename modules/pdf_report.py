import os
import json
from datetime import datetime
from weasyprint import HTML, CSS

def generate_report(scan_data: dict) -> bytes:
    target = scan_data.get("target", "unknown")
    analysis = scan_data.get("analysis", {})
    risk = analysis.get("risk_level", "N/A")
    findings_count = scan_data.get("findings_count", 0)
    summary = analysis.get("summary", "")
    top_issues = analysis.get("top_issues", [])
    recommendations = analysis.get("recommendations", "")
    completed_at = scan_data.get("completed_at", datetime.utcnow().isoformat())

    risk_color = {
        "NISKIE": "#3ddc84",
        "LOW": "#3ddc84",
        "ŚREDNIE": "#f5c518",
        "MEDIUM": "#f5c518",
        "WYSOKIE": "#ff8c00",
        "HIGH": "#ff8c00",
        "KRYTYCZNE": "#ff4444",
        "CRITICAL": "#ff4444",
    }.get(risk.upper(), "#4a8fd4")

    issues_html = ""
    for i, issue in enumerate(top_issues, 1):
        issues_html += f'<div class="issue"><span class="issue-num">{i:02d}</span><span>{issue}</span></div>'

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&display=swap');

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: 'Rajdhani', sans-serif;
    background: #080c18;
    color: #b8ccec;
    padding: 40px;
    font-size: 13px;
  }}

  .header {{
    border-bottom: 2px solid #4a8fd4;
    padding-bottom: 24px;
    margin-bottom: 32px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }}

  .brand {{
    font-size: 36px;
    font-weight: 700;
    letter-spacing: 0.3em;
    color: #e8f0fc;
  }}

  .brand-sub {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: #4a8fd4;
    letter-spacing: 0.3em;
    margin-top: 4px;
  }}

  .report-meta {{
    text-align: right;
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: #4a8fd4;
    line-height: 1.8;
  }}

  .risk-banner {{
    background: rgba(74,143,212,0.08);
    border: 1px solid {risk_color};
    padding: 16px 24px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}

  .risk-label {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: #4a8fd4;
    letter-spacing: 0.3em;
  }}

  .risk-value {{
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 0.2em;
    color: {risk_color};
  }}

  .risk-stats {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: #4a8fd4;
    text-align: right;
    line-height: 1.8;
  }}

  .section {{
    margin-bottom: 28px;
  }}

  .section-title {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: #4a8fd4;
    letter-spacing: 0.3em;
    border-bottom: 1px solid rgba(74,143,212,0.2);
    padding-bottom: 6px;
    margin-bottom: 14px;
  }}

  .summary-text {{
    font-size: 13px;
    line-height: 1.75;
    color: #b8ccec;
  }}

  .issue {{
    display: flex;
    gap: 14px;
    padding: 10px 0;
    border-bottom: 1px solid rgba(74,143,212,0.1);
    font-size: 13px;
    line-height: 1.6;
  }}

  .issue:last-child {{ border-bottom: none; }}

  .issue-num {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: #4a8fd4;
    flex-shrink: 0;
    margin-top: 2px;
    min-width: 22px;
  }}

  .rec-text {{
    font-size: 13px;
    line-height: 1.85;
    color: #b8ccec;
    white-space: pre-wrap;
  }}

  .footer {{
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid rgba(74,143,212,0.2);
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px;
    color: rgba(74,143,212,0.3);
    text-align: center;
    letter-spacing: 0.2em;
  }}
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
    <div class="risk-label">OVERALL THREAT LEVEL</div>
    <div class="risk-value">{risk}</div>
  </div>
  <div class="risk-stats">
    FINDINGS: {findings_count}<br>
    TARGET: {target}
  </div>
</div>

<div class="section">
  <div class="section-title">EXECUTIVE SUMMARY</div>
  <div class="summary-text">{summary}</div>
</div>

<div class="section">
  <div class="section-title">CRITICAL FINDINGS</div>
  {issues_html}
</div>

<div class="section">
  <div class="section-title">REMEDIATION RECOMMENDATIONS</div>
  <div class="rec-text">{recommendations}</div>
</div>

<div class="footer">
  CYRBER · AUTONOMOUS RECON · CONFIDENTIAL · FOR AUTHORIZED USE ONLY · v0.1.0
</div>

</body>
</html>
"""

    pdf = HTML(string=html_content, base_url=".").write_pdf()
    return pdf
