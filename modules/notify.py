import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_TO = os.getenv("SMTP_TO", "")
CYRBER_URL = os.getenv("CYRBER_URL", "http://127.0.0.1:8000")

RISK_COLORS = {
    "KRYTYCZNE": "#ff4444", "CRITICAL": "#ff4444",
    "WYSOKIE": "#ff8c00", "HIGH": "#ff8c00",
    "SREDNIE": "#f5c518", "MEDIUM": "#f5c518", "ŚREDNIE": "#f5c518",
    "NISKIE": "#3ddc84", "LOW": "#3ddc84",
}


def _build_html(target: str, task_id: str, risk_level: str, findings_count: int, summary: str) -> str:
    risk_upper = (risk_level or "UNKNOWN").upper()
    risk_color = RISK_COLORS.get(risk_upper, "#4a8fd4")
    summary_short = (summary or "Brak podsumowania.")[:500]
    if len(summary or "") > 500:
        summary_short += "..."
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    report_url = f"{CYRBER_URL}/ui"
    pdf_url = f"{CYRBER_URL}/scans/{task_id}/pdf"

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#080c18;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#080c18;padding:32px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#0c1220;border:1px solid rgba(74,143,212,0.18);border-radius:4px;">

  <!-- Header -->
  <tr><td style="padding:28px 32px 20px;border-bottom:1px solid rgba(74,143,212,0.18);">
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td style="font-family:Arial,Helvetica,sans-serif;font-size:22px;font-weight:900;letter-spacing:4px;color:#e8eef8;">CYRBER</td>
      <td align="right" style="font-family:Arial,Helvetica,sans-serif;font-size:10px;letter-spacing:2px;color:#4a8fd4;">SCAN COMPLETE</td>
    </tr>
    </table>
  </td></tr>

  <!-- Risk Badge -->
  <tr><td style="padding:24px 32px 16px;">
    <table cellpadding="0" cellspacing="0">
    <tr>
      <td style="font-family:Arial,Helvetica,sans-serif;font-size:10px;letter-spacing:2px;color:#4a8fd4;padding-bottom:8px;">THREAT LEVEL</td>
    </tr>
    <tr>
      <td style="font-family:Arial,Helvetica,sans-serif;font-size:14px;font-weight:700;letter-spacing:3px;color:{risk_color};border:1px solid {risk_color};padding:8px 20px;">{risk_upper}</td>
    </tr>
    </table>
  </td></tr>

  <!-- Info Grid -->
  <tr><td style="padding:8px 32px 20px;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
    <tr>
      <td style="padding:10px 12px;background:#101828;border:1px solid rgba(74,143,212,0.10);" width="50%">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:9px;letter-spacing:2px;color:#4a8fd4;margin-bottom:4px;">TARGET</div>
        <div style="font-family:Courier New,monospace;font-size:13px;color:#e8eef8;">{target}</div>
      </td>
      <td style="padding:10px 12px;background:#101828;border:1px solid rgba(74,143,212,0.10);" width="50%">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:9px;letter-spacing:2px;color:#4a8fd4;margin-bottom:4px;">TASK ID</div>
        <div style="font-family:Courier New,monospace;font-size:13px;color:#e8eef8;">{task_id[:12]}</div>
      </td>
    </tr>
    <tr>
      <td style="padding:10px 12px;background:#101828;border:1px solid rgba(74,143,212,0.10);">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:9px;letter-spacing:2px;color:#4a8fd4;margin-bottom:4px;">FINDINGS</div>
        <div style="font-family:Courier New,monospace;font-size:13px;color:#e8eef8;">{findings_count}</div>
      </td>
      <td style="padding:10px 12px;background:#101828;border:1px solid rgba(74,143,212,0.10);">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:9px;letter-spacing:2px;color:#4a8fd4;margin-bottom:4px;">COMPLETED</div>
        <div style="font-family:Courier New,monospace;font-size:13px;color:#e8eef8;">{now}</div>
      </td>
    </tr>
    </table>
  </td></tr>

  <!-- Summary -->
  <tr><td style="padding:0 32px 24px;">
    <div style="font-family:Arial,Helvetica,sans-serif;font-size:9px;letter-spacing:2px;color:#4a8fd4;margin-bottom:8px;">EXECUTIVE SUMMARY</div>
    <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.7;color:#8a9bb5;background:#101828;border:1px solid rgba(74,143,212,0.10);padding:14px 16px;">{summary_short}</div>
  </td></tr>

  <!-- Action Buttons -->
  <tr><td style="padding:0 32px 28px;">
    <table cellpadding="0" cellspacing="0"><tr>
      <td style="padding-right:10px;">
        <a href="{report_url}" style="display:inline-block;font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:700;letter-spacing:2px;color:#e8eef8;background:linear-gradient(140deg,#183568,#0e2040);border:1px solid #4a8fd4;padding:10px 22px;text-decoration:none;">VIEW REPORT</a>
      </td>
      <td>
        <a href="{pdf_url}" style="display:inline-block;font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:700;letter-spacing:2px;color:#ff8888;background:linear-gradient(140deg,#3a1a1a,#200e0e);border:1px solid #ff4444;padding:10px 22px;text-decoration:none;">DOWNLOAD PDF</a>
      </td>
    </tr></table>
  </td></tr>

  <!-- Footer -->
  <tr><td style="padding:16px 32px;border-top:1px solid rgba(74,143,212,0.10);">
    <div style="font-family:Courier New,monospace;font-size:10px;letter-spacing:2px;color:rgba(74,143,212,0.35);text-align:center;">
      CYRBER &middot; AUTONOMOUS RECON &middot; {now}
    </div>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""


def send_scan_notification(target: str, task_id: str, result: dict):
    """Send HTML email notification after scan completion."""
    if not SMTP_HOST or not all([SMTP_USER, SMTP_PASS, SMTP_TO]):
        return False

    analysis = result.get("analysis", {})
    risk_level = analysis.get("risk_level", "UNKNOWN")
    findings_count = result.get("findings_count", 0)
    summary = analysis.get("summary", "Brak podsumowania")

    subject = f"[CYRBER] Scan complete: {target} — {risk_level}"
    html = _build_html(target, task_id, risk_level, findings_count, summary)

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = SMTP_USER
        msg["To"] = SMTP_TO
        msg["Subject"] = subject

        # Plain text fallback
        plain = (
            f"CYRBER Scan Complete\n\n"
            f"Target: {target}\n"
            f"Task ID: {task_id}\n"
            f"Risk Level: {risk_level}\n"
            f"Findings: {findings_count}\n\n"
            f"Summary:\n{(summary or '')[:500]}\n\n"
            f"Report: {CYRBER_URL}/ui\n"
            f"PDF: {CYRBER_URL}/scans/{task_id}/pdf\n"
        )
        msg.attach(MIMEText(plain, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, SMTP_TO.split(","), msg.as_string())
        print(f"[notify] Email sent to {SMTP_TO} for {target}")
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"[notify] SMTP auth failed: {e}")
        return False
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, TimeoutError) as e:
        print(f"[notify] SMTP connection error: {e}")
        return False
    except Exception as e:
        print(f"[notify] Email error: {e}")
        return False
