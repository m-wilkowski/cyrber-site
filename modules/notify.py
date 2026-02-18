import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_TO = os.getenv("SMTP_TO")

def send_scan_notification(target: str, task_id: str, result: dict):
    if not all([SMTP_USER, SMTP_PASS, SMTP_TO]):
        return False

    analysis = result.get("analysis", {})
    risk_level = analysis.get("risk_level", "UNKNOWN")
    findings_count = result.get("findings_count", 0)
    summary = analysis.get("summary", "Brak podsumowania")

    subject = f"[CYRBER] Skan zakończony: {target} — {risk_level}"

    body = f"""
CYRBER — Raport ze skanu
========================

Target:       {target}
Task ID:      {task_id}
Poziom ryzyka: {risk_level}
Findings:     {findings_count}

Podsumowanie:
{summary}

---
Szczegóły: http://127.0.0.1:8000/scans/{task_id}
PDF raport:  http://127.0.0.1:8000/scans/{task_id}/pdf
"""

    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = SMTP_TO
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, SMTP_TO, msg.as_string())
        return True
    except Exception as e:
        print(f"[notify] Email error: {e}")
        return False
