import os
import json
import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

def analyze_scan_results(scan_data: dict) -> dict:
    target = scan_data.get("target", "unknown")
    ports = scan_data.get("ports", [])
    nuclei_data = scan_data.get("nuclei", {})
    findings = nuclei_data.get("findings", [])

    # Przygotuj skrócone dane dla LLM (bez surowych request/response)
    ports_summary = [
        {"port": p["port"], "service": p["service"], "version": p["version"]}
        for p in ports
    ]
    findings_summary = [
        {
            "name": f["info"]["name"],
            "severity": f["info"]["severity"],
            "description": f["info"].get("description", ""),
            "cve": f["info"].get("classification", {}).get("cve-id"),
            "cvss": f["info"].get("classification", {}).get("cvss-score"),
        }
        for f in findings
    ]

    prompt = f"""Jesteś ekspertem ds. cyberbezpieczeństwa. Przeanalizuj wyniki skanowania i przygotuj raport.

Target: {target}

Otwarte porty:
{json.dumps(ports_summary, indent=2, ensure_ascii=False)}

Znalezione podatności ({len(findings_summary)}):
{json.dumps(findings_summary, indent=2, ensure_ascii=False)}

Przygotuj:
1. Krótkie podsumowanie ogólnego stanu bezpieczeństwa (2-3 zdania)
2. Top 3 najważniejsze problemy do naprawy
3. Ogólną ocenę ryzyka: NISKIE / ŚREDNIE / WYSOKIE / KRYTYCZNE

Odpowiedz w formacie JSON:
{{
  "summary": "...",
  "top_issues": ["...", "...", "..."],
  "risk_level": "...",
  "recommendations": "..."
}}"""

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )

    response_text = message.content[0].text

    # Wyciągnij JSON z odpowiedzi
    try:
        # Usuń możliwe markdown code blocks
        clean = response_text.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        analysis = json.loads(clean.strip())
    except json.JSONDecodeError:
        analysis = {"raw_analysis": response_text}

    return {
        "target": target,
        "findings_count": len(findings),
        "analysis": analysis
    }
