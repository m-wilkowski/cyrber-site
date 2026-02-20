import json
from modules.llm_provider import get_provider


def analyze_scan_results(scan_data: dict) -> dict:
    target = scan_data.get("target", "unknown")
    ports = scan_data.get("ports", [])
    nuclei_data = scan_data.get("nuclei", {})
    findings = nuclei_data.get("findings", [])

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

    provider = get_provider()

    try:
        response_text = provider.chat(prompt)

        try:
            clean = response_text.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            analysis = json.loads(clean.strip())
        except json.JSONDecodeError:
            # Try extracting JSON from anywhere in the response
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            if start != -1 and end > start:
                try:
                    analysis = json.loads(response_text[start:end])
                except json.JSONDecodeError:
                    analysis = {"raw_analysis": response_text}
            else:
                analysis = {"raw_analysis": response_text}

        return {
            "target": target,
            "findings_count": len(findings),
            "analysis": analysis,
            "llm_provider": provider.name
        }

    except Exception as e:
        print(f"[llm_analyze] {provider.name} failed: {e}")

        return {
            "target": target,
            "findings_count": len(findings),
            "analysis": {
                "risk_level": "NIEZNANE",
                "summary": "Analiza LLM niedostępna.",
                "top_issues": [],
                "recommendations": ""
            },
            "llm_provider": "none"
        }
