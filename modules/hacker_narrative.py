import os
import json
import anthropic
from dotenv import load_dotenv
load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def generate_hacker_narrative(scan_result: dict) -> dict:
    target = scan_result.get("target", "unknown")
    analysis = scan_result.get("analysis", {})
    exploit_chains = scan_result.get("exploit_chains", {})
    chains = exploit_chains.get("chains", [])
    ports = scan_result.get("ports", [])
    whatweb = scan_result.get("whatweb", {})
    sqlmap = scan_result.get("sqlmap", {})
    risk_level = analysis.get("risk_level", "NIEZNANE")

    if not chains and not ports:
        return {
            "target": target,
            "narrative": None,
            "executive_summary": analysis.get("summary", ""),
            "note": "Brak wystarczających danych do wygenerowania narracji."
        }

    best_chain = chains[0] if chains else {}

    prompt = f"""Jesteś copywriterem specjalizującym się w cyberbezpieczeństwie. Napisz krótki raport z perspektywy hakera — jak film noir, nie jak dokumentacja techniczna.

Target: {target}
Ryzyko: {risk_level}
Technologie: {json.dumps(whatweb.get('technologies', [])[:5], ensure_ascii=False)}
Otwarte porty: {json.dumps([str(p['port']) + '/' + p['service'] for p in ports[:5]])}
SQL Injection: {sqlmap.get('vulnerable', False)}
Główny łańcuch ataku: {json.dumps(best_chain, ensure_ascii=False)}

Napisz narrację w stylu:
- Czas przeszły, perspektywa hakera ("Znalazłem...", "Wszedłem...", "System otworzył się...")
- Konkretne godziny (Dzień 1, 00:00 → 02:15 itd.)
- Bez żargonu technicznego — CEO musi rozumieć
- Zakończ kwotą potencjalnej straty i kosztem naprawy
- Max 300 słów

Następnie napisz osobno "Podsumowanie dla Zarządu" — 3 zdania, bez technicznych szczegółów, tylko biznesowy wpływ.

Odpowiedz w JSON:
{{
  "narrative": "pełna narracja hakera...",
  "executive_summary": "3 zdania dla zarządu...",
  "potential_loss": "kwota w PLN/EUR",
  "fix_cost": "szacowany koszt naprawy",
  "time_to_compromise": "szacowany czas przejęcia"
}}"""

    try:
        message = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        response_text = message.content[0].text
        clean = response_text.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        result = json.loads(clean.strip())
        return {"target": target, **result}
    except Exception as e:
        print(f"[hacker_narrative] Failed: {e}")
        return {
            "target": target,
            "narrative": None,
            "executive_summary": analysis.get("summary", ""),
            "error": str(e)
        }
