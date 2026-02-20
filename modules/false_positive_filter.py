import json
import requests
from modules.llm_provider import get_provider


def _retest_finding(finding: dict, target: str) -> bool:
    """Warstwa 1: Retest - odrzuca tylko jawne 404/410."""
    try:
        matched_at = finding.get("matched-at", "")
        if not matched_at.startswith("http"):
            return True
        resp = requests.get(matched_at, timeout=10, verify=False, allow_redirects=True)
        if resp.status_code in [404, 410]:
            return False
        return True
    except Exception:
        return True


def _heuristic_filter(finding: dict) -> bool:
    """Warstwa 2: Heurystyczna filtracja na podstawie znanych FP wzorców."""
    name = finding.get("info", {}).get("name", "").lower()
    severity = finding.get("info", {}).get("severity", "").lower()
    template_id = finding.get("template-id", "").lower()

    fp_patterns = [
        "tech-detect", "waf-detect", "favicon",
        "robots", "sitemap", "options-method"
    ]
    for pattern in fp_patterns:
        if pattern in template_id:
            return False

    if severity == "info" and "detect" in name:
        return False

    return True


def _llm_validate(findings: list, target: str) -> list:
    """Warstwa 3: LLM weryfikacja kontekstowa."""
    if not findings:
        return findings

    findings_summary = [
        {
            "index": i,
            "name": f["info"]["name"],
            "severity": f["info"]["severity"],
            "template_id": f.get("template-id", ""),
            "matched_at": f.get("matched-at", ""),
            "description": f["info"].get("description", "")[:200],
        }
        for i, f in enumerate(findings)
    ]

    prompt = f"""Jesteś ekspertem pentestingu. Przeanalizuj wyniki Nuclei i oznacz fałszywe alarmy.

Target: {target}
Findings ({len(findings_summary)}):
{json.dumps(findings_summary, indent=2, ensure_ascii=False)}

Dla każdego finding oceń czy to prawdziwa podatność (true) czy fałszywy alarm (false).
Kryteria fałszywego alarmu:
- Tylko detekcja technologii bez podatności
- Generic headers/info bez konkretnego exploita
- Niedostępny endpoint (404/410)
- Zbyt ogólne (np. "missing header" bez krytycznego znaczenia)

Odpowiedz TYLKO w JSON:
{{
  "results": [
    {{"index": 0, "is_real": true, "reason": "krótkie uzasadnienie"}},
    {{"index": 1, "is_real": false, "reason": "krótkie uzasadnienie"}}
  ]
}}"""

    provider = get_provider()

    try:
        response_text = provider.chat(prompt, max_tokens=1024)
        clean = response_text.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        try:
            validation = json.loads(clean.strip())
        except json.JSONDecodeError:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            validation = json.loads(response_text[start:end])
        real_indices = {r["index"] for r in validation["results"] if r["is_real"]}
        return [f for i, f in enumerate(findings) if i in real_indices]
    except Exception as e:
        print(f"[fp_filter] {provider.name} validation failed: {e}")
        return findings


def filter_false_positives(nuclei_result: dict, target: str) -> dict:
    """Główna funkcja — 3-warstwowa filtracja FP."""
    findings = nuclei_result.get("findings", [])
    original_count = len(findings)

    if not findings:
        return {
            **nuclei_result,
            "fp_filter": {
                "original_count": 0,
                "filtered_count": 0,
                "removed": 0,
                "accuracy": 100
            }
        }

    # Warstwa 1: Retest
    after_retest = [f for f in findings if _retest_finding(f, target)]

    # Warstwa 2: Heurystyki
    after_heuristic = [f for f in after_retest if _heuristic_filter(f)]

    # Warstwa 3: LLM
    after_llm = _llm_validate(after_heuristic, target)

    removed = original_count - len(after_llm)
    accuracy = round((len(after_llm) / original_count * 100) if original_count > 0 else 100, 1)

    return {
        **nuclei_result,
        "findings": after_llm,
        "fp_filter": {
            "original_count": original_count,
            "filtered_count": len(after_llm),
            "removed": removed,
            "accuracy": accuracy
        }
    }
