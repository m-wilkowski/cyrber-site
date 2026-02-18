import requests
import json
import os

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

def analyze_scan_results_ollama(scan_data: dict) -> dict:
    target = scan_data.get("target", "unknown")
    ports = scan_data.get("ports", [])
    nuclei = scan_data.get("nuclei", {})
    whatweb = scan_data.get("whatweb", {})
    sqlmap = scan_data.get("sqlmap", {})

    prompt = f"""You are a security analyst. Analyze this scan data and respond in JSON only.

Target: {target}
Open ports: {json.dumps(ports[:20])}
Nuclei findings: {json.dumps(nuclei.get('findings', [])[:10])}
Technologies: {json.dumps(whatweb.get('technologies', [])[:10])}
SQL injection: {json.dumps(sqlmap.get('vulnerable', False))}

Respond ONLY with valid JSON, no markdown, no explanation:
{{
  "risk_level": "KRYTYCZNE|WYSOKIE|ŚREDNIE|NISKIE",
  "summary": "2-3 sentence summary in Polish",
  "top_issues": ["issue1", "issue2", "issue3"],
  "recommendations": "recommendations in Polish"
}}"""

    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=120
        )
        resp.raise_for_status()
        raw = resp.json().get("response", "")

        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start == -1 or end == 0:
            raise ValueError("No JSON in response")

        analysis = json.loads(raw[start:end])
        return {
            "target": target,
            "findings_count": len(nuclei.get("findings", [])),
            "analysis": analysis,
            "llm_provider": "ollama"
        }
    except Exception as e:
        return {
            "target": target,
            "findings_count": 0,
            "analysis": {
                "risk_level": "NIEZNANE",
                "summary": f"Ollama analysis failed: {e}",
                "top_issues": [],
                "recommendations": ""
            },
            "llm_provider": "ollama",
            "error": str(e)
        }

def is_ollama_available() -> bool:
    try:
        resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        return resp.status_code == 200
    except:
        return False
