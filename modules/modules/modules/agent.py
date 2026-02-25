import os
import json
from modules.llm_provider import get_provider

TOOLS = [
    {
        "name": "nmap_scan",
        "description": "Skanuje porty i usługi na hoście. Zwraca otwarte porty, wersje usług, OS detection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP lub hostname do skanowania"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "nuclei_scan",
        "description": "Skanuje pod kątem znanych podatności CVE używając bazy Nuclei templates.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP lub hostname"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "whatweb_scan",
        "description": "Wykrywa technologie webowe: framework, CMS, serwer, biblioteki JS. Używaj gdy cel ma port 80/443.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP lub hostname"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "gobuster_scan",
        "description": "Brute-force katalogów i plików na serwerze HTTP. Używaj gdy cel ma port 80/443 i chcesz znaleźć ukryte zasoby.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP lub hostname"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "testssl_scan",
        "description": "Analizuje konfigurację SSL/TLS, wykrywa słabe szyfry i podatności (BEAST, POODLE, Heartbleed). Używaj TYLKO gdy cel ma port 443.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "hostname lub IP"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "finish_assessment",
        "description": "Kończy assessment i generuje finalny raport. Wywołaj gdy zebrałeś wystarczające dane.",
        "input_schema": {
            "type": "object",
            "properties": {
                "risk_level": {
                    "type": "string",
                    "enum": ["NISKIE", "ŚREDNIE", "WYSOKIE", "KRYTYCZNE"],
                    "description": "Ogólny poziom ryzyka"
                },
                "summary": {"type": "string", "description": "Podsumowanie wykonawcze (2-4 zdania)"},
                "top_issues": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista 3-5 najważniejszych problemów"
                },
                "recommendations": {"type": "string", "description": "Zalecenia remediacyjne"}
            },
            "required": ["risk_level", "summary", "top_issues", "recommendations"]
        }
    }
]

SYSTEM_PROMPT = """Jesteś autonomicznym agentem bezpieczeństwa CYRBER. Twoim zadaniem jest przeprowadzenie kompleksowego security assessment wskazanego celu.

Działasz w pętli: analizujesz dostępne informacje → decydujesz który skaner uruchomić → interpretujesz wyniki → decydujesz o kolejnym kroku.

Zasady działania:
1. Zawsze zacznij od nmap_scan żeby poznać powierzchnię ataku
2. Jeśli znajdziesz port 80 lub 443 → uruchom whatweb_scan
3. Jeśli znajdziesz port 80 lub 443 → uruchom gobuster_scan
4. Jeśli znajdziesz port 443 → uruchom testssl_scan
5. Zawsze uruchom nuclei_scan dla kompletności
6. Gdy masz wystarczające dane → wywołaj finish_assessment z finalnym raportem
7. Nie uruchamiaj tego samego skanera dwa razy na ten sam cel

Bądź efektywny – nie uruchamiaj skanerów które nie wniosą wartości dla danego celu."""

def run_tool(tool_name: str, tool_input: dict, scan_results: dict) -> str:
    from modules.nmap_scan import scan as nmap_scan
    from modules.nuclei_scan import scan as nuclei_scan
    from modules.whatweb_scan import scan as whatweb_scan
    from modules.gobuster_scan import scan as gobuster_scan
    from modules.testssl_scan import scan as testssl_scan

    target = tool_input.get("target")

    if tool_name == "nmap_scan":
        result = nmap_scan(target)
        scan_results["nmap"] = result
        return json.dumps(result, ensure_ascii=False)
    elif tool_name == "nuclei_scan":
        result = nuclei_scan(target)
        scan_results["nuclei"] = result
        return json.dumps(result, ensure_ascii=False)
    elif tool_name == "whatweb_scan":
        result = whatweb_scan(target)
        scan_results["whatweb"] = result
        return json.dumps(result, ensure_ascii=False)
    elif tool_name == "gobuster_scan":
        result = gobuster_scan(target)
        scan_results["gobuster"] = result
        return json.dumps(result, ensure_ascii=False)
    elif tool_name == "testssl_scan":
        result = testssl_scan(target)
        scan_results["testssl"] = result
        return json.dumps(result, ensure_ascii=False)
    else:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})

def run_agent(target: str, progress_callback=None) -> dict:
    """
    Uruchamia autonomicznego agenta który sam decyduje jakie skanery użyć.
    progress_callback(step, tool_name) - opcjonalny callback dla statusu
    """
    provider = get_provider(task="agent")
    messages = [
        provider.make_user_msg(
            f"Przeprowadź kompletny security assessment dla: {target}")
    ]

    scan_results = {}
    final_report = None
    steps = []
    max_iterations = 10

    for iteration in range(max_iterations):
        response = provider.chat_with_tools(
            messages, TOOLS, system=SYSTEM_PROMPT)

        # Append assistant response to history
        messages.extend(provider.make_assistant_msgs(response))

        # Check if agent finished (no tool calls)
        if response.stop_reason == "end_turn":
            break

        # Process tool calls
        tool_results = []
        for tc in response.tool_calls:
            if tc.name == "finish_assessment":
                final_report = tc.input
                tool_results.append((tc.id, "Assessment zakończony."))
                steps.append({"tool": tc.name, "status": "completed"})
                break

            if progress_callback:
                progress_callback(iteration + 1, tc.name)

            steps.append({"tool": tc.name, "target": tc.input.get("target")})
            result_str = run_tool(tc.name, tc.input, scan_results)
            tool_results.append((tc.id, result_str))

        if tool_results:
            messages.extend(
                provider.make_tool_result_msgs(tool_results))

        if final_report:
            break

    # Count findings
    findings_count = 0
    if "nuclei" in scan_results:
        findings_count += scan_results["nuclei"].get("findings_count", 0)
    if "testssl" in scan_results:
        findings_count += scan_results["testssl"].get("findings_count", 0)

    return {
        "target": target,
        "findings_count": findings_count,
        "steps": steps,
        "analysis": final_report or {
            "risk_level": "NIEZNANE",
            "summary": "Agent nie zakończył assessment.",
            "top_issues": [],
            "recommendations": ""
        },
        "raw_scans": scan_results,
        "llm_provider": provider.name
    }
