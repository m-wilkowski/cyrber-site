import subprocess
import json

def scan(target: str) -> dict:
    url = target if target.startswith("http") else f"http://{target}"

    try:
        result = subprocess.run(
            ["whatweb", "--log-json=-", "-a", "3", url],
            capture_output=True, text=True, timeout=60
        )

        technologies = []
        raw = result.stdout.strip()

        # whatweb zwraca linie - każda linia zaczynająca się od { to obiekt
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
                plugins = entry.get("plugins", {})
                for name, info in plugins.items():
                    tech = {"name": name}
                    if isinstance(info, dict):
                        if info.get("version"):
                            v = info["version"]
                            tech["version"] = v[0] if isinstance(v, list) else v
                        if info.get("string"):
                            s = info["string"]
                            tech["detail"] = s[0] if isinstance(s, list) else s
                        if info.get("os"):
                            o = info["os"]
                            tech["os"] = o[0] if isinstance(o, list) else o
                    technologies.append(tech)
            except json.JSONDecodeError:
                continue

        return {"target": target, "technologies_count": len(technologies), "technologies": technologies}

    except subprocess.TimeoutExpired:
        return {"target": target, "error": "Timeout", "technologies": []}
    except Exception as e:
        return {"target": target, "error": str(e), "technologies": []}
