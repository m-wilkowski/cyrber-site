import subprocess

def scan(target: str) -> dict:
    result = subprocess.run(
        ["nmap", "-sV", "--open", target],
        capture_output=True,
        text=True,
        timeout=120
    )
    return {
        "target": target,
        "output": result.stdout,
        "errors": result.stderr
    }
