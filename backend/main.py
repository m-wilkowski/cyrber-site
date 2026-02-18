from fastapi import FastAPI
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = FastAPI(title="CYRBER API", version="0.1.0")

@app.get("/")
async def root():
    return {"status": "CYRBER online"}

@app.get("/scan/{target}")
async def run_scan(target: str):
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
