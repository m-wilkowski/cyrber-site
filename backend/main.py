from fastapi import FastAPI
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.nmap_scan import scan

app = FastAPI(title="CYRBER API", version="0.1.0")

@app.get("/")
async def root():
    return {"status": "CYRBER online"}

@app.get("/scan/{target}")
async def run_scan(target: str):
    return scan(target)
