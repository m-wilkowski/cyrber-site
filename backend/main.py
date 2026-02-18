from fastapi import FastAPI, Query
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan

app = FastAPI(title="CYRBER API", version="0.1.0")

@app.get("/")
async def root():
    return {"status": "CYRBER online"}

@app.get("/scan/nmap")
async def run_nmap(target: str = Query(...)):
    return nmap_scan(target)

@app.get("/scan/nuclei")
async def run_nuclei(target: str = Query(...)):
    return nuclei_scan(target)

@app.get("/scan/full")
async def run_full(target: str = Query(...)):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    return {
        "target": target,
        "nmap": nmap,
        "nuclei": nuclei
    }
