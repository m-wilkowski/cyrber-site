"""Individual scan tool routes (GET /scan/{tool})."""

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.deps import require_role
from backend.validators import require_valid_target
from modules.database import get_scan_by_task_id

# ── Tool imports ──
from modules.nmap_scan import scan as nmap_scan
from modules.nuclei_scan import scan as nuclei_scan
from modules.llm_analyze import analyze_scan_results
from modules.gobuster_scan import scan as gobuster_scan
from modules.whatweb_scan import scan as whatweb_scan
from modules.testssl_scan import scan as testssl_scan
from modules.sqlmap_scan import scan as sqlmap_scan
from modules.nikto_scan import scan as nikto_scan
from modules.harvester_scan import scan as harvester_scan
from modules.masscan_scan import scan as masscan_scan
from modules.ipinfo_scan import scan as ipinfo_scan
from modules.enum4linux_scan import enum4linux_scan
from modules.mitre_attack import mitre_map
from modules.abuseipdb_scan import scan as abuseipdb_scan
from modules.otx_scan import scan as otx_scan
from modules.exploitdb_scan import exploitdb_scan
from modules.nvd_scan import nvd_scan
from modules.whois_scan import whois_scan
from modules.dnsrecon_scan import dnsrecon_scan
from modules.amass_scan import amass_scan
from modules.cwe_mapping import cwe_mapping
from modules.owasp_mapping import owasp_mapping
from modules.wpscan_scan import wpscan_scan
from modules.zap_scan import zap_scan
from modules.wapiti_scan import wapiti_scan
from modules.joomscan_scan import joomscan_scan
from modules.cmsmap_scan import cmsmap_scan
from modules.droopescan_scan import droopescan_scan
from modules.retirejs_scan import retirejs_scan
from modules.subfinder_scan import subfinder_scan
from modules.httpx_scan import httpx_scan
from modules.naabu_scan import naabu_scan
from modules.katana_scan import katana_scan
from modules.dnsx_scan import dnsx_scan
from modules.netdiscover_scan import netdiscover_scan
from modules.arpscan_scan import arpscan_scan
from modules.fping_scan import fping_scan
from modules.traceroute_scan import traceroute_scan
from modules.nbtscan_scan import nbtscan_scan
from modules.snmpwalk_scan import snmpwalk_scan
from modules.netexec_scan import netexec_scan
from modules.bloodhound_scan import bloodhound_scan
from modules.responder_scan import responder_scan
from modules.fierce_scan import fierce_scan
from modules.smbmap_scan import smbmap_scan
from modules.onesixtyone_scan import onesixtyone_scan
from modules.ikescan_scan import ikescan_scan
from modules.sslyze_scan import sslyze_scan
from modules.searchsploit_scan import searchsploit_scan
from modules.impacket_scan import impacket_scan
from modules.certipy_scan import run_certipy

router = APIRouter(tags=["scan_tools"])


# ── Simple target-based scans ────────────────────────────────────────────────


@router.get("/scan/nmap")
def run_nmap(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    target = require_valid_target(target)
    return nmap_scan(target)


@router.get("/scan/nuclei")
def run_nuclei(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    target = require_valid_target(target)
    return nuclei_scan(target)


# ── Composite scans ──────────────────────────────────────────────────────────


@router.get("/scan/full")
def run_full(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    return {"target": target, "ports": nmap.get("ports", []), "nmap_raw": nmap, "nuclei": nuclei}


@router.get("/scan/analyze")
def run_analyze(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    nmap = nmap_scan(target)
    nuclei = nuclei_scan(target)
    scan_data = {"target": target, "ports": nmap.get("ports", []), "nuclei": nuclei}
    return analyze_scan_results(scan_data)


# ── Web / directory / SSL scanners ───────────────────────────────────────────


@router.get("/scan/gobuster")
def run_gobuster(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    target = require_valid_target(target)
    return gobuster_scan(target)


@router.get("/scan/whatweb")
def run_whatweb(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return whatweb_scan(target)


@router.get("/scan/testssl")
def run_testssl(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return testssl_scan(target)


@router.get("/scan/sqlmap")
def run_sqlmap(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    target = require_valid_target(target)
    return sqlmap_scan(target)


@router.get("/scan/nikto")
def run_nikto(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    target = require_valid_target(target)
    return nikto_scan(target)


@router.get("/scan/harvester")
def run_harvester(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return harvester_scan(target)


@router.get("/scan/masscan")
def run_masscan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return masscan_scan(target)


@router.get("/scan/ipinfo")
def run_ipinfo(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return ipinfo_scan(target)


@router.get("/scan/enum4linux")
def run_enum4linux(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return enum4linux_scan(target)


# ── Task-ID-based enrichment routes ─────────────────────────────────────────


@router.get("/scan/mitre")
def run_mitre(task_id: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return mitre_map(scan)


# ── OSINT / threat intel (target-based) ──────────────────────────────────────


@router.get("/scan/abuseipdb")
def run_abuseipdb(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return abuseipdb_scan(target)


@router.get("/scan/otx")
def run_otx(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return otx_scan(target)


# ── Task-ID-based enrichment routes (continued) ─────────────────────────────


@router.get("/scan/exploitdb")
def run_exploitdb(task_id: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return exploitdb_scan(scan)


@router.get("/scan/nvd")
def run_nvd(task_id: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return nvd_scan(scan)


# ── DNS / WHOIS / domain recon ───────────────────────────────────────────────


@router.get("/scan/whois")
def run_whois(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return whois_scan(target)


@router.get("/scan/dnsrecon")
def run_dnsrecon(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return dnsrecon_scan(target)


@router.get("/scan/amass")
def run_amass(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return amass_scan(target)


# ── Task-ID-based mapping routes ────────────────────────────────────────────


@router.get("/scan/cwe")
def run_cwe(task_id: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return cwe_mapping(scan)


@router.get("/scan/owasp")
def run_owasp(task_id: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return owasp_mapping(scan)


# ── CMS scanners ─────────────────────────────────────────────────────────────


@router.get("/scan/wpscan")
def run_wpscan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return wpscan_scan(target)


@router.get("/scan/zap")
def run_zap(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return zap_scan(target)


@router.get("/scan/wapiti")
def run_wapiti(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return wapiti_scan(target)


@router.get("/scan/joomscan")
def run_joomscan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return joomscan_scan(target)


@router.get("/scan/cmsmap")
def run_cmsmap(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return cmsmap_scan(target)


@router.get("/scan/droopescan")
def run_droopescan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return droopescan_scan(target)


@router.get("/scan/retirejs")
def run_retirejs(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return retirejs_scan(target)


# ── Subdomain / HTTP probing / crawling ──────────────────────────────────────


@router.get("/scan/subfinder")
def run_subfinder(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return subfinder_scan(target)


@router.get("/scan/httpx")
def run_httpx(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return httpx_scan(target)


@router.get("/scan/naabu")
def run_naabu(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return naabu_scan(target)


@router.get("/scan/katana")
def run_katana(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return katana_scan(target)


@router.get("/scan/dnsx")
def run_dnsx(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return dnsx_scan(target)


# ── Network discovery ────────────────────────────────────────────────────────


@router.get("/scan/netdiscover")
def run_netdiscover(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return netdiscover_scan(target)


@router.get("/scan/arpscan")
def run_arpscan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return arpscan_scan(target)


@router.get("/scan/fping")
def run_fping(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return fping_scan(target)


@router.get("/scan/traceroute")
def run_traceroute(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return traceroute_scan(target)


@router.get("/scan/nbtscan")
def run_nbtscan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return nbtscan_scan(target)


@router.get("/scan/snmpwalk")
def run_snmpwalk(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return snmpwalk_scan(target)


# ── Active Directory / SMB / lateral movement ────────────────────────────────


@router.get("/scan/netexec")
def run_netexec(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return netexec_scan(target)


@router.get("/scan/bloodhound")
def run_bloodhound(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return bloodhound_scan(target)


@router.get("/scan/responder")
def run_responder(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return responder_scan(target)


@router.get("/scan/fierce")
def run_fierce(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return fierce_scan(target)


@router.get("/scan/smbmap")
def run_smbmap(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return smbmap_scan(target)


@router.get("/scan/onesixtyone")
def run_onesixtyone(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return onesixtyone_scan(target)


@router.get("/scan/ikescan")
def run_ikescan(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return ikescan_scan(target)


@router.get("/scan/sslyze")
def run_sslyze(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return sslyze_scan(target)


@router.get("/scan/searchsploit")
def run_searchsploit(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return searchsploit_scan(target)


@router.get("/scan/impacket")
def run_impacket(target: str = Query(...), user: dict = Depends(require_role("admin", "operator"))):
    return impacket_scan(target)


# ── Certipy (AD CS) — multi-parameter ────────────────────────────────────────


@router.get("/scan/certipy")
def scan_certipy(
    target: str = Query(...),
    dc_ip: str = Query(""),
    username: str = Query(""),
    password: str = Query(""),
    domain: str = Query(""),
    user: dict = Depends(require_role("admin", "operator")),
):
    return run_certipy(target, username=username or None, password=password or None,
                       domain=domain or None, dc_ip=dc_ip or None)
