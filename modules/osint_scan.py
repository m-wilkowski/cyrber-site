"""OSINT aggregation module — combines theHarvester, WHOIS, DNSRecon, Amass."""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.harvester_scan import scan as harvester_scan
from modules.whois_scan import whois_scan
from modules.dnsrecon_scan import dnsrecon_scan
from modules.amass_scan import amass_scan


def _clean_target(target: str) -> str:
    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    return host.strip().lower()


def osint_scan(target: str) -> dict:
    """Run OSINT reconnaissance by aggregating multiple data sources in parallel.

    Args:
        target: Domain name or IP address.

    Returns:
        Dict with aggregated OSINT profile.
    """
    host = _clean_target(target)
    if not host:
        return {"error": "empty target"}

    # Run all four scans in parallel using threads
    results = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(harvester_scan, host): "harvester",
            executor.submit(whois_scan, host): "whois",
            executor.submit(dnsrecon_scan, host): "dnsrecon",
            executor.submit(amass_scan, host): "amass",
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = {"error": str(e)}

    harv = results.get("harvester") or {}
    whois_data = results.get("whois") or {}
    dns = results.get("dnsrecon") or {}
    amass_data = results.get("amass") or {}

    # Track module errors for diagnostics
    module_errors = []
    if harv.get("error"):
        module_errors.append(f"theHarvester: {harv['error']}")
    if whois_data.get("error"):
        module_errors.append(f"WHOIS: {whois_data['error']}")
    if dns.get("skipped"):
        module_errors.append(f"DNSRecon: {dns.get('reason', 'skipped')}")
    if amass_data.get("skipped"):
        module_errors.append(f"Amass: {amass_data.get('reason', 'skipped')}")

    # ── Aggregate emails ──
    emails = set()
    harv_emails = harv.get("emails", []) or []
    for e in harv_emails:
        if "@" in str(e):
            emails.add(str(e).lower().strip())

    # ── Aggregate subdomains ──
    subdomains = set()
    for src_key, src_data, sub_key in [
        ("harvester", harv, "subdomains"),
        ("amass", amass_data, "subdomains"),
        ("dnsrecon", dns, "subdomains"),
    ]:
        subs = src_data.get(sub_key, []) or []
        for s in subs:
            if s:
                subdomains.add(str(s).lower().strip())

    # Also from dnsrecon A records
    for rec in (dns.get("a_records", []) or []):
        hostname = rec.get("hostname", "")
        if hostname and hostname != host and hostname.endswith("." + host):
            subdomains.add(hostname.lower())

    # ── Aggregate IP addresses ──
    ip_addresses = set()
    # From harvester
    for ip in (harv.get("ips", []) or []):
        if ip:
            ip_addresses.add(str(ip))
    # From amass
    for ip in (amass_data.get("ip_addresses", []) or []):
        if ip:
            ip_addresses.add(str(ip))
    # From dnsrecon A records
    for rec in (dns.get("a_records", []) or []):
        ip = rec.get("ip", "")
        if ip:
            ip_addresses.add(str(ip))

    # ── DNS records (from dnsrecon) ──
    dns_records = {}
    if not dns.get("skipped"):
        dns_records = {
            "a_records": dns.get("a_records", []),
            "mx_records": dns.get("mx_records", []),
            "ns_records": dns.get("ns_records", []),
            "txt_records": dns.get("txt_records", []),
            "srv_records": dns.get("srv_records", []),
        }

    # ── WHOIS info ──
    whois_info = {}
    if not whois_data.get("error"):
        whois_info = whois_data

    # ── Data sources tracking ──
    data_sources = []
    if not harv.get("error"):
        data_sources.append({"source": "theHarvester", "emails": len(harv_emails),
                             "subdomains": len(harv.get("subdomains", []) or [])})
    if not dns.get("skipped"):
        data_sources.append({"source": "DNSRecon", "records": dns.get("total_records", 0),
                             "subdomains": len(dns.get("subdomains", []) or [])})
    if not amass_data.get("skipped"):
        data_sources.append({"source": "Amass", "subdomains": amass_data.get("total_count", 0)})
        # Include Amass source list
        for s in (amass_data.get("sources", []) or []):
            data_sources.append({"source": f"Amass/{s}", "type": "passive"})
    if not whois_data.get("error"):
        data_sources.append({"source": "WHOIS", "type": whois_data.get("type", "")})

    # ── Risk indicators ──
    risk_indicators = []
    if dns.get("zone_transfer"):
        risk_indicators.append({
            "id": "zone_transfer", "severity": "critical",
            "title": "DNS Zone Transfer Possible",
            "description": "Full DNS zone data exposed to unauthorized queries.",
        })
    if dns.get("spf_configured") is False:
        risk_indicators.append({
            "id": "no_spf", "severity": "high",
            "title": "No SPF Record",
            "description": "Domain lacks SPF record — vulnerable to email spoofing.",
        })
    if dns.get("dmarc_configured") is False:
        risk_indicators.append({
            "id": "no_dmarc", "severity": "high",
            "title": "No DMARC Record",
            "description": "Domain lacks DMARC record — no email authentication policy.",
        })
    if whois_data.get("soon_expiring"):
        risk_indicators.append({
            "id": "expiring_domain", "severity": "medium",
            "title": "Domain Expiring Soon",
            "description": f"Domain expires in {whois_data.get('days_until_expiry', '?')} days.",
        })
    if whois_data.get("is_expired"):
        risk_indicators.append({
            "id": "expired_domain", "severity": "critical",
            "title": "Domain Expired",
            "description": "Domain registration has expired — risk of takeover.",
        })
    if whois_data.get("privacy_protected"):
        risk_indicators.append({
            "id": "privacy_protected", "severity": "info",
            "title": "WHOIS Privacy Protected",
            "description": "Domain registrant uses privacy protection service.",
        })

    return {
        "target": host,
        "emails": sorted(emails),
        "subdomains": sorted(subdomains),
        "ip_addresses": sorted(ip_addresses),
        "dns_records": dns_records,
        "whois_info": whois_info,
        "data_sources": data_sources,
        "risk_indicators": risk_indicators,
        "module_errors": module_errors,
        "summary": {
            "total_emails": len(emails),
            "total_subdomains": len(subdomains),
            "total_ips": len(ip_addresses),
            "risk_count": len(risk_indicators),
            "sources_count": len([d for d in data_sources if "/" not in d.get("source", "")]),
            "errors_count": len(module_errors),
        },
    }
