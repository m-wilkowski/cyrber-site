"""CYRBER VERIFY — fraud & scam verification for URLs, companies, and emails.

Aggregates signals from multiple OSINT sources (WHOIS, Google Safe Browsing,
VirusTotal, URLhaus, GreyNoise, Wayback Machine, KRS/CEIDG, Companies House,
MX records, disposable-email lists) and produces a risk score + AI verdict.
"""

import json
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

log = logging.getLogger("cyrber.verify")

REQUEST_TIMEOUT = 15

# ── ENV keys ──
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "") or os.getenv("VIRUSTOTAL_KEY", "")
COMPANIES_HOUSE_KEY = os.getenv("COMPANIES_HOUSE_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

# ── Disposable email cache ──
_DISPOSABLE_DOMAINS: set[str] | None = None
_DISPOSABLE_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"


def _load_disposable_domains() -> set[str]:
    """Load disposable email domain list (cached in memory)."""
    global _DISPOSABLE_DOMAINS
    if _DISPOSABLE_DOMAINS is not None:
        return _DISPOSABLE_DOMAINS
    try:
        resp = requests.get(_DISPOSABLE_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        _DISPOSABLE_DOMAINS = {
            line.strip().lower()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        log.info(f"Loaded {len(_DISPOSABLE_DOMAINS)} disposable email domains")
    except Exception as exc:
        log.warning(f"Failed to load disposable domains: {exc}")
        _DISPOSABLE_DOMAINS = set()
    return _DISPOSABLE_DOMAINS


def _resolve_domain_ip(domain: str) -> str | None:
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _urlhaus_lookup(host: str) -> dict:
    """Wrapper around intelligence_sync.sync_urlhaus for testability."""
    try:
        from modules.intelligence_sync import sync_urlhaus
        return sync_urlhaus(host) or {"urls_count": 0, "blacklisted": False}
    except Exception:
        return {"urls_count": 0, "blacklisted": False}


def _greynoise_lookup(ip: str) -> dict:
    """Wrapper around intelligence_sync.sync_greynoise for testability."""
    try:
        from modules.intelligence_sync import sync_greynoise
        return sync_greynoise(ip) or {"classification": "unknown"}
    except Exception:
        return {"classification": "unknown"}


def _extract_domain(url_or_host: str) -> str:
    """Extract domain from URL or hostname."""
    if "://" in url_or_host:
        parsed = urlparse(url_or_host)
        return parsed.hostname or url_or_host
    return url_or_host.split("/")[0].split(":")[0]


# ═══════════════════════════════════════════════════════════════
#  WHOIS LOOKUP
# ═══════════════════════════════════════════════════════════════

def _whois_lookup(domain: str) -> dict:
    """Perform WHOIS lookup and return registration info."""
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        registrar = w.registrar or ""
        org = w.org or ""
        country = w.country or ""

        age_days = None
        if creation:
            if isinstance(creation, datetime):
                age_days = (datetime.now() - creation).days
            creation = str(creation)

        if expiration and isinstance(expiration, datetime):
            expiration = str(expiration)

        return {
            "domain": domain,
            "registrar": registrar,
            "org": org,
            "country": country,
            "creation_date": creation,
            "expiration_date": str(expiration) if expiration else None,
            "age_days": age_days,
            "available": False,
        }
    except Exception as exc:
        log.warning(f"WHOIS lookup failed for {domain}: {exc}")
        return {"domain": domain, "error": str(exc), "age_days": None, "available": True}


# ═══════════════════════════════════════════════════════════════
#  GOOGLE SAFE BROWSING
# ═══════════════════════════════════════════════════════════════

def _google_safe_browsing(url: str) -> dict:
    """Check URL against Google Safe Browsing API."""
    if not GOOGLE_SAFE_BROWSING_KEY:
        return {"available": False, "reason": "no_api_key"}
    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}",
            json={
                "client": {"clientId": "cyrber", "clientVersion": "0.3.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        return {
            "available": True,
            "flagged": len(matches) > 0,
            "threats": [m.get("threatType", "") for m in matches],
        }
    except Exception as exc:
        log.warning(f"Google Safe Browsing failed: {exc}")
        return {"available": False, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════
#  VIRUSTOTAL
# ═══════════════════════════════════════════════════════════════

def _virustotal_url(url: str) -> dict:
    """Check URL against VirusTotal API."""
    if not VIRUSTOTAL_KEY:
        return {"available": False, "reason": "no_api_key"}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            return {"available": True, "found": False, "positives": 0, "total": 0}
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        return {
            "available": True,
            "found": True,
            "positives": positives,
            "total": total,
            "reputation": data.get("reputation", 0),
            "categories": data.get("categories", {}),
        }
    except Exception as exc:
        log.warning(f"VirusTotal URL check failed: {exc}")
        return {"available": False, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════
#  WAYBACK MACHINE
# ═══════════════════════════════════════════════════════════════

def _wayback_first(domain: str) -> dict:
    """Check first archive date via Wayback Machine CDX API."""
    try:
        resp = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url={domain}&limit=1&output=json&fl=timestamp",
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if len(data) > 1:
            ts = data[1][0]  # first row after header
            first_date = datetime.strptime(ts[:8], "%Y%m%d")
            age_days = (datetime.now() - first_date).days
            return {"available": True, "first_archive": str(first_date.date()), "archive_age_days": age_days}
        return {"available": True, "first_archive": None, "archive_age_days": None}
    except Exception as exc:
        log.warning(f"Wayback Machine lookup failed for {domain}: {exc}")
        return {"available": False, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════
#  MX RECORDS
# ═══════════════════════════════════════════════════════════════

def _check_mx(domain: str) -> dict:
    """Check MX records for a domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        records = [{"host": str(r.exchange).rstrip("."), "priority": r.preference} for r in answers]
        return {"has_mx": True, "records": records}
    except Exception:
        return {"has_mx": False, "records": []}


# ═══════════════════════════════════════════════════════════════
#  RDAP (Registration Data Access Protocol)
# ═══════════════════════════════════════════════════════════════

def _rdap_lookup(domain: str) -> dict:
    """Perform RDAP lookup for domain registration data."""
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return {"available": False, "error": "not_found"}
        resp.raise_for_status()
        data = resp.json()

        registrar = ""
        registration = None
        expiry = None
        status = []

        # Extract registrar from entities
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
                for item in vcard:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        registrar = item[3]

        # Extract dates from events
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action == "registration":
                registration = date
            elif action == "expiration":
                expiry = date

        status = data.get("status", [])

        return {
            "available": True,
            "registration": registration,
            "expiry": expiry,
            "registrar": registrar,
            "status": status,
        }
    except Exception as exc:
        log.warning(f"RDAP lookup failed for {domain}: {exc}")
        return {"available": False, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════
#  CRT.SH (Certificate Transparency)
# ═══════════════════════════════════════════════════════════════

def _crtsh_lookup(domain: str) -> dict:
    """Check oldest certificate via crt.sh."""
    try:
        resp = requests.get(
            f"https://crt.sh/?q={domain}&output=json&limit=1",
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 404 or not resp.text.strip():
            return {"available": True, "cert_age_days": None}
        resp.raise_for_status()
        data = resp.json()
        if not data:
            return {"available": True, "cert_age_days": None}
        oldest = data[-1] if isinstance(data, list) else data
        not_before = oldest.get("not_before") or oldest.get("entry_timestamp", "")
        if not_before:
            cert_date = datetime.strptime(not_before[:10], "%Y-%m-%d")
            cert_age_days = (datetime.now() - cert_date).days
            return {"available": True, "cert_age_days": cert_age_days, "issuer": oldest.get("issuer_name", "")}
        return {"available": True, "cert_age_days": None}
    except Exception as exc:
        log.warning(f"crt.sh lookup failed for {domain}: {exc}")
        return {"available": False, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════
#  SPF / DMARC DNS check
# ═══════════════════════════════════════════════════════════════

def _check_spf_dmarc(domain: str) -> dict:
    """Check SPF and DMARC DNS TXT records."""
    result = {"has_spf": False, "has_dmarc": False}
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    result["has_spf"] = True
        except Exception:
            pass
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    result["has_dmarc"] = True
        except Exception:
            pass
    except Exception as exc:
        log.warning(f"SPF/DMARC check failed for {domain}: {exc}")
    return result


# ═══════════════════════════════════════════════════════════════
#  IPINFO
# ═══════════════════════════════════════════════════════════════

def _ipinfo_lookup(ip: str) -> dict:
    """Lookup IP info via ipinfo.io."""
    try:
        headers = {}
        url = f"https://ipinfo.io/{ip}/json"
        if IPINFO_TOKEN:
            headers["Authorization"] = f"Bearer {IPINFO_TOKEN}"
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return {
            "available": True,
            "org": data.get("org", ""),
            "country": data.get("country", ""),
            "city": data.get("city", ""),
            "hosting": data.get("hosting", False),
        }
    except Exception as exc:
        log.warning(f"IPinfo lookup failed for {ip}: {exc}")
        return {"available": False, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════
#  ABUSEIPDB
# ═══════════════════════════════════════════════════════════════

def _abuseipdb_lookup(ip: str) -> dict:
    """Check IP against AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        return {"available": False, "reason": "no_api_key"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})
        return {
            "available": True,
            "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
            "totalReports": d.get("totalReports", 0),
            "isWhitelisted": d.get("isWhitelisted", False),
            "countryCode": d.get("countryCode", ""),
        }
    except Exception as exc:
        log.warning(f"AbuseIPDB lookup failed for {ip}: {exc}")
        return {"available": False, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════
#  OTX (AlienVault Open Threat Exchange)
# ═══════════════════════════════════════════════════════════════

def _otx_lookup(domain: str) -> dict:
    """Check domain in AlienVault OTX."""
    try:
        headers = {"Accept": "application/json"}
        if OTX_API_KEY:
            headers["X-OTX-API-KEY"] = OTX_API_KEY
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        validation = data.get("validation", [])
        return {
            "available": True,
            "pulse_count": pulse_count,
            "validation": validation,
        }
    except Exception as exc:
        log.warning(f"OTX lookup failed for {domain}: {exc}")
        return {"available": False, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════
#  TRANCO (Top Sites Ranking)
# ═══════════════════════════════════════════════════════════════

def _tranco_lookup(domain: str) -> dict:
    """Check domain ranking in Tranco top list."""
    try:
        resp = requests.get(
            f"https://tranco-list.eu/api/ranks/domain/{domain}",
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        # Tranco returns ranks array
        ranks = data.get("ranks", [])
        rank = ranks[0].get("rank") if ranks else None
        return {"available": True, "rank": rank}
    except Exception as exc:
        log.warning(f"Tranco lookup failed for {domain}: {exc}")
        return {"available": False, "rank": None}


# ═══════════════════════════════════════════════════════════════
#  COMPANY REGISTRIES
# ═══════════════════════════════════════════════════════════════

def _krs_lookup(nip_or_name: str) -> dict:
    """Check Polish KRS registry."""
    # Detect if it's a NIP (10 digits) or name
    clean = re.sub(r"[\s-]", "", nip_or_name)
    if re.match(r"^\d{10}$", clean):
        url = f"https://api-krs.ms.gov.pl/api/krs/OdpisAktualny/{clean}?rejestr=P&format=json"
    else:
        url = f"https://api-krs.ms.gov.pl/api/krs/OdpisAktualny/{nip_or_name}?rejestr=P&format=json"

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return {"found": False, "registry": "KRS"}
        resp.raise_for_status()
        data = resp.json()
        dane = data.get("odpis", {}).get("dane", {})
        return {
            "found": True,
            "registry": "KRS",
            "name": dane.get("nazwa", ""),
            "krs": dane.get("numerKRS", ""),
            "nip": dane.get("nip", ""),
            "regon": dane.get("regon", ""),
            "address": dane.get("adres", ""),
            "registration_date": dane.get("dataRejestracjiWKRS", ""),
            "status": "active",
        }
    except Exception as exc:
        log.warning(f"KRS lookup failed: {exc}")
        return {"found": False, "registry": "KRS", "error": str(exc)}


def _ceidg_lookup(nip_or_name: str) -> dict:
    """Check Polish CEIDG registry (sole proprietors)."""
    clean = re.sub(r"[\s-]", "", nip_or_name)
    if re.match(r"^\d{10}$", clean):
        url = f"https://dane.biznes.gov.pl/api/ceidg/v2/firma?nip={clean}"
    else:
        url = f"https://dane.biznes.gov.pl/api/ceidg/v2/firma?nazwa={nip_or_name}"

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return {"found": False, "registry": "CEIDG"}
        resp.raise_for_status()
        data = resp.json()
        firmy = data.get("firmy", [])
        if not firmy:
            return {"found": False, "registry": "CEIDG"}
        f = firmy[0]
        return {
            "found": True,
            "registry": "CEIDG",
            "name": f.get("nazwa", ""),
            "nip": f.get("wlasciciel", {}).get("nip", ""),
            "status": f.get("status", ""),
            "start_date": f.get("dataRozpoczeciaDzialalnosci", ""),
            "address": f.get("adresDzialalnosci", {}).get("adres", ""),
        }
    except Exception as exc:
        log.warning(f"CEIDG lookup failed: {exc}")
        return {"found": False, "registry": "CEIDG", "error": str(exc)}


def _companies_house_lookup(query: str) -> dict:
    """Check UK Companies House registry."""
    if not COMPANIES_HOUSE_KEY:
        return {"found": False, "registry": "Companies House", "reason": "no_api_key"}
    try:
        resp = requests.get(
            f"https://api.company-information.service.gov.uk/search/companies?q={query}",
            auth=(COMPANIES_HOUSE_KEY, ""),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        items = data.get("items", [])
        if not items:
            return {"found": False, "registry": "Companies House"}
        c = items[0]
        return {
            "found": True,
            "registry": "Companies House",
            "name": c.get("title", ""),
            "company_number": c.get("company_number", ""),
            "status": c.get("company_status", ""),
            "date_of_creation": c.get("date_of_creation", ""),
            "address": c.get("address_snippet", ""),
            "company_type": c.get("company_type", ""),
        }
    except Exception as exc:
        log.warning(f"Companies House lookup failed: {exc}")
        return {"found": False, "registry": "Companies House", "error": str(exc)}


# ═══════════════════════════════════════════════════════════════
#  RISK SCORING
# ═══════════════════════════════════════════════════════════════

def calculate_risk(signals: dict) -> int:
    """Calculate risk score (0-100) from aggregated signals — bidirectional scoring.

    Positive factors increase risk, negative factors (trust signals) decrease it.
    Floor: 0, Cap: 100.
    Thresholds: <20 BEZPIECZNE, 20-50 PODEJRZANE, >50 OSZUSTWO.
    """
    score = 0

    # ── INCREASING FACTORS ──

    # WHOIS age
    whois_data = signals.get("whois", {})
    age = whois_data.get("age_days")
    if age is not None:
        if age < 90:
            score += 40
        elif age < 365:
            score += 20

    # Domain looks available / unregistered
    if whois_data.get("available"):
        score += 30

    # Google Safe Browsing
    gsb = signals.get("google_safe_browsing", {})
    if gsb.get("flagged"):
        score += 70

    # VirusTotal
    vt = signals.get("virustotal", {})
    if vt.get("positives", 0) >= 5:
        score += 60
    elif vt.get("positives", 0) >= 2:
        score += 30

    # URLhaus
    urlhaus = signals.get("urlhaus", {})
    if urlhaus.get("blacklisted"):
        score += 50

    # GreyNoise
    gn = signals.get("greynoise", {})
    if gn.get("classification") == "malicious":
        score += 30

    # Company registry — not found
    company = signals.get("company", {})
    if company and not company.get("found", True):
        score += 60

    # Disposable email
    if signals.get("disposable_email"):
        score += 50

    # No MX records
    mx = signals.get("mx", {})
    if mx and not mx.get("has_mx", True):
        score += 30

    # Wayback Machine — very new site
    wb = signals.get("wayback", {})
    archive_age = wb.get("archive_age_days")
    if archive_age is not None and archive_age < 180:
        score += 25

    # AbuseIPDB high score
    abuse = signals.get("abuseipdb", {})
    abuse_score = abuse.get("abuseConfidenceScore", 0)
    if abuse_score > 50:
        score += 40
    elif abuse_score > 20:
        score += 20

    # OTX pulses
    otx = signals.get("otx", {})
    otx_pulses = otx.get("pulse_count", 0)
    if otx_pulses > 5:
        score += 40
    elif otx_pulses > 0:
        score += 20

    # IPinfo — high-risk countries
    ipinfo = signals.get("ipinfo", {})
    ipinfo_country = (ipinfo.get("country") or "").upper()
    if ipinfo_country in ("UA", "RU", "KP", "IR", "CN"):
        score += 25

    # SPF/DMARC — both missing
    spf_dmarc = signals.get("spf_dmarc", {})
    if spf_dmarc and not spf_dmarc.get("has_spf") and not spf_dmarc.get("has_dmarc"):
        score += 15

    # crt.sh — very new cert
    crtsh = signals.get("crtsh", {})
    cert_age = crtsh.get("cert_age_days")
    if cert_age is not None and cert_age < 30:
        score += 25

    # No Tranco rank (not in top 1M)
    tranco = signals.get("tranco", {})
    if tranco.get("available") and tranco.get("rank") is None:
        score += 10

    # ── DECREASING FACTORS (trust signals) ──

    # Tranco ranking
    tranco_rank = tranco.get("rank")
    if tranco_rank is not None:
        if tranco_rank <= 10000:
            score -= 50
        elif tranco_rank <= 100000:
            score -= 30
        elif tranco_rank <= 1000000:
            score -= 15

    # AbuseIPDB whitelisted
    if abuse.get("isWhitelisted"):
        score -= 30

    # OTX validation non-empty (domain validated / analyzed)
    if otx.get("validation") and len(otx["validation"]) > 0:
        score -= 20

    # Domain age — long-standing
    if age is not None:
        if age > 3650:  # >10 years
            score -= 30
        elif age > 1825:  # >5 years
            score -= 20

    # crt.sh — old cert (>2 years)
    if cert_age is not None and cert_age > 730:
        score -= 20

    # SPF + DMARC both present
    if spf_dmarc.get("has_spf") and spf_dmarc.get("has_dmarc"):
        score -= 10

    # Company confirmed in registry
    if company and company.get("found"):
        score -= 40

    return max(0, min(100, score))


# ═══════════════════════════════════════════════════════════════
#  AI VERDICT
# ═══════════════════════════════════════════════════════════════

def _extract_problems(signals: dict) -> list[dict]:
    """Convert red flags into structured problem cards with what_found/what_means/real_risk."""
    problems = []

    whois = signals.get("whois", {})
    age = whois.get("age_days")
    if age is not None and age < 90:
        problems.append({
            "title": "Bardzo nowa domena",
            "what_found": f"Domena została zarejestrowana zaledwie {age} dni temu.",
            "what_means": "Oszuści zakładają nowe strony tuż przed atakiem i porzucają je po kilku tygodniach. Legalne firmy mają domeny od lat.",
            "real_risk": "Strona może zniknąć razem z Twoimi pieniędzmi.",
        })
    elif age is not None and age < 365:
        problems.append({
            "title": "Stosunkowo nowa domena",
            "what_found": f"Domena istnieje od {age} dni (mniej niż rok).",
            "what_means": "Nowe domeny nie muszą być złośliwe, ale warto zachować czujność — większość oszustw odbywa się na domenach młodszych niż rok.",
            "real_risk": "Podwyższone ryzyko — zweryfikuj firmę innymi kanałami.",
        })

    gsb = signals.get("google_safe_browsing", {})
    if gsb.get("flagged"):
        threats = ", ".join(gsb.get("threats", []))
        problems.append({
            "title": "Google ostrzega przed tą stroną",
            "what_found": f"Google Safe Browsing aktywnie blokuje tę stronę. Zagrożenia: {threats}.",
            "what_means": "Google przeskanował miliardy stron i oznaczył tę jako niebezpieczną. Twoja przeglądarka powinna pokazać ostrzeżenie.",
            "real_risk": "Wejście na tę stronę może zainstalować złośliwe oprogramowanie lub wykraść Twoje dane.",
        })

    vt = signals.get("virustotal", {})
    pos = vt.get("positives", 0)
    if pos >= 5:
        problems.append({
            "title": "Antywirusy oznaczają jako złośliwe",
            "what_found": f"{pos} z {vt.get('total', 0)} silników antywirusowych oznaczyło ten URL.",
            "what_means": "To jak gdyby kilkudziesięciu lekarzy zbadało pacjenta i większość powiedziała, że jest chory. Jeśli wiele antywirusów się zgadza — to poważny sygnał.",
            "real_risk": "Możesz stracić pieniądze lub dane osobowe.",
        })
    elif pos >= 2:
        problems.append({
            "title": "Kilka antywirusów ma zastrzeżenia",
            "what_found": f"{pos} z {vt.get('total', 0)} silników oznaczyło ten URL.",
            "what_means": "Nie jest to jednoznaczne, ale kilka niezależnych systemów zabezpieczeń wykryło potencjalne zagrożenie.",
            "real_risk": "Zachowaj ostrożność — nie podawaj danych osobowych.",
        })

    urlhaus = signals.get("urlhaus", {})
    if urlhaus.get("blacklisted"):
        problems.append({
            "title": "Strona na czarnej liście",
            "what_found": "URLhaus (baza złośliwych stron) ma tę domenę na czarnej liście.",
            "what_means": "Ta strona była wcześniej wykorzystywana do rozprzestrzeniania złośliwego oprogramowania lub phishingu.",
            "real_risk": "Twój komputer może zostać zainfekowany wirusem.",
        })

    gn = signals.get("greynoise", {})
    if gn.get("classification") == "malicious":
        problems.append({
            "title": "IP oznaczone jako złośliwe",
            "what_found": "GreyNoise klasyfikuje adres IP serwera jako złośliwy.",
            "what_means": "Serwer, na którym stoi ta strona, jest znany z podejrzanej aktywności w internecie.",
            "real_risk": "Strona może być częścią większej sieci oszustw.",
        })

    company = signals.get("company", {})
    if company and not company.get("found", True):
        problems.append({
            "title": "Firma nie istnieje w rejestrze",
            "what_found": "Nie znaleźliśmy tej firmy w oficjalnym rejestrze KRS ani CEIDG.",
            "what_means": "Każda legalna polska firma musi być zarejestrowana. Jeśli jej nie ma w rejestrze — albo podaje fałszywą nazwę, albo działa nielegalnie.",
            "real_risk": "Nie masz żadnej ochrony prawnej jeśli firma Cię oszuka.",
        })

    if signals.get("disposable_email"):
        problems.append({
            "title": "Jednorazowy adres email",
            "what_found": "Domena emailowa należy do serwisu jednorazowych adresów.",
            "what_means": "Osoba używa tymczasowego emaila, który za chwilę przestanie istnieć. Legalne firmy nie używają takich adresów.",
            "real_risk": "Nie będziesz w stanie skontaktować się z nadawcą.",
        })

    mx = signals.get("mx", {})
    if mx and not mx.get("has_mx", True):
        problems.append({
            "title": "Domena nie obsługuje poczty",
            "what_found": "Brak rekordów MX — ta domena nie może wysyłać ani odbierać emaili.",
            "what_means": "Jeśli firma twierdzi, że kontakt jest przez email na tej domenie — kłamie.",
            "real_risk": "Odpowiedzi na emaile nie dotrą do nikogo.",
        })

    abuse = signals.get("abuseipdb", {})
    if abuse.get("abuseConfidenceScore", 0) > 20:
        problems.append({
            "title": "IP zgłaszane za nadużycia",
            "what_found": f"AbuseIPDB: {abuse['abuseConfidenceScore']}% pewności nadużyć, {abuse.get('totalReports', 0)} zgłoszeń.",
            "what_means": "Inni internauci zgłaszali problemy z tym adresem IP — spam, ataki, oszustwa.",
            "real_risk": "Serwer ma złą reputację w społeczności bezpieczeństwa.",
        })

    spf_dmarc = signals.get("spf_dmarc", {})
    if spf_dmarc and not spf_dmarc.get("has_spf") and not spf_dmarc.get("has_dmarc"):
        problems.append({
            "title": "Brak ochrony przed podszywaniem",
            "what_found": "Domena nie ma zabezpieczeń SPF ani DMARC.",
            "what_means": "Ktokolwiek może wysyłać emaile udając, że jest z tej domeny. To jak gdyby firma nie miała pieczątki.",
            "real_risk": "Możesz dostać fałszywy email wyglądający jak od tej firmy.",
        })

    crtsh = signals.get("crtsh", {})
    if crtsh.get("cert_age_days") is not None and crtsh["cert_age_days"] < 30:
        problems.append({
            "title": "Bardzo nowy certyfikat SSL",
            "what_found": f"Certyfikat SSL wystawiony {crtsh['cert_age_days']} dni temu.",
            "what_means": "Oszuści uzyskują certyfikaty SSL tuż przed atakiem, żeby strona wyglądała na bezpieczną (kłódka w przeglądarce).",
            "real_risk": "Kłódka w przeglądarce NIE gwarantuje bezpieczeństwa.",
        })

    otx = signals.get("otx", {})
    if otx.get("pulse_count", 0) > 0:
        problems.append({
            "title": "Widoczna w raportach zagrożeń",
            "what_found": f"OTX AlienVault: {otx['pulse_count']} raportów threat intelligence.",
            "what_means": "Eksperci ds. bezpieczeństwa analizowali tę domenę i powiązali ją z zagrożeniami.",
            "real_risk": "Domena jest znana w świecie cyberbezpieczeństwa jako podejrzana.",
        })

    return problems


def _extract_positives(signals: dict) -> list[dict]:
    """Convert trust factors into structured positive cards with what_found/what_means."""
    positives = []

    tranco = signals.get("tranco", {})
    rank = tranco.get("rank")
    if rank is not None:
        if rank <= 10000:
            positives.append({
                "title": "Popularna strona",
                "what_found": f"Domena jest na pozycji #{rank} w rankingu Tranco (top 10K).",
                "what_means": "To jedna z najpopularniejszych stron w internecie — miliony ludzi z niej korzystają.",
            })
        elif rank <= 100000:
            positives.append({
                "title": "Znana strona",
                "what_found": f"Domena jest na pozycji #{rank} w rankingu Tranco.",
                "what_means": "Strona ma spory ruch — to dobry znak, bo oszuści rzadko osiągają taką popularność.",
            })

    whois = signals.get("whois", {})
    age = whois.get("age_days")
    if age is not None and age > 3650:
        positives.append({
            "title": "Domena od wielu lat",
            "what_found": f"Domena istnieje od {age // 365} lat.",
            "what_means": "Długo działające domeny to dobry znak — oszuści porzucają strony po kilku miesiącach.",
        })
    elif age is not None and age > 1825:
        positives.append({
            "title": "Ugruntowana domena",
            "what_found": f"Domena istnieje od {age // 365} lat.",
            "what_means": "Kilka lat działalności buduje zaufanie.",
        })

    abuse = signals.get("abuseipdb", {})
    if abuse.get("isWhitelisted"):
        positives.append({
            "title": "IP na białej liście",
            "what_found": "AbuseIPDB uznaje ten adres IP za zaufany.",
            "what_means": "Serwer jest oficjalnie uznawany za bezpieczny przez społeczność bezpieczeństwa.",
        })

    spf_dmarc = signals.get("spf_dmarc", {})
    if spf_dmarc.get("has_spf") and spf_dmarc.get("has_dmarc"):
        positives.append({
            "title": "Ochrona przed spoofingiem",
            "what_found": "Domena ma skonfigurowane zabezpieczenia SPF + DMARC.",
            "what_means": "Firma dba o bezpieczeństwo emaili — nikt nie może się pod nią podszywać.",
        })

    company = signals.get("company", {})
    if company and company.get("found"):
        registry = company.get("registry", "rejestr")
        positives.append({
            "title": "Firma w oficjalnym rejestrze",
            "what_found": f"Firma potwierdzona w {registry}.",
            "what_means": "Firma jest oficjalnie zarejestrowana, co oznacza że podlega polskiemu prawu i można ją pociągnąć do odpowiedzialności.",
        })

    crtsh = signals.get("crtsh", {})
    cert_age = crtsh.get("cert_age_days")
    if cert_age is not None and cert_age > 730:
        positives.append({
            "title": "Długotrwały certyfikat SSL",
            "what_found": f"Certyfikat SSL od {cert_age // 365} lat.",
            "what_means": "Strona od dawna dba o szyfrowanie — to dobra praktyka.",
        })

    return positives


def _generate_action(risk_score: int, query: str) -> str:
    """Generate concrete action recommendation based on risk score."""
    if risk_score > 50:
        return f"Nie wchodź na {query}. Jeśli ktoś przysłał Ci ten link — zignoruj wiadomość. Jeśli podałeś dane, natychmiast zmień hasła i skontaktuj się z bankiem."
    elif risk_score >= 20:
        return f"Zachowaj ostrożność. Nie podawaj danych osobowych ani finansowych na {query}. Sprawdź adres URL dokładnie — czy to na pewno oficjalna strona?"
    else:
        return f"Strona {query} wygląda bezpiecznie. Pamiętaj jednak, aby zawsze sprawdzać adres URL przed podaniem danych."


def _generate_immediate_actions(risk_score: int, query: str) -> list[str]:
    """Generate numbered list of immediate actions."""
    if risk_score > 50:
        return [
            f"Nie wchodź na {query} — zamknij kartę jeśli jest otwarta",
            "Jeśli kliknąłeś link — uruchom skanowanie antywirusowe na komputerze",
            "Jeśli podałeś login/hasło — natychmiast zmień hasło na tej i innych stronach gdzie używasz tego samego",
            "Ostrzeż osobę, która przysłała Ci ten link — jej konto mogło zostać przejęte",
        ]
    elif risk_score >= 20:
        return [
            f"Nie podawaj żadnych danych osobowych ani finansowych na {query}",
            "Sprawdź adres URL literka po literce — czy to na pewno oficjalna strona?",
            "Poszukaj opinii o tej firmie w Google — dopisz słowo 'oszustwo' lub 'opinie'",
            "Jeśli chcesz coś kupić — szukaj tej samej oferty na znanych portalach (Allegro, OLX)",
        ]
    else:
        return [
            "Strona wygląda bezpiecznie — możesz z niej korzystać",
            "Mimo to zawsze sprawdzaj adres URL przed podaniem danych",
            "Używaj silnych, unikalnych haseł na każdej stronie",
        ]


def _generate_if_paid_already(risk_score: int) -> list[str]:
    """Generate steps for when user already paid/shared data."""
    if risk_score > 50:
        return [
            "Natychmiast zadzwoń do swojego banku i zablokuj kartę/konto",
            "Zmień hasła — zacznij od banku, potem email, potem reszta",
            "Włącz weryfikację dwuetapową (2FA) wszędzie gdzie to możliwe",
            "Zgłoś sprawę na policję i do CERT Polska (incydent.cert.pl)",
            "Monitoruj wyciągi bankowe przez najbliższe 30 dni",
        ]
    elif risk_score >= 20:
        return [
            "Sprawdź wyciąg bankowy — czy są nieautoryzowane transakcje",
            "Zmień hasło jeśli podałeś je na tej stronie",
            "Jeśli podałeś dane karty — skontaktuj się z bankiem",
            "Zachowaj dowody (screenshoty, emaile) na wypadek reklamacji",
        ]
    else:
        return []


def _generate_report_to(risk_score: int) -> list[dict]:
    """Generate list of institutions to report fraud to."""
    if risk_score <= 20:
        return []
    institutions = []
    if risk_score > 50:
        institutions.append({
            "institution": "CERT Polska",
            "url": "https://incydent.cert.pl",
            "description": "Zgłoś stronę phishingową lub oszustwo internetowe. CERT doda ją do listy ostrzeżeń.",
        })
        institutions.append({
            "institution": "Policja — cyberprzestępczość",
            "url": "https://www.policja.pl/pol/zgloszenie",
            "description": "Złóż oficjalne zawiadomienie o przestępstwie. Będziesz potrzebować screenshotów i dowodów wpłaty.",
        })
    institutions.append({
        "institution": "UOKiK",
        "url": "https://uokik.gov.pl/kontakt",
        "description": "Zgłoś nieuczciwą praktykę handlową. UOKiK może nałożyć karę na firmę.",
    })
    institutions.append({
        "institution": "Twój bank",
        "url": "",
        "description": "Zadzwoń na infolinię banku i poproś o procedurę chargeback (zwrot pieniędzy za oszustwo).",
    })
    return institutions


def _generate_narrative(risk_score: int, signals: dict, query: str) -> str:
    """Generate a warm, educational narrative about the verification result."""
    problems = _extract_problems(signals)
    positives = _extract_positives(signals)

    if risk_score > 50:
        intro = f"Sprawdziliśmy {query} w {len(signals)} niezależnych bazach danych bezpieczeństwa i mamy poważne obawy."
        detail = f" Znaleźliśmy {len(problems)} sygnałów ostrzegawczych." if problems else ""
        advice = " Zdecydowanie odradzamy interakcję z tą stroną — wiele wskazuje na to, że może być niebezpieczna."
        outro = " Jeśli otrzymałeś ten link w wiadomości od kogoś — nie klikaj i ostrzeż nadawcę, bo jego konto mogło zostać przejęte."
    elif risk_score >= 20:
        intro = f"Sprawdziliśmy {query} i znaleźliśmy mieszane sygnały."
        detail = f" Z jednej strony {len(positives)} czynników wygląda dobrze, ale {len(problems)} budzi nasze wątpliwości." if positives and problems else ""
        advice = " Nie oznacza to od razu oszustwa, ale zalecamy zachowanie czujności."
        outro = " Zanim podasz jakiekolwiek dane, upewnij się że to oficjalna strona firmy, z którą chcesz mieć do czynienia."
    else:
        intro = f"Sprawdziliśmy {query} w naszych bazach bezpieczeństwa i wszystko wygląda w porządku."
        detail = f" Znaleźliśmy {len(positives)} pozytywnych sygnałów zaufania." if positives else ""
        advice = " Strona ma dobre wskaźniki bezpieczeństwa."
        outro = " Pamiętaj jednak, że żadna automatyczna analiza nie daje 100% pewności — zawsze warto zachować zdrowy rozsądek."

    return intro + detail + advice + outro


def _generate_educational_tips(risk_score: int, signals: dict) -> list[dict]:
    """Generate structured educational tips based on analysis."""
    tips = []

    whois = signals.get("whois", {})
    if whois.get("age_days") is not None:
        tips.append({
            "icon": "📅",
            "title": "Sprawdzaj wiek domeny",
            "text": "Legalne firmy działają od lat. Jeśli domena ma mniej niż 90 dni — to poważny sygnał ostrzegawczy.",
            "example": "Następnym razem wpisz nazwę strony na whois.domaintools.com — zobaczysz kiedy została zarejestrowana.",
        })

    spf = signals.get("spf_dmarc", {})
    if spf:
        tips.append({
            "icon": "📧",
            "title": "SPF i DMARC chronią przed fałszywymi emailami",
            "text": "To jak pieczątka na liście — potwierdza, że email naprawdę pochodzi z tej firmy. Bez SPF i DMARC ktokolwiek może udawać daną firmę.",
            "example": "Jeśli dostaniesz email 'z banku' — sprawdź czy bank ma SPF/DMARC. Większość dużych firm je ma.",
        })

    if signals.get("virustotal", {}).get("available"):
        tips.append({
            "icon": "🔍",
            "title": "Jak samodzielnie sprawdzić link?",
            "text": "Wklej podejrzany link na virustotal.com — 70+ silników antywirusowych sprawdzi go za darmo. Nigdy nie klikaj linku, zanim go nie zweryfikujesz.",
            "example": "Kopiuj link (prawy przycisk → Kopiuj adres linku) i wklej na virustotal.com zamiast klikać.",
        })

    if signals.get("tranco", {}):
        tips.append({
            "icon": "📊",
            "title": "Ranking popularności stron",
            "text": "Tranco to niezależny ranking miliona najpopularniejszych stron. Jeśli strona jest w top 10K — prawie na pewno jest legalna.",
            "example": "Google.com jest w top 10, Allegro.pl w top 1000. Nowa strona z ofertą 'za dobrą żeby była prawdziwa' raczej nie będzie w rankingu.",
        })

    if risk_score > 50:
        tips.append({
            "icon": "🚨",
            "title": "Co zrobić gdy podałeś dane?",
            "text": "Natychmiast zmień hasła (zacznij od banku i emaila). Włącz weryfikację dwuetapową (2FA). Zgłoś incydent na incydent.cert.pl.",
            "example": "Zainstaluj aplikację do 2FA (np. Google Authenticator) — nawet jeśli ktoś pozna Twoje hasło, nie zaloguje się bez kodu z telefonu.",
        })

    if len(tips) < 3:
        tips.append({
            "icon": "🔒",
            "title": "Kłódka nie oznacza bezpieczeństwa",
            "text": "Kłódka w pasku adresu oznacza szyfrowane połączenie, ale NIE gwarantuje, że strona jest bezpieczna. Oszuści też używają HTTPS.",
            "example": "Patrz na adres obok kłódki: allegro.pl jest OK, ale allegro-promocja.xyz to oszustwo — mimo że oba mają kłódkę.",
        })

    return tips[:5]


def generate_verdict(risk_score: int, signals: dict, query: str) -> dict:
    """Generate AI verdict using Claude Haiku — educational mode for non-tech users."""
    # Determine base verdict from score (new thresholds)
    if risk_score < 20:
        base_verdict = "BEZPIECZNE"
    elif risk_score <= 50:
        base_verdict = "PODEJRZANE"
    else:
        base_verdict = "OSZUSTWO"

    # Try AI-enhanced verdict
    try:
        from modules.llm_provider import ClaudeProvider
        provider = ClaudeProvider(model="claude-haiku-4-5-20251001")

        signals_summary = json.dumps(signals, ensure_ascii=False, default=str)
        if len(signals_summary) > 3000:
            signals_summary = signals_summary[:3000] + "..."

        prompt = (
            f"Jesteś ekspertem od bezpieczeństwa online. Piszesz raport dla osoby "
            f"bez wiedzy technicznej — np. emeryta który szuka samochodu online.\n\n"
            f"Dane weryfikacji:\n{signals_summary}\n"
            f"Risk score: {risk_score}/100 (progi: <20 bezpieczne, 20-50 podejrzane, >50 oszustwo)\n"
            f"Sprawdzana domena: {query}\n\n"
            f"Zwróć WYŁĄCZNIE JSON (bez markdown, wszystkie pola PO POLSKU):\n"
            f'{{"verdict": "{base_verdict}", '
            f'"summary": "3-4 zdania. Powiedz CO konkretnie znalazłeś i DLACZEGO to niepokojące lub bezpieczne. Nie używaj żargonu technicznego.", '
            f'"narrative": "4-6 zdań ciepłym językiem — co sprawdziliśmy, co znaleźliśmy, co to oznacza", '
            f'"red_flags": ["lista flag po polsku"], '
            f'"trust_factors": ["lista czynników zaufania"], '
            f'"signal_explanations": [{{"signal": "nazwa", "value": "wartość", "meaning": "co to znaczy po polsku", "risk": "green|gray|amber|red", "icon": "emoji"}}], '
            f'"problems": [{{"title": "Krótka nazwa problemu", "what_found": "Co technicznie znalazłeś - 1 zdanie", "what_means": "Co to oznacza dla zwykłego człowieka - 1-2 zdania", "real_risk": "Konkretne ryzyko np. Możesz stracić pieniądze"}}], '
            f'"positives": [{{"title": "Krótka nazwa pozytywu", "what_found": "Co znalazłeś - 1 zdanie", "what_means": "Dlaczego to dobry znak - 1 zdanie"}}], '
            f'"immediate_actions": ["Natychmiastowe działanie 1 - konkretne i wykonalne", "Działanie 2", "Działanie 3"], '
            f'"if_paid_already": ["Co zrobić jeśli już zapłaciłeś krok 1", "Krok 2"], '
            f'"report_to": [{{"institution": "Nazwa instytucji", "url": "adres strony", "description": "Co tam zgłosić i po co"}}], '
            f'"educational_tips": [{{"icon": "emoji", "title": "Tytuł wskazówki", "text": "2-3 zdania edukacyjne", "example": "Konkretny przykład jak zastosować tę wiedzę"}}], '
            f'"recommendation": "Rekomendacja 1-2 zdania"}}\n\n'
            f"WAŻNE:\n"
            f"- Dla OSZUSTWA: report_to musi zawierać CERT Polska (incydent.cert.pl), Policję, UOKiK, bank\n"
            f"- Dla PODEJRZANE: daj konkretne kroki jak zweryfikować ręcznie\n"
            f"- if_paid_already wypełnij zawsze dla OSZUSTWO i PODEJRZANE\n"
            f"- Pisz jakbyś rozmawiał z osobą starszą która nie zna się na technologii"
        )

        response_text = provider.chat(prompt, max_tokens=2500)
        clean = response_text.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        try:
            result = json.loads(clean.strip())
        except json.JSONDecodeError:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            if start >= 0 and end > start:
                result = json.loads(response_text[start:end])
            else:
                raise

        # Ensure verdict matches score-based threshold
        result["verdict"] = base_verdict
        # Ensure all fields present with fallbacks
        result.setdefault("trust_factors", _extract_trust_factors(signals))
        result.setdefault("signal_explanations", _extract_signal_explanations(signals))
        result.setdefault("narrative", _generate_narrative(risk_score, signals, query))
        result.setdefault("problems", _extract_problems(signals))
        result.setdefault("positives", _extract_positives(signals))
        result.setdefault("action", _generate_action(risk_score, query))
        result.setdefault("immediate_actions", _generate_immediate_actions(risk_score, query))
        result.setdefault("if_paid_already", _generate_if_paid_already(risk_score))
        result.setdefault("report_to", _generate_report_to(risk_score))
        result.setdefault("educational_tips", _generate_educational_tips(risk_score, signals))
        # Normalize educational_tips to dict format
        tips = result.get("educational_tips", [])
        if tips and isinstance(tips[0], str):
            result["educational_tips"] = [{"icon": "💡", "title": "Porada", "text": t, "example": ""} for t in tips]
        return result

    except Exception as exc:
        log.warning(f"AI verdict generation failed: {exc}")
        return {
            "verdict": base_verdict,
            "summary": f"Analiza automatyczna wykazała risk score {risk_score}/100.",
            "narrative": _generate_narrative(risk_score, signals, query),
            "red_flags": _extract_red_flags(signals),
            "trust_factors": _extract_trust_factors(signals),
            "signal_explanations": _extract_signal_explanations(signals),
            "problems": _extract_problems(signals),
            "positives": _extract_positives(signals),
            "action": _generate_action(risk_score, query),
            "immediate_actions": _generate_immediate_actions(risk_score, query),
            "if_paid_already": _generate_if_paid_already(risk_score),
            "report_to": _generate_report_to(risk_score),
            "educational_tips": _generate_educational_tips(risk_score, signals),
            "recommendation": "Zalecamy ostrożność." if risk_score >= 20 else "Brak podejrzanych sygnałów.",
        }


def _extract_red_flags(signals: dict) -> list[str]:
    """Extract human-readable red flags from signals."""
    flags = []
    whois = signals.get("whois", {})
    age = whois.get("age_days")
    if age is not None and age < 90:
        flags.append(f"WHOIS: domena zarejestrowana {age} dni temu (bardzo nowa)")
    elif age is not None and age < 365:
        flags.append(f"WHOIS: domena zarejestrowana {age} dni temu (stosunkowo nowa)")
    if whois.get("available"):
        flags.append("WHOIS: domena wygląda na niezarejestrowaną")

    gsb = signals.get("google_safe_browsing", {})
    if gsb.get("flagged"):
        flags.append(f"Google Safe Browsing: {', '.join(gsb.get('threats', []))}")

    vt = signals.get("virustotal", {})
    if vt.get("positives", 0) > 0:
        flags.append(f"VirusTotal: {vt['positives']}/{vt.get('total', 0)} silników oznaczyło jako złośliwe")

    urlhaus = signals.get("urlhaus", {})
    if urlhaus.get("blacklisted"):
        flags.append("URLhaus: domena na czarnej liście")

    gn = signals.get("greynoise", {})
    if gn.get("classification") == "malicious":
        flags.append("GreyNoise: IP oznaczone jako złośliwe")

    company = signals.get("company", {})
    if company and not company.get("found", True):
        flags.append("Rejestr: firma nie znaleziona w rejestrze")

    if signals.get("disposable_email"):
        flags.append("Email: domena jednorazowego użytku (disposable)")

    mx = signals.get("mx", {})
    if mx and not mx.get("has_mx", True):
        flags.append("MX: brak rekordów (domena nie obsługuje poczty)")

    wb = signals.get("wayback", {})
    if wb.get("archive_age_days") is not None and wb["archive_age_days"] < 180:
        flags.append(f"Wayback: strona w archiwum od {wb['archive_age_days']} dni")

    # New sources
    abuse = signals.get("abuseipdb", {})
    if abuse.get("abuseConfidenceScore", 0) > 20:
        flags.append(f"AbuseIPDB: wynik zaufania {abuse['abuseConfidenceScore']}% ({abuse.get('totalReports', 0)} zgłoszeń)")

    otx = signals.get("otx", {})
    if otx.get("pulse_count", 0) > 0:
        flags.append(f"OTX: {otx['pulse_count']} pulsów threat intelligence")

    ipinfo = signals.get("ipinfo", {})
    if (ipinfo.get("country") or "").upper() in ("UA", "RU", "KP", "IR", "CN"):
        flags.append(f"IPinfo: hosting w kraju podwyższonego ryzyka ({ipinfo['country']})")

    spf_dmarc = signals.get("spf_dmarc", {})
    if spf_dmarc and not spf_dmarc.get("has_spf") and not spf_dmarc.get("has_dmarc"):
        flags.append("DNS: brak SPF i DMARC (brak ochrony przed spoofingiem)")

    crtsh = signals.get("crtsh", {})
    if crtsh.get("cert_age_days") is not None and crtsh["cert_age_days"] < 30:
        flags.append(f"crt.sh: certyfikat SSL wystawiony {crtsh['cert_age_days']} dni temu")

    return flags


def _extract_trust_factors(signals: dict) -> list[str]:
    """Extract trust-positive factors from signals."""
    factors = []

    tranco = signals.get("tranco", {})
    rank = tranco.get("rank")
    if rank is not None:
        if rank <= 10000:
            factors.append(f"Tranco: domena w top 10K najpopularniejszych stron (pozycja {rank})")
        elif rank <= 100000:
            factors.append(f"Tranco: domena w top 100K popularnych stron (pozycja {rank})")
        elif rank <= 1000000:
            factors.append(f"Tranco: domena w top 1M stron (pozycja {rank})")

    whois = signals.get("whois", {})
    age = whois.get("age_days")
    if age is not None:
        if age > 3650:
            factors.append(f"WHOIS: domena zarejestrowana od {age // 365} lat (stabilna)")
        elif age > 1825:
            factors.append(f"WHOIS: domena zarejestrowana od {age // 365} lat")

    abuse = signals.get("abuseipdb", {})
    if abuse.get("isWhitelisted"):
        factors.append("AbuseIPDB: IP na białej liście (zaufane)")

    spf_dmarc = signals.get("spf_dmarc", {})
    if spf_dmarc.get("has_spf") and spf_dmarc.get("has_dmarc"):
        factors.append("DNS: SPF + DMARC skonfigurowane (ochrona przed spoofingiem)")

    company = signals.get("company", {})
    if company and company.get("found"):
        registry = company.get("registry", "rejestr")
        factors.append(f"Rejestr: firma potwierdzona w {registry}")

    crtsh = signals.get("crtsh", {})
    cert_age = crtsh.get("cert_age_days")
    if cert_age is not None and cert_age > 730:
        factors.append(f"crt.sh: certyfikat SSL od {cert_age // 365} lat (długotrwały)")

    otx = signals.get("otx", {})
    if otx.get("validation") and len(otx["validation"]) > 0:
        factors.append("OTX: domena poddana walidacji threat intelligence")

    return factors


def _extract_signal_explanations(signals: dict) -> list[dict]:
    """Generate per-signal explanations for educational purposes."""
    explanations = []

    def _add(signal: str, value: str, meaning: str, risk: str, icon: str):
        explanations.append({"signal": signal, "value": value, "meaning": meaning, "risk": risk, "icon": icon})

    # WHOIS
    whois = signals.get("whois", {})
    age = whois.get("age_days")
    if age is not None:
        if age < 90:
            _add("WHOIS wiek", f"{age} dni", "Bardzo nowa domena — oszuści często rejestrują domeny tuż przed atakiem", "red", "🔴")
        elif age < 365:
            _add("WHOIS wiek", f"{age} dni", "Stosunkowo nowa domena — warto zachować czujność", "amber", "🟡")
        elif age > 3650:
            _add("WHOIS wiek", f"{age // 365} lat", "Długo działająca domena — to dobry znak zaufania", "green", "🟢")
        else:
            _add("WHOIS wiek", f"{age} dni", "Domena o umiarkowanym stażu", "gray", "⚪")

    # GSB
    gsb = signals.get("google_safe_browsing", {})
    if gsb.get("available"):
        if gsb.get("flagged"):
            _add("Google Safe Browsing", "OZNACZONE", "Google aktywnie ostrzega przed tą stroną", "red", "🔴")
        else:
            _add("Google Safe Browsing", "Czyste", "Google nie znalazł zagrożeń na tej stronie", "green", "🟢")

    # VT
    vt = signals.get("virustotal", {})
    if vt.get("available"):
        pos = vt.get("positives", 0)
        total = vt.get("total", 0)
        if pos >= 5:
            _add("VirusTotal", f"{pos}/{total}", "Wiele silników antywirusowych oznaczyło ten URL jako niebezpieczny", "red", "🔴")
        elif pos >= 2:
            _add("VirusTotal", f"{pos}/{total}", "Kilka silników antywirusowych ma zastrzeżenia", "amber", "🟡")
        elif pos > 0:
            _add("VirusTotal", f"{pos}/{total}", "Pojedyncze oznaczenie — może być fałszywy alarm", "gray", "⚪")
        else:
            _add("VirusTotal", f"0/{total}", "Żaden silnik antywirusowy nie znalazł zagrożeń", "green", "🟢")

    # Tranco
    tranco = signals.get("tranco", {})
    rank = tranco.get("rank")
    if tranco.get("available"):
        if rank is not None:
            _add("Tranco Ranking", f"#{rank}", f"Domena jest w top {rank} najpopularniejszych stron — to wskazuje na legitymalność", "green", "🟢")
        else:
            _add("Tranco Ranking", "Brak w rankingu", "Domena nie jest w top 1M popularnych stron", "gray", "⚪")

    # AbuseIPDB
    abuse = signals.get("abuseipdb", {})
    if abuse.get("available"):
        ascore = abuse.get("abuseConfidenceScore", 0)
        if ascore > 50:
            _add("AbuseIPDB", f"{ascore}%", "Wysokie prawdopodobieństwo nadużyć z tego IP", "red", "🔴")
        elif ascore > 20:
            _add("AbuseIPDB", f"{ascore}%", "Umiarkowana liczba zgłoszeń nadużyć z tego IP", "amber", "🟡")
        elif abuse.get("isWhitelisted"):
            _add("AbuseIPDB", "Whitelisted", "IP jest na białej liście — zaufane źródło", "green", "🟢")
        else:
            _add("AbuseIPDB", f"{ascore}%", "Brak znaczących zgłoszeń nadużyć", "green", "🟢")

    # OTX
    otx = signals.get("otx", {})
    if otx.get("available"):
        pulses = otx.get("pulse_count", 0)
        if pulses > 5:
            _add("OTX AlienVault", f"{pulses} pulsów", "Domena pojawia się w wielu raportach o zagrożeniach", "red", "🔴")
        elif pulses > 0:
            _add("OTX AlienVault", f"{pulses} pulsów", "Domena pojawiła się w raportach threat intelligence", "amber", "🟡")
        else:
            _add("OTX AlienVault", "0 pulsów", "Brak raportów o zagrożeniach związanych z tą domeną", "green", "🟢")

    # SPF/DMARC
    spf_dmarc = signals.get("spf_dmarc", {})
    if spf_dmarc:
        has_spf = spf_dmarc.get("has_spf", False)
        has_dmarc = spf_dmarc.get("has_dmarc", False)
        if has_spf and has_dmarc:
            _add("SPF + DMARC", "Oba skonfigurowane", "Domena chroni przed podszywaniem się (spoofingiem)", "green", "🟢")
        elif has_spf or has_dmarc:
            parts = []
            if has_spf:
                parts.append("SPF")
            if has_dmarc:
                parts.append("DMARC")
            _add("SPF/DMARC", " + ".join(parts), "Częściowa ochrona przed spoofingiem", "gray", "⚪")
        else:
            _add("SPF/DMARC", "Brak", "Domena nie chroni przed podszywaniem się pod nadawcę", "amber", "🟡")

    # crt.sh
    crtsh = signals.get("crtsh", {})
    cert_age = crtsh.get("cert_age_days")
    if cert_age is not None:
        if cert_age < 30:
            _add("Certyfikat SSL", f"{cert_age} dni", "Bardzo nowy certyfikat — oszuści często uzyskują SSL tuż przed atakiem", "red", "🔴")
        elif cert_age > 730:
            _add("Certyfikat SSL", f"{cert_age // 365} lat", "Długotrwały certyfikat — dobry znak", "green", "🟢")
        else:
            _add("Certyfikat SSL", f"{cert_age} dni", "Certyfikat o standardowym wieku", "gray", "⚪")

    # IPinfo
    ipinfo = signals.get("ipinfo", {})
    if ipinfo.get("available"):
        country = (ipinfo.get("country") or "").upper()
        if country in ("UA", "RU", "KP", "IR", "CN"):
            _add("IPinfo", f"{ipinfo.get('org', '')} ({country})", "Hosting w kraju podwyższonego ryzyka cybernetycznego", "amber", "🟡")
        else:
            _add("IPinfo", f"{ipinfo.get('org', '')} ({country})", "Lokalizacja serwera", "gray", "⚪")

    return explanations


# ═══════════════════════════════════════════════════════════════
#  MAIN VERIFY METHODS
# ═══════════════════════════════════════════════════════════════

class CyrberVerify:
    """Main verification engine."""

    def verify_url(self, url: str) -> dict:
        """Verify a URL for fraud signals."""
        if not url.startswith("http"):
            url = "https://" + url

        domain = _extract_domain(url)
        ip = _resolve_domain_ip(domain)

        signals = {}

        # WHOIS
        signals["whois"] = _whois_lookup(domain)

        # Google Safe Browsing
        signals["google_safe_browsing"] = _google_safe_browsing(url)

        # VirusTotal
        signals["virustotal"] = _virustotal_url(url)

        # URLhaus (reuse existing module)
        signals["urlhaus"] = _urlhaus_lookup(domain)

        # GreyNoise (IP only)
        if ip:
            signals["greynoise"] = _greynoise_lookup(ip)
            signals["resolved_ip"] = ip

        # Wayback Machine
        signals["wayback"] = _wayback_first(domain)

        # ── New v2 sources ──
        signals["rdap"] = _rdap_lookup(domain)
        signals["crtsh"] = _crtsh_lookup(domain)
        signals["spf_dmarc"] = _check_spf_dmarc(domain)
        signals["tranco"] = _tranco_lookup(domain)
        if ip:
            signals["ipinfo"] = _ipinfo_lookup(ip)
            signals["abuseipdb"] = _abuseipdb_lookup(ip)
        signals["otx"] = _otx_lookup(domain)

        risk_score = calculate_risk(signals)
        verdict = generate_verdict(risk_score, signals, url)

        return {
            "query": url,
            "type": "url",
            "domain": domain,
            "risk_score": risk_score,
            "signals": signals,
            **verdict,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def verify_company(self, query: str, country: str = "PL") -> dict:
        """Verify a company in public registries."""
        signals = {}
        country = country.upper()

        if country == "PL":
            krs = _krs_lookup(query)
            ceidg = _ceidg_lookup(query)
            # Use whichever found results
            if krs.get("found"):
                signals["company"] = krs
            elif ceidg.get("found"):
                signals["company"] = ceidg
            else:
                signals["company"] = {"found": False, "registry": "KRS+CEIDG", "krs": krs, "ceidg": ceidg}
        elif country == "UK":
            signals["company"] = _companies_house_lookup(query)
        else:
            signals["company"] = {"found": False, "registry": "unsupported_country"}

        # If company has a website, check the domain too
        company = signals.get("company", {})
        company_name = company.get("name", query)

        risk_score = calculate_risk(signals)
        verdict = generate_verdict(risk_score, signals, query)

        return {
            "query": query,
            "type": "company",
            "country": country,
            "risk_score": risk_score,
            "signals": signals,
            **verdict,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def verify_email(self, email: str) -> dict:
        """Verify an email address for fraud signals."""
        signals = {}

        # Extract domain
        parts = email.split("@")
        if len(parts) != 2:
            return {
                "query": email, "type": "email", "risk_score": 80,
                "verdict": "OSZUSTWO", "summary": "Nieprawidłowy format adresu email.",
                "narrative": "Podany adres email ma nieprawidłowy format — brakuje znaku @ lub domeny. Prawidłowy email wygląda tak: nazwa@domena.pl. Nie mogliśmy przeprowadzić dalszej analizy.",
                "red_flags": ["Nieprawidłowy format email"],
                "trust_factors": [], "signal_explanations": [],
                "problems": [{"title": "Nieprawidłowy format", "what_found": "Adres email nie zawiera znaku @ z domeną.", "what_means": "To nie jest prawdziwy adres email.", "real_risk": "Nie można zweryfikować nadawcy."}],
                "positives": [],
                "action": "Sprawdź poprawność adresu email i spróbuj ponownie.",
                "immediate_actions": ["Sprawdź poprawność adresu email i spróbuj ponownie"],
                "if_paid_already": [],
                "report_to": [],
                "educational_tips": [{"icon": "📧", "title": "Format email", "text": "Prawidłowy adres email zawsze ma format: nazwa@domena.pl", "example": "jan.kowalski@gmail.com — to poprawny adres."}],
                "recommendation": "Podaj poprawny adres email.",
                "signals": {}, "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        domain = parts[1].lower()

        # Disposable email check
        disposable_domains = _load_disposable_domains()
        signals["disposable_email"] = domain in disposable_domains

        # MX records
        signals["mx"] = _check_mx(domain)

        # Domain WHOIS
        signals["whois"] = _whois_lookup(domain)

        # URLhaus for domain
        signals["urlhaus"] = _urlhaus_lookup(domain)

        # SPF/DMARC for email domain
        signals["spf_dmarc"] = _check_spf_dmarc(domain)

        risk_score = calculate_risk(signals)
        verdict = generate_verdict(risk_score, signals, email)

        return {
            "query": email,
            "type": "email",
            "domain": domain,
            "risk_score": risk_score,
            "signals": signals,
            **verdict,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


def detect_query_type(query: str) -> str:
    """Auto-detect query type: url, email, or company."""
    q = query.strip()
    if "@" in q:
        return "email"
    if q.startswith("http://") or q.startswith("https://"):
        return "url"
    if "." in q and not " " in q:
        return "url"
    return "company"
