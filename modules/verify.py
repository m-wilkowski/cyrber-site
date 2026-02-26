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
    """Calculate risk score (0-100) from aggregated signals."""
    score = 0

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
    if vt.get("positives", 0) >= 3:
        score += 60
    elif vt.get("positives", 0) >= 1:
        score += 30

    # URLhaus
    urlhaus = signals.get("urlhaus", {})
    if urlhaus.get("blacklisted"):
        score += 50
    elif urlhaus.get("urls_count", 0) > 0:
        score += 25

    # GreyNoise
    gn = signals.get("greynoise", {})
    if gn.get("classification") == "malicious":
        score += 30

    # Company registry
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

    return min(100, score)


# ═══════════════════════════════════════════════════════════════
#  AI VERDICT
# ═══════════════════════════════════════════════════════════════

def generate_verdict(risk_score: int, signals: dict, query: str) -> dict:
    """Generate AI verdict using Claude Haiku."""
    # Determine base verdict from score
    if risk_score < 30:
        base_verdict = "BEZPIECZNE"
    elif risk_score <= 60:
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
            f"Jesteś ekspertem ds. cyberbezpieczeństwa i wykrywania oszustw. "
            f"Przeanalizuj poniższe sygnały dla zapytania: {query}\n\n"
            f"Risk score: {risk_score}/100\n"
            f"Sygnały:\n{signals_summary}\n\n"
            f"Odpowiedz WYŁĄCZNIE w formacie JSON (bez markdown):\n"
            f'{{"verdict": "{base_verdict}", '
            f'"summary": "Krótkie podsumowanie po polsku (2-3 zdania)", '
            f'"red_flags": ["lista konkretnych czerwonych flag po polsku"], '
            f'"recommendation": "Rekomendacja działania po polsku (1-2 zdania)"}}'
        )

        response_text = provider.chat(prompt, max_tokens=800)
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
        return result

    except Exception as exc:
        log.warning(f"AI verdict generation failed: {exc}")
        return {
            "verdict": base_verdict,
            "summary": f"Analiza automatyczna wykazała risk score {risk_score}/100.",
            "red_flags": _extract_red_flags(signals),
            "recommendation": "Zalecamy ostrożność." if risk_score >= 30 else "Brak podejrzanych sygnałów.",
        }


def _extract_red_flags(signals: dict) -> list[str]:
    """Extract human-readable red flags from signals."""
    flags = []
    whois = signals.get("whois", {})
    age = whois.get("age_days")
    if age is not None and age < 90:
        flags.append(f"Domena zarejestrowana {age} dni temu (bardzo nowa)")
    elif age is not None and age < 365:
        flags.append(f"Domena zarejestrowana {age} dni temu (stosunkowo nowa)")
    if whois.get("available"):
        flags.append("Domena wygląda na niezarejestrowaną")

    gsb = signals.get("google_safe_browsing", {})
    if gsb.get("flagged"):
        flags.append(f"Google Safe Browsing: {', '.join(gsb.get('threats', []))}")

    vt = signals.get("virustotal", {})
    if vt.get("positives", 0) > 0:
        flags.append(f"VirusTotal: {vt['positives']}/{vt.get('total', 0)} silników oznaczyło jako złośliwe")

    urlhaus = signals.get("urlhaus", {})
    if urlhaus.get("blacklisted"):
        flags.append("URLhaus: domena na czarnej liście")
    elif urlhaus.get("urls_count", 0) > 0:
        flags.append(f"URLhaus: {urlhaus['urls_count']} podejrzanych URL-i")

    gn = signals.get("greynoise", {})
    if gn.get("classification") == "malicious":
        flags.append("GreyNoise: IP oznaczone jako złośliwe")

    company = signals.get("company", {})
    if company and not company.get("found", True):
        flags.append("Firma nie znaleziona w rejestrze")

    if signals.get("disposable_email"):
        flags.append("Domena email jednorazowego użytku (disposable)")

    mx = signals.get("mx", {})
    if mx and not mx.get("has_mx", True):
        flags.append("Brak rekordów MX (domena nie obsługuje poczty)")

    wb = signals.get("wayback", {})
    if wb.get("archive_age_days") is not None and wb["archive_age_days"] < 180:
        flags.append(f"Strona w archiwum internetowym od {wb['archive_age_days']} dni")

    return flags


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
                "red_flags": ["Nieprawidłowy format email"],
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
