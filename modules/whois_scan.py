import re
import socket
from datetime import datetime, timezone

PRIVACY_KEYWORDS = [
    "privacy", "redacted", "data protected", "whoisguard", "domains by proxy",
    "contact privacy", "withheld", "gdpr", "not disclosed", "identity protect",
    "whois privacy", "private registration", "domain protection",
]


def _is_ip(target: str) -> bool:
    """Check if target is an IP address."""
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


def _clean_target(target: str) -> str:
    """Strip protocol, path, port from target."""
    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    return host.strip().lower()


def _to_str(val):
    """Convert whois value to string, handling lists and datetimes."""
    if val is None:
        return ""
    if isinstance(val, list):
        return str(val[0]) if val else ""
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


def _to_date(val):
    """Extract first datetime from whois value."""
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str) and val:
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    return None


def _check_privacy(data: dict) -> bool:
    """Check if WHOIS data indicates privacy protection."""
    check_fields = ["org", "name", "registrant", "email", "registrant_name"]
    for field in check_fields:
        val = str(data.get(field, "") or "").lower()
        for kw in PRIVACY_KEYWORDS:
            if kw in val:
                return True
    return False


def _whois_domain(host: str) -> dict:
    """Lookup WHOIS for a domain."""
    import whois

    try:
        w = whois.whois(host)
    except whois.parser.PywhoisError:
        return {"error": f"Domain not found: {host}"}
    except Exception as e:
        return {"error": str(e)}

    if not w or not w.domain_name:
        return {"error": f"No WHOIS data for {host}"}

    raw = w.__dict__ if hasattr(w, '__dict__') else {}

    domain_name = _to_str(w.domain_name)
    registrar = _to_str(w.registrar)

    reg_date = _to_date(w.creation_date)
    exp_date = _to_date(w.expiration_date)
    upd_date = _to_date(w.updated_date)

    # Name servers
    ns = w.name_servers or []
    if isinstance(ns, str):
        ns = [ns]
    name_servers = sorted(set(s.lower() for s in ns if s))

    # Status
    status = w.status or []
    if isinstance(status, str):
        status = [status]

    # Registrant info
    registrant = {}
    registrant_name = _to_str(getattr(w, 'name', None) or raw.get('registrant_name'))
    registrant_org = _to_str(w.org)
    registrant_country = _to_str(w.country)
    registrant_email = ""
    emails = w.emails
    if emails:
        if isinstance(emails, list):
            registrant_email = emails[0]
        else:
            registrant_email = str(emails)
    if registrant_name:
        registrant["name"] = registrant_name
    if registrant_org:
        registrant["organization"] = registrant_org
    if registrant_country:
        registrant["country"] = registrant_country
    if registrant_email:
        registrant["email"] = registrant_email

    # Days until expiry
    days_until_expiry = None
    is_expired = False
    soon_expiring = False
    if exp_date:
        now = datetime.now(timezone.utc) if exp_date.tzinfo else datetime.now()
        delta = exp_date - now
        days_until_expiry = delta.days
        is_expired = days_until_expiry < 0
        soon_expiring = 0 <= days_until_expiry < 30

    privacy_protected = _check_privacy(raw)

    return {
        "type": "domain",
        "target": host,
        "domain_name": domain_name,
        "registrar": registrar,
        "registration_date": reg_date.isoformat() if reg_date else "",
        "expiration_date": exp_date.isoformat() if exp_date else "",
        "last_updated": upd_date.isoformat() if upd_date else "",
        "status": status,
        "name_servers": name_servers,
        "registrant": registrant,
        "days_until_expiry": days_until_expiry,
        "is_expired": is_expired,
        "soon_expiring": soon_expiring,
        "privacy_protected": privacy_protected,
    }


def _whois_ip(ip: str) -> dict:
    """Lookup WHOIS for an IP address."""
    from ipwhois import IPWhois
    from ipwhois.exceptions import IPDefinedError

    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(asn_methods=["dns", "whois", "http"], depth=1)
    except IPDefinedError:
        return {"error": f"Private/reserved IP: {ip}"}
    except Exception as e:
        return {"error": str(e)}

    asn = result.get("asn", "")
    asn_registry = result.get("asn_registry", "")
    asn_country = result.get("asn_country_code", "")
    asn_desc = result.get("asn_description", "")

    network = result.get("network", {}) or {}
    net_cidr = ""
    net_name = network.get("name", "")
    net_desc = ""

    # Extract CIDR
    links = network.get("links", [])
    cidrs = network.get("cidr", "")
    if cidrs:
        net_cidr = cidrs if isinstance(cidrs, str) else str(cidrs)

    # Description from remarks
    remarks = network.get("remarks", []) or []
    for r in remarks:
        desc_val = r.get("description", "")
        if desc_val:
            net_desc = desc_val
            break

    return {
        "type": "ip",
        "target": ip,
        "asn": asn,
        "asn_registry": asn_registry,
        "asn_country_code": asn_country,
        "asn_description": asn_desc,
        "network": {
            "cidr": net_cidr,
            "name": net_name,
            "description": net_desc,
        },
    }


def whois_scan(target: str) -> dict:
    """Perform WHOIS lookup for domain or IP.

    Args:
        target: Domain name or IP address.

    Returns:
        Dict with WHOIS data.
    """
    host = _clean_target(target)
    if not host:
        return {"error": "Empty target"}

    try:
        if _is_ip(host):
            return _whois_ip(host)
        else:
            return _whois_domain(host)
    except Exception as e:
        return {"error": str(e)}
