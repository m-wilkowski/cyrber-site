PROFILES = {
    "SZCZENIAK": {
        "name": "Szczeniak",
        "price": "€4,000",
        "description": "Podstawowy rekonesans i web scanning",
        "time_estimate": "~30 min",
        "modules": [
            "nmap", "whatweb", "testssl", "sslyze",
            "nuclei", "gobuster", "sqlmap", "wapiti",
            "subfinder", "dnsx", "whois", "searchsploit"
        ]
    },
    "STRAZNIK": {
        "name": "Straznik",
        "price": "€7,500",
        "description": "Pelny pentest sieci i aplikacji webowych",
        "time_estimate": "~2h",
        "modules": [
            "naabu", "masscan", "httpx", "katana",
            "amass", "fierce", "netdiscover", "arpscan",
            "fping", "traceroute", "nbtscan", "snmpwalk",
            "onesixtyone", "netexec", "enum4linux", "smbmap",
            "zap", "droopescan", "wpscan", "joomscan",
            "cmsmap", "retirejs"
        ]
    },
    "CERBER": {
        "name": "Cerber",
        "price": "€15,000+",
        "description": "Pelny red team - AD, exploitation, hardware",
        "time_estimate": "~4h+",
        "modules": [
            "bloodhound", "impacket", "certipy",
            "responder", "ikescan", "nikto"
        ]
    },
    "CI": {
        "name": "CI",
        "price": "—",
        "description": "Fast CI/CD pipeline scan — no AI, ~3 min",
        "time_estimate": "~3 min",
        "modules": [
            "nmap", "nuclei", "whatweb", "gobuster", "testssl", "zap"
        ]
    },
}

_HIERARCHY = ["SZCZENIAK", "STRAZNIK", "CERBER"]


def get_profile(name: str) -> dict | None:
    return PROFILES.get(name.upper())


def get_all_modules(profile_name: str) -> set:
    profile_name = profile_name.upper()
    if profile_name not in PROFILES:
        return set()
    # CI is standalone — not part of the tier hierarchy
    if profile_name == "CI":
        return set(PROFILES["CI"]["modules"])
    idx = _HIERARCHY.index(profile_name)
    modules = set()
    for level in _HIERARCHY[:idx + 1]:
        modules.update(PROFILES[level]["modules"])
    return modules


def get_profiles_list() -> list:
    result = []
    for key in _HIERARCHY:
        p = PROFILES[key]
        result.append({
            "key": key,
            "name": p["name"],
            "price": p["price"],
            "description": p["description"],
            "time_estimate": p["time_estimate"],
            "modules": sorted(get_all_modules(key)),
            "module_count": len(get_all_modules(key)),
        })
    return result


def should_run_module(module_name: str, profile: str) -> bool:
    return module_name in get_all_modules(profile)
