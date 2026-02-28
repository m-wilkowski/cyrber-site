"""Compliance status dashboard — NIS2, DORA, GDPR assessment from scan findings."""

from fastapi import APIRouter, Depends, Query
from datetime import datetime, timezone, timedelta
import json

from backend.deps import get_current_user
from modules.database import SessionLocal, Scan
from backend.routers.findings import _extract_findings

router = APIRouter(prefix="/api/compliance", tags=["compliance"])

# ── Requirements definitions ─────────────────────────────────────

_NIS2_REQUIREMENTS = [
    {
        "id": "nis2-art21-risk",
        "article": "Art. 21(2)(a)",
        "name": "Risk management",
        "description": "Polityki analizy ryzyka i bezpieczenstwa systemow informacyjnych",
        "keywords": ["open port", "unnecessary", "smb", "dns", "misconfiguration"],
    },
    {
        "id": "nis2-art21-incident",
        "article": "Art. 21(2)(b)",
        "name": "Incident response",
        "description": "Obsluga incydentow — procedury wykrywania, analizy i reagowania",
        "keywords": [],
    },
    {
        "id": "nis2-art21-continuity",
        "article": "Art. 21(2)(c)",
        "name": "Business continuity",
        "description": "Ciaglosc dzialania, zarzadzanie kopiami zapasowymi, odtwarzanie po awarii",
        "keywords": ["backup", ".bak", ".old"],
    },
    {
        "id": "nis2-art21-supply",
        "article": "Art. 21(2)(d)",
        "name": "Supply chain security",
        "description": "Bezpieczenstwo lancucha dostaw — weryfikacja dostawcow i partnerow",
        "keywords": ["supply chain", "dependency", "outdated", "eol"],
    },
    {
        "id": "nis2-art21-dev",
        "article": "Art. 21(2)(e)",
        "name": "Secure development",
        "description": "Bezpieczenstwo w pozyskiwaniu, rozwijaniu i utrzymywaniu sieci i systemow",
        "keywords": ["sql injection", "xss", "command injection", "path traversal", "ssrf", "rce", "missing header", "cve-"],
    },
    {
        "id": "nis2-art21-assess",
        "article": "Art. 21(2)(f)",
        "name": "Effectiveness assessment",
        "description": "Polityki i procedury oceny skutecznosci srodkow zarzadzania ryzykiem",
        "keywords": [],
    },
    {
        "id": "nis2-art21-hygiene",
        "article": "Art. 21(2)(g)",
        "name": "Cyber hygiene & training",
        "description": "Podstawowe praktyki cyberhigieny i szkolenia w zakresie cyberbezpieczenstwa",
        "keywords": ["phishing", "social engineering"],
    },
    {
        "id": "nis2-art21-crypto",
        "article": "Art. 21(2)(h)",
        "name": "Cryptography",
        "description": "Polityki stosowania kryptografii i szyfrowania",
        "keywords": ["ssl", "tls", "cipher", "certificate", "poodle", "beast", "heartbleed", "weak crypto"],
    },
    {
        "id": "nis2-art21-access",
        "article": "Art. 21(2)(i)",
        "name": "Access control",
        "description": "Bezpieczenstwo zasobow ludzkich, kontrola dostepu i zarzadzanie aktywami",
        "keywords": ["default cred", "weak password", "authentication bypass", "broken auth", "brute force"],
    },
    {
        "id": "nis2-art21-mfa",
        "article": "Art. 21(2)(j)",
        "name": "Multi-factor authentication",
        "description": "Stosowanie uwierzytelniania wieloskladnikowego lub ciaglego",
        "keywords": [],
    },
    {
        "id": "nis2-art23-reporting",
        "article": "Art. 23",
        "name": "Incident reporting",
        "description": "Obowiazki w zakresie raportowania incydentow — early warning 24h, notification 72h",
        "keywords": [],
    },
]

_DORA_REQUIREMENTS = [
    {
        "id": "dora-art5-governance",
        "article": "Art. 5",
        "name": "ICT governance",
        "description": "Ramy zarzadzania ryzykiem ICT i nadzoru nad nim",
        "keywords": [],
    },
    {
        "id": "dora-art6-risk",
        "article": "Art. 6",
        "name": "ICT risk management",
        "description": "Identyfikacja, ochrona, wykrywanie i reagowanie na ryzyko ICT",
        "keywords": ["open port", "smb", "dns", "misconfiguration", "unnecessary"],
    },
    {
        "id": "dora-art7-systems",
        "article": "Art. 7",
        "name": "ICT systems & tools",
        "description": "Identyfikacja i klasyfikacja funkcji i zasobow ICT",
        "keywords": [],
    },
    {
        "id": "dora-art8-protection",
        "article": "Art. 8",
        "name": "Protection & prevention",
        "description": "Srodki ochrony i zapobiegania — patching, crypto, kontrola dostepu",
        "keywords": ["sql injection", "xss", "rce", "command injection", "ssl", "tls", "cipher", "default cred", "weak password", "cve-"],
    },
    {
        "id": "dora-art9-detection",
        "article": "Art. 9",
        "name": "Detection",
        "description": "Mechanizmy wykrywania anomalii i incydentow ICT",
        "keywords": [],
    },
    {
        "id": "dora-art10-response",
        "article": "Art. 10",
        "name": "Response & recovery",
        "description": "Planowanie reagowania i odtwarzania po incydentach ICT",
        "keywords": ["backup", ".bak"],
    },
    {
        "id": "dora-art11-backup",
        "article": "Art. 11",
        "name": "Backup policies",
        "description": "Polityki tworzenia kopii zapasowych i procedury odtwarzania",
        "keywords": ["backup"],
    },
    {
        "id": "dora-art13-testing",
        "article": "Art. 13",
        "name": "Digital resilience testing",
        "description": "Testowanie cyfrowej odpornosci operacyjnej — TLPT, pentesty",
        "keywords": [],
    },
    {
        "id": "dora-art28-tpp",
        "article": "Art. 28",
        "name": "Third-party risk",
        "description": "Zarzadzanie ryzykiem zwiazanym z zewnetrznymi dostawcami uslug ICT",
        "keywords": ["supply chain", "dependency", "outdated"],
    },
]

_GDPR_REQUIREMENTS = [
    {
        "id": "gdpr-art5-principles",
        "article": "Art. 5",
        "name": "Processing principles",
        "description": "Zasady przetwarzania danych osobowych — zgodnosc z prawem, minimalizacja, integralnosc",
        "keywords": [],
    },
    {
        "id": "gdpr-art25-design",
        "article": "Art. 25",
        "name": "Data protection by design",
        "description": "Ochrona danych w fazie projektowania i domyslna ochrona danych",
        "keywords": ["information disclosure", "info leak", "data exposure"],
    },
    {
        "id": "gdpr-art32-security",
        "article": "Art. 32",
        "name": "Security of processing",
        "description": "Bezpieczenstwo przetwarzania — szyfrowanie, integralnosc, dostepnosc, testowanie",
        "keywords": ["sql injection", "xss", "ssl", "tls", "cipher", "default cred", "weak password", "cve-"],
    },
    {
        "id": "gdpr-art33-breach",
        "article": "Art. 33",
        "name": "Breach notification",
        "description": "Zglaszanie naruszen ochrony danych — 72h do organu nadzorczego",
        "keywords": [],
    },
    {
        "id": "gdpr-art35-dpia",
        "article": "Art. 35",
        "name": "DPIA",
        "description": "Ocena skutkow dla ochrony danych (Data Protection Impact Assessment)",
        "keywords": [],
    },
]


def _match_findings_to_requirement(req: dict, findings: list) -> list:
    """Return findings matching a requirement's keywords."""
    keywords = req.get("keywords", [])
    if not keywords:
        return []
    matched = []
    for f in findings:
        name_lower = (f.get("name") or "").lower()
        desc_lower = (f.get("description") or "").lower()
        for kw in keywords:
            if kw in name_lower or kw in desc_lower:
                matched.append(f)
                break
    return matched


def _compute_framework_status(critical: int, high: int) -> str:
    if critical == 0 and high == 0:
        return "OK"
    if critical <= 3:
        return "WARNING"
    return "FAIL"


def _compute_coverage(requirements: list, all_findings: list) -> float:
    if not requirements:
        return 100.0
    ok_count = 0
    for req in requirements:
        matched = _match_findings_to_requirement(req, all_findings)
        critical_matched = [f for f in matched if f.get("severity") == "CRITICAL"]
        if len(critical_matched) == 0:
            ok_count += 1
    return round(ok_count / len(requirements) * 100, 1)


def _build_requirements_status(requirements: list, all_findings: list) -> list:
    result = []
    for req in requirements:
        matched = _match_findings_to_requirement(req, all_findings)
        critical_count = sum(1 for f in matched if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in matched if f.get("severity") == "HIGH")

        if not req.get("keywords"):
            status = "OK"
        elif critical_count > 0:
            status = "FAIL"
        elif high_count > 0:
            status = "WARNING"
        elif len(matched) > 0:
            status = "WARNING"
        else:
            status = "OK"

        last_verified = ""
        if matched:
            dates = [f.get("created_at", "") for f in matched if f.get("created_at")]
            if dates:
                last_verified = max(dates)[:10]

        result.append({
            "id": req["id"],
            "article": req["article"],
            "name": req["name"],
            "description": req["description"],
            "status": status,
            "findings_count": len(matched),
            "critical_count": critical_count,
            "high_count": high_count,
            "last_verified": last_verified,
        })
    return result


def _get_recent_findings(days: int = 30) -> tuple:
    """Return (all_findings, recent_scans) from last N days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    db = SessionLocal()
    try:
        rows = (
            db.query(Scan.id, Scan.task_id, Scan.target, Scan.raw_data, Scan.created_at)
            .filter(Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .all()
        )
    finally:
        db.close()

    all_findings = []
    recent_scans = []
    for row in rows:
        if not row.raw_data:
            continue
        try:
            raw = json.loads(row.raw_data) if isinstance(row.raw_data, str) else row.raw_data
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(raw, dict):
            continue

        findings = _extract_findings(raw, row.target, row.task_id, row.created_at, row.id)

        is_recent = row.created_at and row.created_at.replace(tzinfo=timezone.utc) >= cutoff
        if is_recent:
            all_findings.extend(findings)
            recent_scans.append({
                "task_id": row.task_id,
                "target": row.target,
                "created_at": str(row.created_at)[:19] if row.created_at else "",
                "findings_count": len(findings),
            })

    return all_findings, recent_scans


@router.get("/status")
async def compliance_status(
    days: int = Query(30, ge=1, le=365),
    _user=Depends(get_current_user),
):
    all_findings, recent_scans = _get_recent_findings(days)

    critical_count = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")

    # NIS2
    nis2_status = _compute_framework_status(critical_count, high_count)
    nis2_coverage = _compute_coverage(_NIS2_REQUIREMENTS, all_findings)
    nis2_requirements = _build_requirements_status(_NIS2_REQUIREMENTS, all_findings)

    # DORA
    dora_status = _compute_framework_status(critical_count, high_count)
    dora_coverage = _compute_coverage(_DORA_REQUIREMENTS, all_findings)
    dora_requirements = _build_requirements_status(_DORA_REQUIREMENTS, all_findings)

    # GDPR — always WARNING (cannot fully verify without personal data inventory)
    gdpr_coverage = _compute_coverage(_GDPR_REQUIREMENTS, all_findings)
    gdpr_requirements = _build_requirements_status(_GDPR_REQUIREMENTS, all_findings)
    gdpr_has_fail = any(r["status"] == "FAIL" for r in gdpr_requirements)
    gdpr_status = "FAIL" if gdpr_has_fail else "WARNING"

    return {
        "period_days": days,
        "total_findings": len(all_findings),
        "critical_count": critical_count,
        "high_count": high_count,
        "frameworks": {
            "nis2": {
                "name": "NIS2",
                "full_name": "Network and Information Security Directive 2",
                "status": nis2_status,
                "coverage": nis2_coverage,
                "requirements": nis2_requirements,
            },
            "dora": {
                "name": "DORA",
                "full_name": "Digital Operational Resilience Act",
                "status": dora_status,
                "coverage": dora_coverage,
                "requirements": dora_requirements,
            },
            "gdpr": {
                "name": "GDPR",
                "full_name": "General Data Protection Regulation",
                "status": gdpr_status,
                "coverage": gdpr_coverage,
                "requirements": gdpr_requirements,
            },
        },
        "evidence_scans": recent_scans[:10],
    }
