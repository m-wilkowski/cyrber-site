"""
routers/organizations.py

Endpointy dla:
- GET /api/overview — dane strony głównej per organizacja (3 poziomy)
- GET /api/organizations — lista organizacji (tylko operator)
- POST /api/organizations — nowa organizacja (tylko admin/operator)
- GET /api/organizations/{org_id} — szczegóły organizacji
- GET /api/pulse/stream — SSE stream CYRBER PULSE
- GET /api/pulse/events — historia eventów (z paginacją)
- POST /api/pulse/events — dodaj event (internal, z skanerów)
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import json
import asyncio

from modules.database import SessionLocal
from backend.deps import get_current_user, require_role
from modules.organizations import Organization, License, PulseEvent, create_pulse_event

router = APIRouter(prefix='/api', tags=['organizations'])


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================================================================
# SCHEMAS
# =========================================================================

class OrganizationCreate(BaseModel):
    name: str
    domain: Optional[str] = None
    slug: str
    connection_mode: str = 'CONNECTED'
    brand_name: Optional[str] = None
    brand_color: Optional[str] = None
    notes: Optional[str] = None
    llm_mode: str = 'cloud'
    preferred_provider: str = 'anthropic'
    ollama_base_url: Optional[str] = None


class LLMSettingsUpdate(BaseModel):
    llm_mode: str  # cloud / local / airgap
    preferred_provider: str = 'anthropic'
    ollama_base_url: Optional[str] = None


class OrganizationOut(BaseModel):
    id: int
    name: str
    domain: Optional[str]
    slug: str
    connection_mode: str
    brand_name: Optional[str]
    brand_color: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class PulseEventCreate(BaseModel):
    organization_id: int
    head: str  # RATIO / ANIMUS / FATUM / MENS / SYSTEM
    event_type: str
    message_human: str
    severity: str = 'INFO'
    message_technical: Optional[str] = None
    scan_id: Optional[str] = None
    finding_name: Optional[str] = None
    target: Optional[str] = None


# =========================================================================
# OVERVIEW — strona główna per organizacja
# Trzy poziomy: CEO / IT Manager / Operator
# =========================================================================

@router.get('/overview')
async def get_overview(
    org_id: Optional[int] = None,
    current_user=Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    """
    Dane dla /overview — trzy poziomy na jeden request.

    Jeśli user ma organization_id → zwraca jego org.
    Jeśli user is_operator i podał org_id → zwraca wskazaną org.
    Jeśli user is_operator bez org_id → zwraca pierwszą org (redirect do /organizations).
    """
    # Określ która organizacja
    if current_user.get('is_operator'):
        if org_id:
            org = db.query(Organization).filter(Organization.id == org_id).first()
            if not org:
                raise HTTPException(status_code=404, detail='Organization not found')
        else:
            # Operator bez org_id — zwróć listę zamiast overview
            return {'redirect': '/organizations'}
    else:
        # Klient — tylko jego organizacja
        org = db.query(Organization).filter(
            Organization.id == current_user.get('organization_id')
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail='Organization not found')

    # --- POZIOM 1: Security score (dla CEO) ---
    # Pobierz ostatni skan dla tej organizacji
    from modules.database import Scan  # import lokalny żeby nie tworzyć circular
    last_scan = (
        db.query(Scan)
        .filter(Scan.organization_id == org.id)
        .order_by(desc(Scan.created_at))
        .first()
    )

    risk_score = None
    if last_scan and last_scan.risk_level:
        _level_map = {'critical': 90, 'high': 70, 'medium': 50, 'low': 25, 'info': 10}
        risk_score = _level_map.get(last_scan.risk_level.lower(), 0)
    risk_label = _risk_label(risk_score)

    # Predyspozycje (placeholder — będą z SPECULUM Sprint 2)
    predispositions = {
        'ransomware': {'level': 'WYSOKIE', 'score': 75},
        'phishing': {'level': 'ŚREDNIE', 'score': 50},
        'supply_chain': {'level': 'ŚREDNIE', 'score': 45},
    }

    # --- POZIOM 2: Metryki (dla IT Managera) ---
    # Liczba otwartych podatności
    open_findings = _count_open_findings(db, org.id)

    # Compliance (placeholder — będzie z TESTIMONIUM Sprint 3)
    compliance = {
        'NIS2': 'OK',
        'DORA': 'OK',
        'GDPR': 'WARNING',
    }

    # Ostatnia misja
    last_mission_date = last_scan.created_at.strftime('%d.%m') if last_scan else None
    last_mission_findings = last_scan.findings_count if last_scan and hasattr(last_scan, 'findings_count') else 0

    # Status Cerberusa
    cerberus_status = 'AKTYWNY'  # TODO: sprawdź czy Celery worker żyje
    fiducia = risk_score or 0

    # Active license
    active_lic = org.active_license
    package = active_lic.package if active_lic else 'BRAK'

    # --- POZIOM 3: PULSE (dla operatora / informatyka) ---
    recent_events = (
        db.query(PulseEvent)
        .filter(PulseEvent.organization_id == org.id)
        .order_by(desc(PulseEvent.created_at))
        .limit(10)
        .all()
    )

    # Licznik czasu ochrony
    protection_since = org.created_at
    protection_days = (datetime.utcnow() - protection_since).days if protection_since else 0

    is_operator = current_user.get('is_operator', False)

    return {
        'organization': {
            'id': org.id,
            'name': org.name,
            'slug': org.slug,
            'brand_name': org.brand_name or org.name,
            'brand_color': org.brand_color or '#FF6B35',
            'connection_mode': org.connection_mode,
            'package': package,
        },

        # Poziom 1 — CEO
        'security': {
            'score': risk_score,
            'label': risk_label,
            'predispositions': predispositions,
            'last_updated': last_scan.created_at.isoformat() if last_scan else None,
        },

        # Poziom 2 — IT Manager
        'metrics': {
            'open_findings': open_findings,
            'compliance': compliance,
            'last_mission': {
                'date': last_mission_date,
                'findings_count': last_mission_findings,
                'scan_id': last_scan.task_id if last_scan else None,
            },
            'cerberus_status': cerberus_status,
            'fiducia': fiducia,
        },

        # Poziom 3 — PULSE
        'pulse': {
            'protection_days': protection_days,
            'recent_events': [
                e.to_sse_dict(include_technical=is_operator)
                for e in recent_events
            ],
        },
    }


# =========================================================================
# ORGANIZATIONS — lista i CRUD (tylko operator)
# =========================================================================

@router.get('/organizations')
async def list_organizations(
    current_user=Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    """Lista wszystkich organizacji — tylko dla operatorów CYRBER."""
    if not current_user.get('is_operator'):
        if current_user['role'] != 'admin':
            raise HTTPException(status_code=403, detail='Operator access required')

    orgs = db.query(Organization).order_by(Organization.name).all()

    from modules.database import Scan  # local import to avoid circular

    # Dla każdej organizacji dodaj aktywny score z ostatniego skanu
    result = []
    for org in orgs:
        # Security score from latest completed scan
        last_scan = (
            db.query(Scan)
            .filter(Scan.organization_id == org.id, Scan.status == 'completed')
            .order_by(desc(Scan.created_at))
            .first()
        )
        score = None
        if last_scan and last_scan.risk_level:
            _level_map = {'critical': 90, 'high': 70, 'medium': 50, 'low': 25, 'info': 10}
            score = _level_map.get(last_scan.risk_level.lower(), 0)

        org_dict = {
            'id': org.id,
            'name': org.name,
            'domain': org.domain,
            'slug': org.slug,
            'connection_mode': org.connection_mode,
            'brand_name': org.brand_name,
            'brand_color': org.brand_color,
            'is_active': org.is_active,
            'created_at': org.created_at,
            # Rozszerzone dla widoku operatora
            'package': org.active_license.package if org.active_license else None,
            'security_score': score,
            'last_alert': _get_last_alert(db, org.id),
            # LLM settings
            'llm_mode': org.llm_mode,
            'preferred_provider': org.preferred_provider,
            'ollama_base_url': org.ollama_base_url,
        }
        result.append(org_dict)

    return result


@router.post('/organizations', status_code=status.HTTP_201_CREATED)
async def create_organization(
    data: OrganizationCreate,
    current_user=Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    """Nowa organizacja — tylko admin/operator."""
    if not current_user.get('is_operator'):
        if current_user['role'] != 'admin':
            raise HTTPException(status_code=403, detail='Admin or operator required')

    # Sprawdź unikalność slug
    existing = db.query(Organization).filter(Organization.slug == data.slug).first()
    if existing:
        raise HTTPException(status_code=400, detail=f'Slug {data.slug!r} already exists')

    org = Organization(
        name=data.name,
        domain=data.domain,
        slug=data.slug,
        connection_mode=data.connection_mode,
        brand_name=data.brand_name,
        brand_color=data.brand_color,
        notes=data.notes,
        is_active=True,
        llm_mode=data.llm_mode,
        preferred_provider=data.preferred_provider,
        ollama_base_url=data.ollama_base_url,
    )
    db.add(org)
    db.commit()
    db.refresh(org)

    return {'id': org.id, 'slug': org.slug, 'name': org.name}


@router.get('/organizations/{org_id}')
async def get_organization(
    org_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    """Szczegóły organizacji."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail='Not found')

    # Klient może widzieć tylko swoją organizację
    if not current_user.get('is_operator'):
        if current_user['role'] != 'admin':
            if current_user.get('organization_id') != org_id:
                raise HTTPException(status_code=403, detail='Access denied')

    return {
        'id': org.id,
        'name': org.name,
        'domain': org.domain,
        'slug': org.slug,
        'connection_mode': org.connection_mode,
        'brand_name': org.brand_name,
        'brand_color': org.brand_color,
        'is_active': org.is_active,
        'created_at': org.created_at,
        'notes': org.notes,
        'llm_mode': org.llm_mode,
        'preferred_provider': org.preferred_provider,
        'ollama_base_url': org.ollama_base_url,
        'active_license': {
            'package': org.active_license.package,
            'model': org.active_license.model,
            'valid_until': org.active_license.valid_until,
            'max_targets': org.active_license.max_targets,
        } if org.active_license else None,
    }


# =========================================================================
# LLM SETTINGS — per-org LLM configuration
# =========================================================================

@router.patch('/organizations/{org_id}/llm-settings')
async def update_llm_settings(
    org_id: int,
    data: LLMSettingsUpdate,
    current_user=Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    """Update LLM settings for an organization. Admin/operator only."""
    if not current_user.get('is_operator'):
        if current_user['role'] != 'admin':
            raise HTTPException(status_code=403, detail='Admin or operator required')

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail='Organization not found')

    if data.llm_mode not in ('cloud', 'local', 'airgap'):
        raise HTTPException(status_code=400, detail='llm_mode must be cloud, local, or airgap')

    if data.preferred_provider not in ('anthropic', 'openai', 'deepseek'):
        raise HTTPException(status_code=400, detail='preferred_provider must be anthropic, openai, or deepseek')

    org.llm_mode = data.llm_mode
    org.preferred_provider = data.preferred_provider
    org.ollama_base_url = data.ollama_base_url if data.llm_mode in ('local', 'airgap') else None
    db.commit()

    return {
        'id': org.id,
        'llm_mode': org.llm_mode,
        'preferred_provider': org.preferred_provider,
        'ollama_base_url': org.ollama_base_url,
    }


# =========================================================================
# PULSE — SSE stream i historia
# =========================================================================

@router.get('/pulse/stream')
async def pulse_stream(
    org_id: Optional[int] = None,
    current_user=Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    """
    SSE stream CYRBER PULSE.
    Serwuje nowe eventy co 2 sekundy.
    Taka sama technologia jak istniejący COGITATIO stream.
    """
    # Określ org_id
    if current_user.get('is_operator'):
        target_org_id = org_id
    else:
        target_org_id = current_user.get('organization_id')

    is_operator = current_user.get('is_operator', False)

    async def event_generator():
        last_id = 0
        while True:
            # Pobierz nowe eventy od ostatniego id
            query = db.query(PulseEvent).order_by(PulseEvent.id)
            if last_id > 0:
                query = query.filter(PulseEvent.id > last_id)
            if target_org_id:
                query = query.filter(PulseEvent.organization_id == target_org_id)

            events = query.limit(20).all()

            for event in events:
                last_id = event.id
                data = event.to_sse_dict(include_technical=is_operator)
                yield f'data: {json.dumps(data, ensure_ascii=False, default=str)}\n\n'

            if not events:
                # Heartbeat co 15s żeby połączenie nie wygasło
                yield f': heartbeat\n\n'

            await asyncio.sleep(2)

    return StreamingResponse(
        event_generator(),
        media_type='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',  # wyłącz nginx buffering
        }
    )


@router.get('/pulse/events')
async def get_pulse_events(
    org_id: Optional[int] = None,
    severity: Optional[str] = None,
    head: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    current_user=Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    """Historia PULSE eventów z filtrowaniem."""
    if current_user.get('is_operator'):
        target_org_id = org_id
    else:
        target_org_id = current_user.get('organization_id')

    query = db.query(PulseEvent).order_by(desc(PulseEvent.created_at))

    if target_org_id:
        query = query.filter(PulseEvent.organization_id == target_org_id)
    if severity:
        query = query.filter(PulseEvent.severity == severity.upper())
    if head:
        query = query.filter(PulseEvent.head == head.upper())

    total = query.count()
    events = query.offset(offset).limit(min(limit, 200)).all()

    is_operator = current_user.get('is_operator', False)

    return {
        'total': total,
        'events': [e.to_sse_dict(include_technical=is_operator) for e in events],
    }


@router.post('/pulse/events', status_code=status.HTTP_201_CREATED)
async def add_pulse_event(
    data: PulseEventCreate,
    current_user=Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    """
    Dodaj event do PULSE.
    Używane wewnętrznie przez skanery i MENS.
    """
    event = create_pulse_event(
        db=db,
        organization_id=data.organization_id,
        head=data.head,
        event_type=data.event_type,
        message_human=data.message_human,
        severity=data.severity,
        message_technical=data.message_technical,
        scan_id=data.scan_id,
        finding_name=data.finding_name,
        target=data.target,
    )
    return {'id': event.id, 'created_at': event.created_at}


# =========================================================================
# HELPERS
# =========================================================================

def _risk_label(score: Optional[int]) -> str:
    if score is None:
        return 'NIEZNANE'
    if score >= 80:
        return 'KRYTYCZNE'
    if score >= 60:
        return 'PODWYŻSZONE RYZYKO'
    if score >= 40:
        return 'UMIARKOWANE'
    return 'NISKIE'


def _count_open_findings(db: Session, org_id: int) -> dict:
    """Zlicz otwarte findings per severity dla organizacji."""
    # Placeholder — w pełnej implementacji query przez scans → findings
    return {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
    }


def _get_last_alert(db: Session, org_id: int) -> Optional[dict]:
    """Pobierz ostatni CRITICAL/HIGH event dla organizacji (dla widoku operatora)."""
    event = (
        db.query(PulseEvent)
        .filter(
            PulseEvent.organization_id == org_id,
            PulseEvent.severity.in_(['CRITICAL', 'HIGH'])
        )
        .order_by(desc(PulseEvent.created_at))
        .first()
    )
    if not event:
        return None
    return {
        'severity': event.severity,
        'message': event.message_human,
        'created_at': event.created_at.isoformat(),
    }
