"""
models/organizations.py

ORM modele dla multi-tenancy CYRBER:
- Organization — jeden klient / jedna firma monitorowana
- License — licencja per organizacja (pakiet, model, daty)
- PulseEvent — CYRBER PULSE live activity stream
"""

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text,
    ForeignKey, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from modules.database import Base


class Organization(Base):
    __tablename__ = 'organizations'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=True)
    slug = Column(String(100), nullable=False, unique=True)  # URL-safe ID

    # White-label branding (foundation — pełne UI w późniejszej fazie)
    brand_name = Column(String(255), nullable=True)
    brand_logo_url = Column(String(500), nullable=True)
    brand_color = Column(String(7), nullable=True)  # hex np. #FF6B35

    # Tryb połączenia — wpływa na cennik (+15% SCHEDULED, +30% AIRGAP)
    connection_mode = Column(String(20), nullable=False, default='CONNECTED')
    # Wartości: CONNECTED / SCHEDULED / AIRGAP

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(),
                        onupdate=func.now())
    is_active = Column(Boolean, nullable=False, default=True)
    notes = Column(Text, nullable=True)

    # Relacje
    licenses = relationship('License', back_populates='organization',
                            cascade='all, delete-orphan')
    pulse_events = relationship('PulseEvent', back_populates='organization',
                                cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Organization {self.slug} ({self.connection_mode})>'

    @property
    def active_license(self):
        """Zwraca aktywną licencję lub None."""
        from datetime import datetime
        for lic in self.licenses:
            if lic.is_active:
                if lic.valid_until is None or lic.valid_until > datetime.utcnow():
                    return lic
        return None

    @property
    def security_score(self):
        """Placeholder — będzie wyliczany z ostatniego skanu."""
        return None


class License(Base):
    __tablename__ = 'licenses'

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey('organizations.id', ondelete='CASCADE'),
                             nullable=False)

    # Pakiet — SPECULATOR/EXCUBITOR/HARUSPEX/PRAEFECTUS
    package = Column(String(50), nullable=False)

    # Model — subscription / perpetual
    model = Column(String(20), nullable=False, default='subscription')

    # Daty
    valid_from = Column(DateTime(timezone=True), nullable=False,
                        server_default=func.now())
    valid_until = Column(DateTime(timezone=True), nullable=True)
    # NULL = bezterminowy (perpetual bez daty końca)
    maintenance_until = Column(DateTime(timezone=True), nullable=True)
    # Dla perpetual — bez aktywnego maintenance intel sync zatrzymuje się po 30d

    # Limity z pakietu
    max_targets = Column(Integer, nullable=False, default=50)
    # SPECULATOR=50, EXCUBITOR=250, HARUSPEX=1000, PRAEFECTUS=9999

    intel_sync_enabled = Column(Boolean, nullable=False, default=True)
    # False gdy maintenance wygasł (perpetual) lub subskrypcja nieaktywna

    # HMAC-SHA256 podpis (weryfikowany przez cyrber-install.sh przy starcie)
    license_key = Column(Text, nullable=True)
    license_signature = Column(String(64), nullable=True)

    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(),
                        onupdate=func.now())

    # Relacje
    organization = relationship('Organization', back_populates='licenses')

    def __repr__(self):
        return f'<License {self.package} org={self.organization_id}>'

    @property
    def is_valid(self):
        """Sprawdza czy licencja jest aktywna i nieprzeterminowana."""
        from datetime import datetime
        if not self.is_active:
            return False
        if self.valid_until and self.valid_until < datetime.utcnow():
            return False
        return True

    @property
    def maintenance_active(self):
        """Dla perpetual — czy maintenance jest aktywny."""
        from datetime import datetime
        if self.model != 'perpetual':
            return True  # subscription zawsze ma maintenance
        if not self.maintenance_until:
            return False
        return self.maintenance_until > datetime.utcnow()

    @property
    def package_limits(self):
        """Zwraca limity dla pakietu."""
        limits = {
            'SPECULATOR': {'max_targets': 50, 'celery_concurrency': 4},
            'EXCUBITOR': {'max_targets': 250, 'celery_concurrency': 8},
            'HARUSPEX': {'max_targets': 1000, 'celery_concurrency': 16},
            'PRAEFECTUS': {'max_targets': 9999, 'celery_concurrency': 32},
        }
        return limits.get(self.package, limits['SPECULATOR'])


class PulseEvent(Base):
    """
    CYRBER PULSE — live activity stream.

    Każde zdarzenie w systemie tworzy rekord.
    SSE endpoint serwuje strumień per organization_id.

    Dwie warstwy treści (zgodnie z Vision v4):
    - message_human: dla klienta, ludzki język, bez IP/CVE
    - message_technical: dla operatora, surowe dane (IP, CVE, komendy)
    """
    __tablename__ = 'pulse_events'

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey('organizations.id', ondelete='CASCADE'),
                             nullable=False)

    # Która głowa Cerberusa generuje event
    head = Column(String(10), nullable=False)
    # RATIO / ANIMUS / FATUM / MENS / SYSTEM

    severity = Column(String(10), nullable=False, default='INFO')
    # CRITICAL / HIGH / MEDIUM / LOW / INFO

    event_type = Column(String(50), nullable=False)
    # scan_started / finding_detected / mission_step /
    # intel_updated / retest_done / hw_connected / etc.

    # Treść — dwa poziomy
    message_human = Column(Text, nullable=False)
    # "Wykryto podatny serwer Apache — ryzyko KRYTYCZNE"

    message_technical = Column(Text, nullable=True)
    # "RATIO → nmap -sV 192.168.1.47 → Apache/2.4.25 CVE-2021-41773 EPSS:0.97"

    # Powiązania (opcjonalne)
    scan_id = Column(String(100), nullable=True)
    finding_name = Column(String(255), nullable=True)
    target = Column(String(255), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relacje
    organization = relationship('Organization', back_populates='pulse_events')

    def __repr__(self):
        return f'<PulseEvent [{self.head}] {self.event_type} org={self.organization_id}>'

    def to_sse_dict(self, include_technical=False):
        """
        Serializacja do SSE event.
        include_technical=True dla operatorów CYRBER.
        """
        data = {
            'id': self.id,
            'head': self.head,
            'severity': self.severity,
            'event_type': self.event_type,
            'message': self.message_human,
            'target': self.target,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
        if include_technical and self.message_technical:
            data['message_technical'] = self.message_technical
        if self.scan_id:
            data['scan_id'] = self.scan_id
        if self.finding_name:
            data['finding_name'] = self.finding_name
        return data


# =========================================================================
# Helper — tworzenie PulseEvent z jednej linii
# =========================================================================

def create_pulse_event(
    db,
    organization_id: int,
    head: str,
    event_type: str,
    message_human: str,
    severity: str = 'INFO',
    message_technical: str = None,
    scan_id: str = None,
    finding_name: str = None,
    target: str = None,
) -> PulseEvent:
    """
    Helper do tworzenia PULSE eventów z jednej linii kodu.

    Użycie w skanerach:
        from models.organizations import create_pulse_event
        create_pulse_event(
            db, org_id,
            head='RATIO',
            event_type='finding_detected',
            message_human='Wykryto podatny serwer Apache',
            severity='CRITICAL',
            message_technical=f'nuclei CVE-2021-41773 → {target}',
            scan_id=task_id,
            finding_name='CVE-2021-41773',
            target=target,
        )
    """
    event = PulseEvent(
        organization_id=organization_id,
        head=head,
        event_type=event_type,
        message_human=message_human,
        severity=severity,
        message_technical=message_technical,
        scan_id=scan_id,
        finding_name=finding_name,
        target=target,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


# =========================================================================
# Indeksy (definiowane tutaj jako backup — główne w migracji)
# =========================================================================

Index('ix_pulse_events_org_created', PulseEvent.organization_id, PulseEvent.created_at)
Index('ix_pulse_events_severity', PulseEvent.severity)
Index('ix_licenses_org_active', License.organization_id, License.is_active)
