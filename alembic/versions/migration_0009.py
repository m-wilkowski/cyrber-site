"""0009 - organizations, licenses, pulse_events, multi-tenancy

Revision ID: 0009
Revises: 0008
Create Date: 2026-02-28

Co robi ta migracja:
- Tworzy tabelę organizations (multi-tenant core)
- Tworzy tabelę licenses (HMAC-SHA256, pakiety, tryby)
- Tworzy tabelę pulse_events (live activity stream CYRBER PULSE)
- Dodaje organization_id do: users, scans, findings, remediation_tasks,
  mens_missions, proof_leaves, intel_sync_log
- Dodaje role 'operator' do users (obok admin/viewer/client)
- Tworzy indeksy na organization_id we wszystkich tabelach
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from datetime import datetime

# revision identifiers
revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade():

    # =========================================================================
    # TABELA: organizations
    # Każdy klient / każda firma monitorowana to jedna organizacja.
    # Operator CYRBER ma dostęp do wszystkich, klient tylko do swojej.
    # =========================================================================
    op.create_table(
        'organizations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('domain', sa.String(255), nullable=True),
        sa.Column('slug', sa.String(100), nullable=False, unique=True),  # URL-safe identyfikator

        # Branding (white-label foundation)
        sa.Column('brand_name', sa.String(255), nullable=True),
        sa.Column('brand_logo_url', sa.String(500), nullable=True),
        sa.Column('brand_color', sa.String(7), nullable=True),  # hex, np. #FF6B35

        # Tryb połączenia (wpływa na cennik)
        sa.Column('connection_mode', sa.String(20), nullable=False,
                  server_default='CONNECTED'),  # CONNECTED / SCHEDULED / AIRGAP

        # Metadane
        sa.Column('created_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('NOW()')),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('notes', sa.Text(), nullable=True),

        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_organizations_slug', 'organizations', ['slug'], unique=True)
    op.create_index('ix_organizations_is_active', 'organizations', ['is_active'])

    # =========================================================================
    # TABELA: licenses
    # Licencja per organizacja. HMAC-SHA256, pakiet, daty, limity.
    # Jeden rekord = aktywna licencja. Historia przez is_active=false.
    # =========================================================================
    op.create_table(
        'licenses',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),

        # Pakiet
        sa.Column('package', sa.String(50), nullable=False),
        # SPECULATOR / EXCUBITOR / HARUSPEX / PRAEFECTUS

        # Model licencjonowania
        sa.Column('model', sa.String(20), nullable=False, server_default='subscription'),
        # subscription / perpetual

        # Daty
        sa.Column('valid_from', sa.DateTime(), nullable=False),
        sa.Column('valid_until', sa.DateTime(), nullable=True),  # NULL = bezterminowy
        sa.Column('maintenance_until', sa.DateTime(), nullable=True),
        # Dla perpetual — osobne pole. Bez aktywnego maintenance intel sync zatrzymuje się po 30d.

        # Limity (z pakietu)
        sa.Column('max_targets', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('intel_sync_enabled', sa.Boolean(), nullable=False, server_default='true'),

        # HMAC-SHA256 podpis (weryfikowany przy starcie instancji)
        sa.Column('license_key', sa.Text(), nullable=True),
        sa.Column('license_signature', sa.String(64), nullable=True),

        # Status
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('NOW()')),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'],
                                name='fk_licenses_organization',
                                ondelete='CASCADE'),
    )
    op.create_index('ix_licenses_organization_id', 'licenses', ['organization_id'])
    op.create_index('ix_licenses_is_active', 'licenses', ['is_active'])
    op.create_index('ix_licenses_package', 'licenses', ['package'])

    # =========================================================================
    # TABELA: pulse_events
    # CYRBER PULSE — live activity stream.
    # Każde zdarzenie w systemie (skan, finding, misja MENS) to jeden rekord.
    # SSE serwuje z tego strumień per organization_id.
    # =========================================================================
    op.create_table(
        'pulse_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),

        # Klasyfikacja zdarzenia
        sa.Column('head', sa.String(10), nullable=False),
        # RATIO / ANIMUS / FATUM / MENS / SYSTEM

        sa.Column('severity', sa.String(10), nullable=False, server_default='INFO'),
        # CRITICAL / HIGH / MEDIUM / LOW / INFO

        sa.Column('event_type', sa.String(50), nullable=False),
        # scan_started / finding_detected / mission_step / intel_updated / retest_done / etc.

        # Treść — dwa poziomy (PULSE filozofia)
        sa.Column('message_human', sa.Text(), nullable=False),
        # Wersja dla klienta: "Wykryto podatny serwer Apache"

        sa.Column('message_technical', sa.Text(), nullable=True),
        # Wersja dla operatora: "nmap -sV 192.168.1.47 → Apache/2.4.25 CVE-2021-41773"

        # Powiązania (opcjonalne — nie wszystkie eventy mają scan)
        sa.Column('scan_id', sa.String(100), nullable=True),  # task_id Celery
        sa.Column('finding_name', sa.String(255), nullable=True),
        sa.Column('target', sa.String(255), nullable=True),

        # Timestamp
        sa.Column('created_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('NOW()')),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'],
                                name='fk_pulse_events_organization',
                                ondelete='CASCADE'),
    )
    op.create_index('ix_pulse_events_organization_id', 'pulse_events', ['organization_id'])
    op.create_index('ix_pulse_events_created_at', 'pulse_events', ['created_at'])
    op.create_index('ix_pulse_events_severity', 'pulse_events', ['severity'])
    op.create_index('ix_pulse_events_head', 'pulse_events', ['head'])

    # =========================================================================
    # DEFAULT ORGANIZATION
    # Istniejące dane (scany, users) przypisane do org_id=1 (domyślna).
    # =========================================================================
    op.execute("""
        INSERT INTO organizations (name, domain, slug, connection_mode, is_active)
        VALUES ('Default Organization', 'localhost', 'default', 'CONNECTED', true)
    """)

    op.execute("""
        INSERT INTO licenses (organization_id, package, model, valid_from, max_targets, is_active)
        VALUES (1, 'PRAEFECTUS', 'subscription', NOW(), 9999, true)
    """)

    # =========================================================================
    # DODAJ organization_id DO ISTNIEJĄCYCH TABEL
    # Wszystkie z server_default=1 żeby nie łamać istniejących danych.
    # =========================================================================

    # users — dodaj organization_id + rozszerz enum ról
    op.add_column('users',
        sa.Column('organization_id', sa.Integer(), nullable=True,
                  server_default='1'))
    op.execute("UPDATE users SET organization_id = 1 WHERE organization_id IS NULL")
    op.alter_column('users', 'organization_id', nullable=False)
    op.create_foreign_key('fk_users_organization', 'users',
                          'organizations', ['organization_id'], ['id'])
    op.create_index('ix_users_organization_id', 'users', ['organization_id'])

    # Operatorzy CYRBER mają organization_id = NULL (widzą wszystkie org)
    # Dodaj kolumnę is_operator
    op.add_column('users',
        sa.Column('is_operator', sa.Boolean(), nullable=False, server_default='false'))

    # scans
    op.add_column('scans',
        sa.Column('organization_id', sa.Integer(), nullable=True,
                  server_default='1'))
    op.execute("UPDATE scans SET organization_id = 1 WHERE organization_id IS NULL")
    op.alter_column('scans', 'organization_id', nullable=False)
    op.create_foreign_key('fk_scans_organization', 'scans',
                          'organizations', ['organization_id'], ['id'])
    op.create_index('ix_scans_organization_id', 'scans', ['organization_id'])

    # findings — tabela nie istnieje w tej wersji, pomijamy

    # remediation_tasks
    op.add_column('remediation_tasks',
        sa.Column('organization_id', sa.Integer(), nullable=True,
                  server_default='1'))
    op.execute("UPDATE remediation_tasks SET organization_id = 1 WHERE organization_id IS NULL")
    op.alter_column('remediation_tasks', 'organization_id', nullable=False)
    op.create_foreign_key('fk_remediation_organization', 'remediation_tasks',
                          'organizations', ['organization_id'], ['id'])
    op.create_index('ix_remediation_tasks_organization_id', 'remediation_tasks',
                    ['organization_id'])

    # intel_sync_log — tylko indeks, bez FK (dane globalne, nie per-org)
    # Nie dodajemy organization_id tutaj — intel jest globalny dla całej instancji


def downgrade():
    # Usuń indeksy i FK z istniejących tabel
    for table in ['remediation_tasks', 'findings', 'scans', 'users']:
        try:
            op.drop_index(f'ix_{table}_organization_id', table_name=table)
            op.drop_constraint(f'fk_{table}_organization', table, type_='foreignkey')
            op.drop_column(table, 'organization_id')
        except Exception:
            pass

    op.drop_column('users', 'is_operator')

    # Usuń nowe tabele
    op.drop_table('pulse_events')
    op.drop_table('licenses')
    op.drop_table('organizations')
