"""0011 - Rebuild mens_missions / mens_iterations for MENS v2

Revision ID: 0011
Revises: 0010
Create Date: 2026-03-01

DROP old MENS tables (v1 String-PK schema) and recreate them with Integer
PKs, organization_id FK, policy_id FK to lex_policies, and a cleaner column
set matching the new modules/mind_agent.py agent.
"""

from alembic import op
import sqlalchemy as sa

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade():
    # Drop old tables (iterations first due to FK)
    op.drop_table('mens_iterations')
    op.drop_table('mens_missions')

    # ── New mens_missions ────────────────────────────────────────
    op.create_table(
        'mens_missions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('mission_id', sa.String(64), nullable=False),
        sa.Column('target', sa.String(512), nullable=False),
        sa.Column('policy_id', sa.Integer(), nullable=False),
        sa.Column('mode', sa.String(20), nullable=False, server_default='COMES'),
        sa.Column('status', sa.String(20), nullable=False, server_default='pending'),
        sa.Column('started_at', sa.DateTime(), server_default=sa.text('NOW()')),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('iterations_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(100), server_default='system'),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'],
            name='fk_mens_missions_organization',
            ondelete='CASCADE',
        ),
        sa.ForeignKeyConstraint(
            ['policy_id'], ['lex_policies.id'],
            name='fk_mens_missions_policy',
            ondelete='CASCADE',
        ),
    )
    op.create_index('ix_mens_missions_organization_id', 'mens_missions', ['organization_id'])
    op.create_index('ix_mens_missions_mission_id', 'mens_missions', ['mission_id'], unique=True)
    op.create_index('ix_mens_missions_status', 'mens_missions', ['status'])
    op.create_index('ix_mens_missions_policy_id', 'mens_missions', ['policy_id'])

    # ── New mens_iterations ──────────────────────────────────────
    op.create_table(
        'mens_iterations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('mission_id', sa.Integer(), nullable=False),
        sa.Column('iteration_number', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('module_used', sa.String(100), nullable=True),
        sa.Column('target', sa.String(512), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('result_summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()')),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(
            ['mission_id'], ['mens_missions.id'],
            name='fk_mens_iterations_mission',
            ondelete='CASCADE',
        ),
    )
    op.create_index('ix_mens_iterations_mission_id', 'mens_iterations', ['mission_id'])


def downgrade():
    op.drop_index('ix_mens_iterations_mission_id')
    op.drop_table('mens_iterations')

    op.drop_index('ix_mens_missions_policy_id')
    op.drop_index('ix_mens_missions_status')
    op.drop_index('ix_mens_missions_mission_id')
    op.drop_index('ix_mens_missions_organization_id')
    op.drop_table('mens_missions')

    # Recreate old v1 tables (minimal schema for rollback)
    op.create_table(
        'mens_missions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('target', sa.String(), nullable=False),
        sa.Column('objective', sa.Text(), nullable=False),
        sa.Column('lex_rule_id', sa.String(), nullable=False),
        sa.Column('mode', sa.String(), server_default='comes'),
        sa.Column('status', sa.String(), server_default='pending'),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_by', sa.String(), server_default='system'),
        sa.Column('fiducia', sa.Float(), server_default='0.0'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'mens_iterations',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('mission_id', sa.String(), nullable=False),
        sa.Column('iteration_number', sa.Integer(), server_default='0'),
        sa.Column('phase', sa.String(), server_default='observe'),
        sa.Column('module_selected', sa.String(), nullable=True),
        sa.Column('module_args', sa.JSON(), nullable=True),
        sa.Column('cogitatio', sa.Text(), nullable=True),
        sa.Column('result_summary', sa.Text(), nullable=True),
        sa.Column('findings_count', sa.Integer(), server_default='0'),
        sa.Column('head', sa.String(10), server_default='RATIO'),
        sa.Column('approved', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
