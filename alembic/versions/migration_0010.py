"""0010 - lex_policies table (LEX Decision Guard v2)

Revision ID: 0010
Revises: 0009
Create Date: 2026-03-01

Extended LEX policy model with multi-tenant support, time windows,
excluded modules, and COMES/LIBER/ITERUM mode awareness.
"""

from alembic import op
import sqlalchemy as sa

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'lex_policies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('mission_id', sa.String(), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('scope_cidrs', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('excluded_hosts', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('allowed_modules', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('excluded_modules', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('time_windows', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('require_approval_cvss', sa.Float(), nullable=False, server_default='9.0'),
        sa.Column('max_duration_seconds', sa.Integer(), nullable=False, server_default='28800'),
        sa.Column('max_targets', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('mode', sa.String(20), nullable=False, server_default='COMES'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()')),
        sa.Column('created_by', sa.String(100), server_default='system'),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'],
            name='fk_lex_policies_organization',
            ondelete='CASCADE',
        ),
    )
    op.create_index('ix_lex_policies_organization_id', 'lex_policies', ['organization_id'])
    op.create_index('ix_lex_policies_mission_id', 'lex_policies', ['mission_id'])
    op.create_index('ix_lex_policies_is_active', 'lex_policies', ['is_active'])


def downgrade():
    op.drop_index('ix_lex_policies_is_active')
    op.drop_index('ix_lex_policies_mission_id')
    op.drop_index('ix_lex_policies_organization_id')
    op.drop_table('lex_policies')
