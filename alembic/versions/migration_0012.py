"""0012 - Add LLM settings to organizations

Revision ID: 0012
Revises: 0011
Create Date: 2026-03-01

Add per-org LLM configuration:
- llm_mode: cloud / local / airgap
- preferred_provider: anthropic / openai / deepseek
- ollama_base_url: custom Ollama endpoint (nullable)
"""

from alembic import op
import sqlalchemy as sa

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('organizations',
                  sa.Column('llm_mode', sa.String(20), nullable=False,
                            server_default='cloud'))
    op.add_column('organizations',
                  sa.Column('preferred_provider', sa.String(50), nullable=False,
                            server_default='anthropic'))
    op.add_column('organizations',
                  sa.Column('ollama_base_url', sa.String(255), nullable=True))


def downgrade():
    op.drop_column('organizations', 'ollama_base_url')
    op.drop_column('organizations', 'preferred_provider')
    op.drop_column('organizations', 'llm_mode')
