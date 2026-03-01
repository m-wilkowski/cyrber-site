"""SQLAlchemy model for integration_configs table."""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB

from modules.database import Base


class IntegrationConfig(Base):
    """Persistent config for an organization's integration."""

    __tablename__ = "integration_configs"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    integration_type = Column(String(50), nullable=False)
    name = Column(String(255), nullable=False)
    config = Column(JSONB, nullable=False, server_default="{}")
    is_active = Column(Boolean, nullable=False, server_default="false")
    created_at = Column(DateTime, server_default="now()")
    updated_at = Column(DateTime, server_default="now()", onupdate=datetime.now)
