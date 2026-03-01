"""Base integration interface for CYRBER external connectors."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IntegrationResult:
    """Result of an integration operation."""

    success: bool
    message: str
    details: dict = field(default_factory=dict)


class BaseIntegration(ABC):
    """Abstract base class for all CYRBER integrations."""

    name: str = "base"

    @abstractmethod
    def send_finding(
        self,
        finding: dict,
        org_id: int,
        mission_id: Optional[str] = None,
    ) -> IntegrationResult:
        """Send a finding to the external system."""

    @abstractmethod
    def send_mission_event(
        self,
        mission: dict,
        event_type: str,
    ) -> IntegrationResult:
        """Send a mission lifecycle event (start/complete/abort)."""

    @abstractmethod
    def test_connection(self) -> dict:
        """Test connectivity. Returns status dict."""
