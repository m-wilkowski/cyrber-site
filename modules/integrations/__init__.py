"""CYRBER Integration Layer — extensible external connectors.

IntegrationManager is the central dispatcher for finding/mission events.
It loads active integrations from DB and dispatches events to all of them.
"""

import logging
from typing import Optional

from modules.integrations.base import BaseIntegration, IntegrationResult
from modules.integrations.els import ELSIntegration
from modules.integrations.webhook import WebhookIntegration

_log = logging.getLogger("cyrber.integrations")

_INTEGRATION_CLASSES = {
    "els": ELSIntegration,
    "energylogserver": ELSIntegration,
    "webhook": WebhookIntegration,
}


def create_integration(integration_type: str, config: dict) -> Optional[BaseIntegration]:
    """Factory: create an integration instance by type name."""
    cls = _INTEGRATION_CLASSES.get(integration_type)
    if cls is None:
        _log.warning("Unknown integration type: %s", integration_type)
        return None
    return cls(config=config)


class IntegrationManager:
    """Central dispatcher for integration events. Singleton."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

    def get_integrations(self, org_id: int) -> list[BaseIntegration]:
        """Load active integrations for an organization from DB."""
        try:
            from modules.database import SessionLocal
            db = SessionLocal()
            try:
                from modules.integrations.models import IntegrationConfig
                rows = (
                    db.query(IntegrationConfig)
                    .filter(
                        IntegrationConfig.organization_id == org_id,
                        IntegrationConfig.is_active == True,
                    )
                    .all()
                )
                integrations = []
                for row in rows:
                    cfg = row.config or {}
                    cfg["enabled"] = "true"
                    inst = create_integration(row.integration_type, cfg)
                    if inst:
                        integrations.append(inst)
                return integrations
            finally:
                db.close()
        except Exception as exc:
            _log.warning("Failed to load integrations for org %d: %s", org_id, exc)
            return []

    def notify_finding(
        self,
        finding: dict,
        org_id: int,
        mission_id: Optional[str] = None,
    ) -> list[IntegrationResult]:
        """Dispatch a finding event to all active integrations."""
        results = []
        for integration in self.get_integrations(org_id):
            try:
                r = integration.send_finding(finding, org_id, mission_id)
                results.append(r)
                if r.success:
                    _log.info(
                        "Integration %s: finding sent for org=%d (%s)",
                        integration.name, org_id, r.message,
                    )
                else:
                    _log.warning(
                        "Integration %s: finding send failed for org=%d (%s)",
                        integration.name, org_id, r.message,
                    )
            except Exception as exc:
                _log.warning("Integration %s error: %s", integration.name, exc)
                results.append(IntegrationResult(success=False, message=str(exc)))
        return results

    def notify_mission(
        self,
        mission: dict,
        event_type: str,
    ) -> list[IntegrationResult]:
        """Dispatch a mission event to all active integrations."""
        org_id = mission.get("organization_id", 0)
        results = []
        for integration in self.get_integrations(org_id):
            try:
                r = integration.send_mission_event(mission, event_type)
                results.append(r)
            except Exception as exc:
                _log.warning("Integration %s error: %s", integration.name, exc)
                results.append(IntegrationResult(success=False, message=str(exc)))
        return results
