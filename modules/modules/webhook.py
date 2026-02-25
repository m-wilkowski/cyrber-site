from pydantic import BaseModel
from typing import Optional
import re

class WazuhAlert(BaseModel):
    agent_ip: Optional[str] = None
    agent_name: Optional[str] = None
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    data: Optional[dict] = None

def extract_target(alert: WazuhAlert) -> Optional[str]:
    """Wyciąga IP/hostname z alertu Wazuh"""
    # Bezpośredni IP agenta
    if alert.agent_ip and alert.agent_ip != "127.0.0.1":
        return alert.agent_ip

    # IP z pola data (np. network scan, nmap detection)
    if alert.data:
        for field in ["srcip", "dstip", "src_ip", "dst_ip", "ip"]:
            val = alert.data.get(field)
            if val and is_valid_ip(val):
                return val

    return None

def is_valid_ip(ip: str) -> bool:
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts) and ip != "127.0.0.1"
