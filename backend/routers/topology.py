"""Network topology graph builder + API route."""

from fastapi import APIRouter, Depends, HTTPException

from backend.deps import get_current_user
from modules.database import get_scan_by_task_id

router = APIRouter(tags=["topology"])


def build_topology(scan: dict) -> dict:
    """Build network topology graph from scan data. Pure function for testability."""
    target = scan.get("target", "unknown")
    nodes_map: dict[str, dict] = {}
    edges: list[dict] = []

    # Type priority for merging: dc > target > gateway > host > cloud
    _TYPE_PRIO = {"dc": 5, "target": 4, "gateway": 3, "host": 2, "cloud": 1}

    def _merge_node(node_id: str, data: dict):
        node_id = node_id.strip()
        if not node_id:
            return
        if node_id in nodes_map:
            existing = nodes_map[node_id]
            new_type = data.get("type", "host")
            old_type = existing.get("type", "host")
            if _TYPE_PRIO.get(new_type, 0) > _TYPE_PRIO.get(old_type, 0):
                existing["type"] = new_type
            for k in ("label", "os", "vendor", "mac", "netbios_name", "workgroup"):
                if data.get(k) and not existing.get(k):
                    existing[k] = data[k]
            if data.get("ports"):
                existing.setdefault("ports", []).extend(data["ports"])
        else:
            nodes_map[node_id] = {
                "id": node_id,
                "type": data.get("type", "host"),
                "label": data.get("label", node_id),
                "ports": data.get("ports", []),
                "os": data.get("os", ""),
                "vendor": data.get("vendor", ""),
                "mac": data.get("mac", ""),
                "risk": "info",
            }
            for k in ("netbios_name", "workgroup"):
                if data.get(k):
                    nodes_map[node_id][k] = data[k]

    def _add_edge(src: str, tgt: str, label: str = ""):
        src, tgt = src.strip(), tgt.strip()
        if not src or not tgt:
            return
        for e in edges:
            if e["source"] == src and e["target"] == tgt:
                return
        edges.append({"source": src, "target": tgt, "label": label})

    # 1. Always: internet + target
    _merge_node("internet", {"type": "cloud", "label": "INTERNET"})
    _merge_node(target, {"type": "target", "label": target})
    _add_edge("internet", target, "WAN")

    # 2. Nmap ports
    ports_data = scan.get("ports", [])
    if isinstance(ports_data, list) and ports_data:
        port_entries = []
        for p in ports_data:
            if isinstance(p, dict):
                port_entries.append(p)
        if port_entries:
            _merge_node(target, {"type": "target", "ports": port_entries})

    # 3. Netdiscover hosts
    nd = scan.get("netdiscover")
    if isinstance(nd, dict):
        for h in nd.get("hosts", []):
            if isinstance(h, dict) and h.get("ip"):
                ip = h["ip"]
                _merge_node(ip, {"type": "host", "label": ip, "mac": h.get("mac", ""), "vendor": h.get("vendor", "")})
                _add_edge(target, ip, "LAN")

    # 4. Arpscan hosts (dedup via merge)
    arp = scan.get("arpscan")
    if isinstance(arp, dict):
        for h in arp.get("hosts", []):
            if isinstance(h, dict) and h.get("ip"):
                ip = h["ip"]
                _merge_node(ip, {"type": "host", "label": ip, "mac": h.get("mac", ""), "vendor": h.get("vendor", "")})
                _add_edge(target, ip, "LAN")

    # 5. NBTscan — merge by IP + enrich
    nbt = scan.get("nbtscan")
    if isinstance(nbt, dict):
        for h in nbt.get("hosts", []):
            if isinstance(h, dict) and h.get("ip"):
                ip = h["ip"]
                node_type = "dc" if h.get("is_dc") else "host"
                _merge_node(ip, {
                    "type": node_type,
                    "label": h.get("netbios_name") or ip,
                    "netbios_name": h.get("netbios_name", ""),
                    "workgroup": h.get("workgroup", ""),
                })
                _add_edge(target, ip, "LAN")
        for dc in nbt.get("domain_controllers", []):
            if isinstance(dc, dict) and dc.get("ip"):
                _merge_node(dc["ip"], {"type": "dc", "label": dc.get("name") or dc["ip"]})
                _add_edge(target, dc["ip"], "LAN")

    # 6. Bloodhound computers + domain_controllers
    bh = scan.get("bloodhound")
    if isinstance(bh, dict):
        for c in bh.get("computers", []):
            if isinstance(c, dict):
                cid = c.get("ip") or c.get("name", "")
                if cid:
                    node_type = "dc" if c.get("is_dc") else "host"
                    _merge_node(cid, {"type": node_type, "label": c.get("name") or cid, "os": c.get("os", "")})
                    _add_edge(target, cid, "AD")
        for dc in bh.get("domain_controllers", []):
            if isinstance(dc, dict):
                dcid = dc.get("ip") or dc.get("name", "")
                if dcid:
                    _merge_node(dcid, {"type": "dc", "label": dc.get("name") or dcid})
                    _add_edge(target, dcid, "AD")

    # 7. Traceroute hops — chain internet → hop1 → hop2 → target
    tr = scan.get("traceroute")
    if isinstance(tr, dict):
        hops = tr.get("hops", [])
        if isinstance(hops, list) and hops:
            prev = "internet"
            for hop in hops:
                if isinstance(hop, dict) and hop.get("ip"):
                    hip = hop["ip"]
                    if hip == target:
                        continue
                    _merge_node(hip, {"type": "gateway", "label": hop.get("hostname") or hip})
                    _add_edge(prev, hip, f"hop {hop.get('ttl', '')}")
                    prev = hip
            _add_edge(prev, target, "hop")

    # 8. Certipy CAs
    cert = scan.get("certipy")
    if isinstance(cert, dict):
        for ca in cert.get("certificate_authorities", []):
            if isinstance(ca, dict):
                ca_name = ca.get("name") or ca.get("dns_name", "")
                if ca_name:
                    _merge_node(ca_name, {"type": "dc", "label": ca_name})
                    _add_edge(target, ca_name, "AD CS")

    # Risk per node: count findings by host IP
    findings_by_host: dict[str, list[str]] = {}
    nuclei = scan.get("nuclei")
    if isinstance(nuclei, dict):
        for f in nuclei.get("findings", []):
            if isinstance(f, dict):
                host = f.get("host") or f.get("ip") or target
                sev = (f.get("severity") or (f.get("info", {}) or {}).get("severity") or "info").lower()
                findings_by_host.setdefault(host, []).append(sev)

    _RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for node_id, node in nodes_map.items():
        host_sevs = findings_by_host.get(node_id, [])
        if not host_sevs:
            if node_id == target:
                host_sevs = findings_by_host.get(target, [])
        if host_sevs:
            max_sev = max(host_sevs, key=lambda s: _RISK_ORDER.get(s, 0))
            node["risk"] = max_sev

    nodes = list(nodes_map.values())

    open_ports = 0
    for n in nodes:
        open_ports += len(n.get("ports", []))

    all_risks = [n.get("risk", "info") for n in nodes]
    max_risk = max(all_risks, key=lambda r: _RISK_ORDER.get(r, 0)) if all_risks else "info"

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "scan_id": scan.get("task_id", ""),
            "target": target,
            "total_hosts": len([n for n in nodes if n["type"] not in ("cloud",)]),
            "open_ports_count": open_ports,
            "risk_level": max_risk,
        },
    }


@router.get("/api/scan/{task_id}/topology")
async def scan_topology(task_id: str, user: dict = Depends(get_current_user)):
    scan = get_scan_by_task_id(task_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return build_topology(scan)
