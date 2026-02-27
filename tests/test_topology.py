"""Tests for build_topology() network graph builder."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.routers.topology import build_topology


def _minimal_scan(target="192.168.1.1", **extra):
    scan = {"task_id": "test-001", "target": target, "status": "completed"}
    scan.update(extra)
    return scan


def test_topology_target_node_always_present():
    topo = build_topology(_minimal_scan())
    ids = [n["id"] for n in topo["nodes"]]
    assert "192.168.1.1" in ids
    target_node = next(n for n in topo["nodes"] if n["id"] == "192.168.1.1")
    assert target_node["type"] == "target"


def test_topology_cloud_node_always_present():
    topo = build_topology(_minimal_scan())
    ids = [n["id"] for n in topo["nodes"]]
    assert "internet" in ids
    cloud = next(n for n in topo["nodes"] if n["id"] == "internet")
    assert cloud["type"] == "cloud"


def test_topology_nodes_have_required_fields():
    topo = build_topology(_minimal_scan(
        netdiscover={"hosts": [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff"}]},
    ))
    for node in topo["nodes"]:
        assert "id" in node
        assert "type" in node
        assert "label" in node
        assert node["type"] in ("cloud", "target", "gateway", "host", "dc")


def test_topology_edges_connect_existing_nodes():
    topo = build_topology(_minimal_scan(
        traceroute={"hops": [{"ip": "10.0.0.1", "ttl": 1}, {"ip": "10.0.0.2", "ttl": 2}]},
    ))
    node_ids = {n["id"] for n in topo["nodes"]}
    for edge in topo["edges"]:
        assert edge["source"] in node_ids, f"edge source {edge['source']} not in nodes"
        assert edge["target"] in node_ids, f"edge target {edge['target']} not in nodes"


def test_topology_with_nmap_ports():
    ports = [{"port": 80, "state": "open", "service": "http"}, {"port": 443, "state": "open", "service": "https"}]
    topo = build_topology(_minimal_scan(ports=ports))
    target_node = next(n for n in topo["nodes"] if n["id"] == "192.168.1.1")
    assert len(target_node["ports"]) == 2
    assert topo["meta"]["open_ports_count"] == 2


def test_topology_with_discovered_hosts():
    topo = build_topology(_minimal_scan(
        netdiscover={"hosts": [
            {"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Cisco"},
            {"ip": "10.0.0.6", "mac": "11:22:33:44:55:66", "vendor": "Dell"},
        ]},
    ))
    ids = [n["id"] for n in topo["nodes"]]
    assert "10.0.0.5" in ids
    assert "10.0.0.6" in ids
    host = next(n for n in topo["nodes"] if n["id"] == "10.0.0.5")
    assert host["type"] == "host"
    assert host["vendor"] == "Cisco"
    assert topo["meta"]["total_hosts"] >= 3  # target + 2 hosts


def test_topology_with_nbtscan_dc():
    topo = build_topology(_minimal_scan(
        nbtscan={
            "hosts": [{"ip": "10.0.0.10", "netbios_name": "DC01", "is_dc": True, "workgroup": "CORP"}],
            "domain_controllers": [{"ip": "10.0.0.10", "name": "DC01"}],
        },
    ))
    dc_node = next(n for n in topo["nodes"] if n["id"] == "10.0.0.10")
    assert dc_node["type"] == "dc"


def test_topology_empty_scan():
    topo = build_topology(_minimal_scan())
    assert len(topo["nodes"]) == 2  # internet + target
    assert len(topo["edges"]) == 1  # internet → target
    assert topo["meta"]["target"] == "192.168.1.1"
    assert topo["meta"]["open_ports_count"] == 0
