"""Evidence chain graph — deterministic causal attack graph.

Builds a directed graph from correlated artifacts with 5 edge types:
- spawned: parent → child process chain (same host)
- lateral_move: same binary hash on ≥2 hosts, or same account on ≥2 hosts
- ran_on: host → root of each process tree
- file_lineage: file written then executed (same hash)
- network_flow: src → dst IP:port connections

Every edge carries confidence, rule, basis, and event_ids for auditability.
Pure/deterministic — no AI, no network calls.

Inspired by DFIR-Companion's evidenceGraph.ts.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from nexus.ingest.schemas import Artifact

log = logging.getLogger(__name__)


class EdgeType(StrEnum):
    """Types of edges in the evidence chain graph."""
    SPAWNED = "spawned"
    LATERAL_MOVE = "lateral_move"
    RAN_ON = "ran_on"
    FILE_LINEAGE = "file_lineage"
    NETWORK_FLOW = "network_flow"


class Confidence(StrEnum):
    """Edge confidence level."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class GraphNode:
    """A node in the evidence chain graph."""
    id: str
    label: str
    node_type: str
    host: str | None = None
    user: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    process_name: str | None = None
    file_path: str | None = None
    file_hash_sha256: str | None = None
    artifact_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "node_type": self.node_type,
            "host": self.host,
            "user": self.user,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "process_name": self.process_name,
            "file_path": self.file_path,
            "file_hash_sha256": self.file_hash_sha256,
            "artifact_ids": self.artifact_ids,
        }


@dataclass
class GraphEdge:
    """An edge in the evidence chain graph."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    confidence: Confidence
    rule: str
    basis: str
    artifact_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "edge_type": self.edge_type.value,
            "confidence": self.confidence.value,
            "rule": self.rule,
            "basis": self.basis,
            "artifact_ids": self.artifact_ids,
        }


@dataclass
class EvidenceGraph:
    """The complete evidence chain graph."""
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def add_node(self, node: GraphNode) -> None:
        if node.id in self.nodes:
            existing = self.nodes[node.id]
            existing.artifact_ids.extend(node.artifact_ids)
        else:
            self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }

    def get_process_trees(self) -> list[list[str]]:
        """Extract process trees (rooted at nodes with no spawned-in edges)."""
        children: dict[str, list[str]] = defaultdict(list)
        has_parent: set[str] = set()

        for edge in self.edges:
            if edge.edge_type == EdgeType.SPAWNED:
                children[edge.source_id].append(edge.target_id)
                has_parent.add(edge.target_id)

        roots = [nid for nid in self.nodes if nid not in has_parent and
                 self.nodes[nid].node_type == "process"]
        trees: list[list[str]] = []
        for root in roots:
            tree: list[str] = []
            stack = [root]
            while stack:
                node_id = stack.pop()
                tree.append(node_id)
                stack.extend(children.get(node_id, []))
            trees.append(tree)
        return trees

    def get_lateral_moves(self) -> list[GraphEdge]:
        """Get all lateral movement edges."""
        return [e for e in self.edges if e.edge_type == EdgeType.LATERAL_MOVE]


def build_evidence_graph(artifacts: list[Artifact]) -> EvidenceGraph:
    """Build a deterministic evidence chain graph from a list of artifacts.

    Pure function — no side effects, no I/O, no AI.
    """
    graph = EvidenceGraph()

    # Index artifacts by key dimensions
    by_host_process: dict[str, list[Artifact]] = defaultdict(list)
    by_hash: dict[str, list[Artifact]] = defaultdict(list)
    by_account_host: dict[str, list[Artifact]] = defaultdict(list)
    by_ip_port: dict[str, list[Artifact]] = defaultdict(list)

    for a in artifacts:
        if a.host and a.process_name:
            key = f"{a.host}|{a.process_name}|{a.process_id or 0}"
            by_host_process[key].append(a)
        if a.file_hash_sha256:
            by_hash[a.file_hash_sha256.lower()].append(a)
        if a.user and a.host:
            key = f"{a.host}|{a.user}"
            by_account_host[key].append(a)
        if a.source_ip and a.dest_ip:
            key = f"{a.source_ip}|{a.dest_ip}|{a.dest_port or 0}"
            by_ip_port[key].append(a)

    # Create process nodes
    process_nodes: dict[str, str] = {}
    for key, arts in by_host_process.items():
        parts = key.split("|")
        host, proc, pid = parts[0], parts[1], parts[2]
        node_id = f"proc:{host}:{proc}:{pid}"
        node = GraphNode(
            id=node_id,
            label=f"{proc} (PID {pid}) on {host}",
            node_type="process",
            host=host,
            process_name=proc,
            artifact_ids=[a.id for a in arts],
        )
        graph.add_node(node)
        process_nodes[key] = node_id

    # Create host nodes
    hosts_seen: set[str] = set()
    for a in artifacts:
        if a.host and a.host not in hosts_seen:
            hosts_seen.add(a.host)
            graph.add_node(GraphNode(
                id=f"host:{a.host}",
                label=a.host,
                node_type="host",
                host=a.host,
                artifact_ids=[x.id for x in artifacts if x.host == a.host],
            ))

    # Create file nodes
    file_nodes: dict[str, str] = {}
    for hash_val, arts in by_hash.items():
        node_id = f"file:{hash_val[:16]}"
        file_path = next((a.file_path for a in arts if a.file_path), None)
        graph.add_node(GraphNode(
            id=node_id,
            label=file_path or f"hash:{hash_val[:16]}",
            node_type="file",
            file_path=file_path,
            file_hash_sha256=hash_val,
            artifact_ids=[a.id for a in arts],
        ))
        file_nodes[hash_val] = node_id

    # Create network nodes
    for key, arts in by_ip_port.items():
        parts = key.split("|")
        src_ip, dst_ip, dst_port = parts[0], parts[1], parts[2]
        node_id = f"net:{src_ip}->{dst_ip}:{dst_port}"
        graph.add_node(GraphNode(
            id=node_id,
            label=f"{src_ip} → {dst_ip}:{dst_port}",
            node_type="network",
            source_ip=src_ip,
            dest_ip=dst_ip,
            artifact_ids=[a.id for a in arts],
        ))

    # --- Edge type 1: SPAWNED (parent → child process) ---
    for a in artifacts:
        if a.host and a.process_name and a.raw:
            parent = a.raw.get("parent_process_name") or a.raw.get("parent_name")
            parent_pid = a.raw.get("parent_process_id") or a.raw.get("parent_pid")
            if parent and a.host:
                parent_key = f"{a.host}|{parent}|{parent_pid or 0}"
                child_key = f"{a.host}|{a.process_name}|{a.process_id or 0}"
                if parent_key in process_nodes and child_key in process_nodes:
                    graph.add_edge(GraphEdge(
                        source_id=process_nodes[parent_key],
                        target_id=process_nodes[child_key],
                        edge_type=EdgeType.SPAWNED,
                        confidence=Confidence.HIGH,
                        rule="parent_process_match",
                        basis=f"parent={parent}, child={a.process_name}, host={a.host}",
                        artifact_ids=[a.id],
                    ))

    # --- Edge type 2: LATERAL_MOVE (same hash/account on multiple hosts) ---
    for hash_val, arts in by_hash.items():
        hosts = set(a.host for a in arts if a.host)
        if len(hosts) >= 2 and hash_val in file_nodes:
            for host in hosts:
                host_arts = [a for a in arts if a.host == host]
                graph.add_edge(GraphEdge(
                    source_id=f"host:{sorted(hosts)[0]}",
                    target_id=f"host:{host}",
                    edge_type=EdgeType.LATERAL_MOVE,
                    confidence=Confidence.HIGH,
                    rule="same_hash_multi_host",
                    basis=f"hash={hash_val[:16]}, hosts={sorted(hosts)}",
                    artifact_ids=[a.id for a in host_arts],
                ))

    for acct_key, arts in by_account_host.items():
        hosts = set(a.host for a in arts if a.host)
        if len(hosts) >= 2:
            host_list = sorted(hosts)
            for i in range(1, len(host_list)):
                graph.add_edge(GraphEdge(
                    source_id=f"host:{host_list[0]}",
                    target_id=f"host:{host_list[i]}",
                    edge_type=EdgeType.LATERAL_MOVE,
                    confidence=Confidence.MEDIUM,
                    rule="same_account_multi_host",
                    basis=f"account={acct_key}, hosts={host_list}",
                    artifact_ids=[a.id for a in arts],
                ))

    # --- Edge type 3: RAN_ON (host → root process) ---
    for key, node_id in process_nodes.items():
        host = key.split("|")[0]
        has_parent = any(
            e.target_id == node_id and e.edge_type == EdgeType.SPAWNED
            for e in graph.edges
        )
        if not has_parent:
            graph.add_edge(GraphEdge(
                source_id=f"host:{host}",
                target_id=node_id,
                edge_type=EdgeType.RAN_ON,
                confidence=Confidence.MEDIUM,
                rule="root_process_on_host",
                basis=f"root process on {host}",
                artifact_ids=graph.nodes[node_id].artifact_ids if node_id in graph.nodes else [],
            ))

    # --- Edge type 4: FILE_LINEAGE (file written then executed) ---
    for hash_val, arts in by_hash.items():
        write_arts = [a for a in arts if a.raw and a.raw.get("action") in ("create", "write", "modify")]
        exec_arts = [a for a in arts if a.raw and a.raw.get("action") in ("execute", "run")]
        if write_arts and exec_arts and hash_val in file_nodes:
            graph.add_edge(GraphEdge(
                source_id=file_nodes[hash_val],
                target_id=file_nodes[hash_val],
                edge_type=EdgeType.FILE_LINEAGE,
                confidence=Confidence.HIGH,
                rule="write_then_execute",
                basis=f"hash={hash_val[:16]}, written by {len(write_arts)} events, executed by {len(exec_arts)}",
                artifact_ids=[a.id for a in write_arts + exec_arts],
            ))

    # --- Edge type 5: NETWORK_FLOW (src → dst connections) ---
    for key, arts in by_ip_port.items():
        parts = key.split("|")
        src_ip, dst_ip = parts[0], parts[1]
        src_nodes = [nid for nid, n in graph.nodes.items()
                     if n.host and n.source_ip == src_ip]
        dst_nodes = [nid for nid, n in graph.nodes.items()
                     if n.host and n.dest_ip == dst_ip]
        net_id = f"net:{src_ip}->{dst_ip}:{parts[2]}"
        if src_nodes:
            graph.add_edge(GraphEdge(
                source_id=src_nodes[0],
                target_id=net_id,
                edge_type=EdgeType.NETWORK_FLOW,
                confidence=Confidence.MEDIUM,
                rule="outbound_connection",
                basis=f"{src_ip} → {dst_ip}:{parts[2]}",
                artifact_ids=[a.id for a in arts],
            ))

    return graph
