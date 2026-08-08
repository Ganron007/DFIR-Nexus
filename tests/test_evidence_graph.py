"""Tests for evidence chain graph — deterministic causal graph."""

from __future__ import annotations

from datetime import UTC, datetime

from nexus.ingest.evidence_graph import (
    EdgeType,
    build_evidence_graph,
)
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity


def _make_artifact(
    host: str = "host1",
    process_name: str | None = None,
    process_id: int | None = None,
    file_hash_sha256: str | None = None,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    dest_port: int | None = None,
    user: str | None = None,
    raw: dict | None = None,
) -> Artifact:
    return Artifact(
        id=Artifact.new_id(),
        artifact_type=ArtifactType.PROCESS,
        source=ArtifactSource.EVTX,
        timestamp=datetime.now(UTC),
        severity=Severity.INFORMATIONAL,
        host=host,
        process_name=process_name,
        process_id=process_id,
        file_hash_sha256=file_hash_sha256,
        source_ip=source_ip,
        dest_ip=dest_ip,
        dest_port=dest_port,
        user=user,
        raw=raw or {},
    )


class TestEvidenceGraph:
    def test_empty_artifacts(self) -> None:
        graph = build_evidence_graph([])
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_process_nodes_created(self) -> None:
        arts = [_make_artifact(host="host1", process_name="cmd.exe", process_id=1234)]
        graph = build_evidence_graph(arts)
        proc_nodes = [n for n in graph.nodes.values() if n.node_type == "process"]
        assert len(proc_nodes) >= 1

    def test_host_nodes_created(self) -> None:
        arts = [_make_artifact(host="dc01.corp", process_name="lsass.exe")]
        graph = build_evidence_graph(arts)
        host_nodes = [n for n in graph.nodes.values() if n.node_type == "host"]
        assert any(n.host == "dc01.corp" for n in host_nodes)

    def test_lateral_move_same_hash(self) -> None:
        h = "e" * 64
        arts = [
            _make_artifact(host="host1", file_hash_sha256=h, process_name="evil.exe"),
            _make_artifact(host="host2", file_hash_sha256=h, process_name="evil.exe"),
        ]
        graph = build_evidence_graph(arts)
        lateral = graph.get_lateral_moves()
        assert len(lateral) >= 1

    def test_spawned_edge(self) -> None:
        arts = [
            _make_artifact(
                host="host1",
                process_name="cmd.exe",
                process_id=100,
                raw={"parent_process_name": "explorer.exe", "parent_process_id": 50},
            ),
            _make_artifact(host="host1", process_name="explorer.exe", process_id=50),
        ]
        graph = build_evidence_graph(arts)
        spawned = [e for e in graph.edges if e.edge_type == EdgeType.SPAWNED]
        assert len(spawned) >= 1

    def test_network_flow_edge(self) -> None:
        arts = [
            _make_artifact(host="host1", source_ip="10.0.0.1", dest_ip="1.2.3.4", dest_port=443),
        ]
        graph = build_evidence_graph(arts)
        net_nodes = [n for n in graph.nodes.values() if n.node_type == "network"]
        assert len(net_nodes) >= 1

    def test_to_dict(self) -> None:
        arts = [_make_artifact(host="host1", process_name="test.exe", process_id=1)]
        graph = build_evidence_graph(arts)
        d = graph.to_dict()
        assert "node_count" in d
        assert "edge_count" in d
        assert "nodes" in d
        assert "edges" in d

    def test_process_trees(self) -> None:
        arts = [
            _make_artifact(host="host1", process_name="explorer.exe", process_id=10),
            _make_artifact(
                host="host1",
                process_name="cmd.exe",
                process_id=20,
                raw={"parent_process_name": "explorer.exe", "parent_process_id": 10},
            ),
        ]
        graph = build_evidence_graph(arts)
        trees = graph.get_process_trees()
        assert len(trees) >= 1
