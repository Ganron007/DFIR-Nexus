"""GraphRAG context block — causal edges for LLM prompts."""

from __future__ import annotations

import os

from nexus.analysis.evidence_graph import (
    SEV_RANK,
    EvidenceEdge,
    EvidenceEdgeType,
    build_evidence_graph,
)
from nexus.constants import DEFAULT_GRAPH_MAX_EDGES, ENV_GRAPH_MAX_EDGES
from nexus.ingest.schemas import Artifact

TYPE_ORDER: list[EvidenceEdgeType] = [
    "spawned",
    "file_lineage",
    "lateral_move",
    "network_flow",
    "ran_on",
]
TYPE_LABEL: dict[EvidenceEdgeType, str] = {
    "spawned": "Process spawns (parent → child)",
    "file_lineage": "File lineage (wrote → executed)",
    "lateral_move": "Lateral movement (same binary/account across hosts)",
    "network_flow": "Network connections (source → destination)",
    "ran_on": "Process anchored to host",
}
CITES_PER_EDGE = 3

DEFAULT_MAX_GRAPH_EDGES = int(os.environ.get(ENV_GRAPH_MAX_EDGES, str(DEFAULT_GRAPH_MAX_EDGES)))


def build_graph_context(
    artifacts: list[Artifact],
    *,
    max_edges: int | None = None,
) -> str:
    graph = build_evidence_graph(artifacts)
    if not graph.edges:
        return ""
    cap = max(0, max_edges if max_edges is not None else DEFAULT_MAX_GRAPH_EDGES)
    if cap == 0:
        return ""

    sev_rank = {n.id: SEV_RANK[n.max_severity] for n in graph.nodes}

    def edge_rank(e: EvidenceEdge) -> int:
        return min(sev_rank.get(e.source, 4), sev_rank.get(e.target, 4))

    ranked = sorted(
        graph.edges,
        key=lambda e: (edge_rank(e), TYPE_ORDER.index(e.type), e.basis),
    )
    kept = ranked[:cap]

    lines: list[str] = []
    for etype in TYPE_ORDER:
        group = [e for e in kept if e.type == etype]
        if not group:
            continue
        lines.append(f"{TYPE_LABEL[etype]}:")
        for e in group:
            cites = ", ".join(e.event_ids[:CITES_PER_EDGE])
            lines.append(f"- {e.basis}" + (f" [{cites}]" if cites else ""))

    if not lines:
        return ""

    header = (
        "ATTACK GRAPH (deterministic causal relationships — follow these edges to trace "
        "multi-hop attack paths; cite [event ids] in relatedEventIds):"
    )
    footer = ""
    if len(kept) < len(graph.edges):
        footer = f"\n(showing {len(kept)} of {len(graph.edges)} graph edges, highest-severity first)"
    return f"{header}\n" + "\n".join(lines) + footer + "\n\n"
