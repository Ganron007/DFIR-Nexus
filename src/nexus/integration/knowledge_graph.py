"""E.0.4 — Investigation knowledge graph (entities + relations)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class KGEntity:
    id: str
    kind: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class KGRelation:
    source: str
    target: str
    kind: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class KnowledgeGraph:
    entities: list[KGEntity] = field(default_factory=list)
    relations: list[KGRelation] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    learnings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": [e.__dict__ for e in self.entities],
            "relations": [r.__dict__ for r in self.relations],
            "decisions": self.decisions,
            "learnings": self.learnings,
        }


def build_case_knowledge_graph(bundle: dict[str, Any]) -> KnowledgeGraph:
    """Build a lightweight knowledge graph from a case export bundle."""
    kg = KnowledgeGraph()
    case = bundle["case"]
    kg.entities.append(KGEntity(id=case.id, kind="case", label=case.name, properties={"severity": case.severity.value}))

    for finding in bundle.get("findings") or []:
        fid = f"finding:{finding.id}"
        kg.entities.append(
            KGEntity(
                id=fid,
                kind="finding",
                label=finding.title,
                properties={"severity": finding.severity.value, "state": finding.approval_state.value},
            )
        )
        kg.relations.append(KGRelation(source=case.id, target=fid, kind="has_finding"))
        for tid in finding.technique_ids:
            tid_id = f"technique:{tid}"
            if not any(e.id == tid_id for e in kg.entities):
                kg.entities.append(KGEntity(id=tid_id, kind="technique", label=tid))
            kg.relations.append(KGRelation(source=fid, target=tid_id, kind="uses_technique"))

    for evidence in bundle.get("evidence") or []:
        eid = f"evidence:{evidence.id}"
        kg.entities.append(KGEntity(id=eid, kind="evidence", label=evidence.name))
        kg.relations.append(KGRelation(source=case.id, target=eid, kind="has_evidence"))
        host = (evidence.metadata or {}).get("host")
        if host:
            hid = f"host:{host}"
            if not any(e.id == hid for e in kg.entities):
                kg.entities.append(KGEntity(id=hid, kind="host", label=str(host)))
            kg.relations.append(KGRelation(source=eid, target=hid, kind="observed_on"))

    if bundle.get("audit_verified"):
        kg.decisions.append({"type": "audit_chain", "outcome": "verified"})
    else:
        kg.learnings.append({"topic": "audit", "note": "Audit chain verification failed", "errors": bundle.get("audit_errors")})

    return kg
