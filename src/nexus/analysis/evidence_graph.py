"""Deterministic evidence chain graph from ingested artifacts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from nexus.ingest.schemas import Artifact, ArtifactType, Severity

EvidenceEdgeType = Literal["spawned", "lateral_move", "ran_on", "file_lineage", "network_flow"]
Confidence = Literal["high", "medium", "low"]
EvidenceNodeKind = Literal["process", "host", "account", "file", "network"]

SEV_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}

ACCT_RE = re.compile(
    r"(?<![\\/:.\w])([A-Za-z][A-Za-z0-9.-]{1,14})\\([A-Za-z0-9._$-]{2,20})(?![\\/\w])"
)
PSEUDO_ACCT_DOMAIN = re.compile(
    r"^(global|local|session|nt authority|nt service|window manager|font driver host|iis apppool)$",
    re.I,
)
PSEUDO_ACCT_USER = re.compile(
    r"^(dwm-\d+|umfd-\d+|msi[0-9a-f]+|system|local service|network service|anonymous logon)$",
    re.I,
)


@dataclass
class EvidenceNode:
    id: str
    kind: EvidenceNodeKind
    label: str
    asset: str | None = None
    max_severity: Severity = Severity.INFORMATIONAL
    event_ids: list[str] = field(default_factory=list)


@dataclass
class EvidenceEdge:
    id: str
    type: EvidenceEdgeType
    source: str
    target: str
    confidence: Confidence
    rule: str
    basis: str
    event_ids: list[str] = field(default_factory=list)


@dataclass
class EvidenceGraph:
    nodes: list[EvidenceNode]
    edges: list[EvidenceEdge]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "kind": n.kind,
                    "label": n.label,
                    "asset": n.asset,
                    "max_severity": n.max_severity.value,
                    "event_ids": n.event_ids,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "id": e.id,
                    "type": e.type,
                    "source": e.source,
                    "target": e.target,
                    "confidence": e.confidence,
                    "rule": e.rule,
                    "basis": e.basis,
                    "event_ids": e.event_ids,
                }
                for e in self.edges
            ],
        }


def _worse(a: Severity, b: Severity) -> Severity:
    return b if SEV_RANK[b] < SEV_RANK[a] else a


def _proc_id(asset: str, name: str) -> str:
    return f"proc:{asset.lower()}:{name.lower()}"


def _host_id(name: str) -> str:
    return f"host:{name.lower()}"


def _account_id(name: str) -> str:
    return f"account:{name.lower()}"


def _file_id(h: str) -> str:
    return f"file:{h.lower()}"


def _net_id(ip: str, port: int | None = None) -> str:
    return f"net:{ip.lower()}" + (f":{port}" if port else "")


def _short_hash(h: str) -> str:
    return f"{h[:12]}…" if len(h) > 14 else h


def _extract_accounts(text: str) -> list[str]:
    return [f"{m.group(1)}\\{m.group(2)}" for m in ACCT_RE.finditer(text)]


def _is_pseudo_account(acct: str) -> bool:
    i = acct.find("\\")
    domain = acct[:i] if i >= 0 else ""
    user = acct[i + 1 :] if i >= 0 else acct
    return bool(PSEUDO_ACCT_DOMAIN.match(domain.strip()) or PSEUDO_ACCT_USER.match(user.strip()))


def _artifact_text(art: Artifact) -> str:
    parts = [art.description or "", art.command_line or "", art.user or ""]
    return " ".join(p for p in parts if p)


def build_evidence_graph(artifacts: list[Artifact]) -> EvidenceGraph:
    node_map: dict[str, EvidenceNode] = {}
    edge_map: dict[str, EvidenceEdge] = {}

    def merge_node(
        nid: str,
        kind: EvidenceNodeKind,
        label: str,
        asset: str | None,
        event_id: str,
        sev: Severity,
    ) -> EvidenceNode:
        n = node_map.get(nid)
        if not n:
            n = EvidenceNode(nid, kind, label, asset, Severity.INFORMATIONAL, [])
            node_map[nid] = n
        n.max_severity = _worse(n.max_severity, sev)
        if event_id not in n.event_ids:
            n.event_ids.append(event_id)
        return n

    def add_edge(
        eid: str,
        etype: EvidenceEdgeType,
        source: str,
        target: str,
        confidence: Confidence,
        rule: str,
        basis: str,
        event_id: str,
    ) -> None:
        e = edge_map.get(eid)
        if e:
            if event_id not in e.event_ids:
                e.event_ids.append(event_id)
            return
        edge_map[eid] = EvidenceEdge(eid, etype, source, target, confidence, rule, basis, [event_id])

    for art in artifacts:
        asset = (art.host or "").strip()
        parent = (art.parent_process or "").strip()
        child = (art.process_name or "").strip()
        if parent and child and parent.lower() != child.lower() and asset:
            p_id = _proc_id(asset, parent)
            c_id = _proc_id(asset, child)
            merge_node(p_id, "process", parent, asset, art.id, art.severity)
            merge_node(c_id, "process", child, asset, art.id, art.severity)
            add_edge(
                f"spawned|{p_id}|{c_id}",
                "spawned",
                p_id,
                c_id,
                "high",
                "process-parent-child",
                f"{parent} → {child} on {asset}",
                art.id,
            )

    by_hash: dict[str, dict[str, Artifact]] = {}
    for art in artifacts:
        h = (art.file_hash_sha256 or art.file_hash_md5 or "").strip().lower()
        asset = (art.host or "").strip()
        if not h or not asset:
            continue
        by_hash.setdefault(h, {})[asset.lower()] = art

    for h, hosts in by_hash.items():
        if len(hosts) < 2:
            continue
        entries = sorted(hosts.items())
        for i in range(1, len(entries)):
            ea = entries[i - 1][1]
            eb = entries[i][1]
            a_node = merge_node(_host_id(ea.host or ""), "host", ea.host or "", None, ea.id, ea.severity)
            b_node = merge_node(_host_id(eb.host or ""), "host", eb.host or "", None, eb.id, eb.severity)
            add_edge(
                f"lateral|hash:{h}|{a_node.id}|{b_node.id}",
                "lateral_move",
                a_node.id,
                b_node.id,
                "high",
                "shared-hash",
                f"same binary {_short_hash(h)} on {ea.host} + {eb.host}",
                eb.id,
            )

    by_account: dict[str, dict[str, Artifact]] = {}
    for art in artifacts:
        asset = (art.host or "").strip()
        if not asset:
            continue
        for acct in _extract_accounts(_artifact_text(art)):
            if _is_pseudo_account(acct):
                continue
            by_account.setdefault(acct, {})[asset.lower()] = art

    for acct, hosts in by_account.items():
        if len(hosts) < 2:
            continue
        acct_id = _account_id(acct)
        for _, art in sorted(hosts.items()):
            merge_node(acct_id, "account", acct, None, art.id, art.severity)
            h_node = merge_node(_host_id(art.host or ""), "host", art.host or "", None, art.id, art.severity)
            add_edge(
                f"lateral|acct:{acct}|{h_node.id}",
                "lateral_move",
                acct_id,
                h_node.id,
                "medium",
                "shared-account",
                f"{acct} active on {art.host}",
                art.id,
            )

    writes: dict[str, list[Artifact]] = {}
    execs: dict[str, list[Artifact]] = {}
    for art in artifacts:
        h = (art.file_hash_sha256 or art.file_hash_md5 or "").strip().lower()
        if not h or not art.action:
            continue
        act = art.action.lower()
        if act in ("write", "create", "modify"):
            writes.setdefault(h, []).append(art)
        elif act == "execute":
            execs.setdefault(h, []).append(art)

    for h, write_list in writes.items():
        exec_list = execs.get(h)
        if not exec_list:
            continue
        sample = next((a.file_path for a in write_list + exec_list if a.file_path), None)
        fname = sample.rsplit("\\", 1)[-1] if sample else _short_hash(h)
        f_id = _file_id(h)
        for we in write_list:
            w_asset = (we.host or "").strip()
            if not w_asset:
                continue
            merge_node(f_id, "file", fname, None, we.id, we.severity)
            w_h = merge_node(_host_id(w_asset), "host", w_asset, None, we.id, we.severity)
            add_edge(
                f"file_lineage|wrote|{w_h.id}|{f_id}",
                "file_lineage",
                w_h.id,
                f_id,
                "high",
                "wrote-file",
                f"{w_asset} wrote {fname} ({_short_hash(h)})",
                we.id,
            )
        for xe in exec_list:
            x_asset = (xe.host or "").strip()
            if not x_asset:
                continue
            merge_node(f_id, "file", fname, None, xe.id, xe.severity)
            if xe.process_name:
                x_id = _proc_id(x_asset, xe.process_name)
                merge_node(x_id, "process", xe.process_name, x_asset, xe.id, xe.severity)
            else:
                x_id = _host_id(x_asset)
                merge_node(x_id, "host", x_asset, None, xe.id, xe.severity)
            add_edge(
                f"file_lineage|exec|{f_id}|{x_id}",
                "file_lineage",
                f_id,
                x_id,
                "high",
                "executed-file",
                f"{fname} ({_short_hash(h)}) executed on {x_asset}",
                xe.id,
            )

    for art in artifacts:
        if art.artifact_type != ArtifactType.NETWORK:
            continue
        src = art.source_ip or art.host
        dst = art.dest_ip
        if not src or not dst:
            continue
        src_id = _net_id(src)
        dst_id = _net_id(dst, art.dest_port)
        merge_node(src_id, "network", src, None, art.id, art.severity)
        merge_node(dst_id, "network", f"{dst}:{art.dest_port}" if art.dest_port else dst, None, art.id, art.severity)
        add_edge(
            f"net|{src_id}|{dst_id}",
            "network_flow",
            src_id,
            dst_id,
            "medium",
            "network-connection",
            f"{src} → {dst}" + (f":{art.dest_port}" if art.dest_port else ""),
            art.id,
        )

    used_nodes = {e.source for e in edge_map.values()} | {e.target for e in edge_map.values()}
    return EvidenceGraph(
        nodes=[n for n in node_map.values() if n.id in used_nodes],
        edges=list(edge_map.values()),
    )
