"""Helpers so agents cite real artifact fields in findings."""

from __future__ import annotations

from collections import Counter
from typing import Any

from nexus.ingest.schemas import Artifact


def _ts(a: Artifact) -> str:
    try:
        return a.timestamp.isoformat()
    except Exception:
        return ""


def top_values(artifacts: list[Artifact], attr: str, n: int = 5) -> list[tuple[str, int]]:
    c: Counter[str] = Counter()
    for a in artifacts:
        v = getattr(a, attr, None)
        if v:
            c[str(v)] += 1
    return c.most_common(n)


def sample_rows(artifacts: list[Artifact], limit: int = 5) -> list[str]:
    rows: list[str] = []
    for a in artifacts[:limit]:
        bits = [a.source.value, a.artifact_type.value]
        if a.host:
            bits.append(f"host={a.host}")
        if a.process_name:
            bits.append(f"proc={a.process_name}")
        if a.process_id is not None:
            bits.append(f"pid={a.process_id}")
        if a.command_line:
            bits.append(f"cmd={a.command_line[:120]}")
        if a.source_ip or a.dest_ip:
            bits.append(f"{a.source_ip or '?'}->{a.dest_ip or '?'}")
            if a.dest_port:
                bits[-1] += f":{a.dest_port}"
        if a.file_path:
            bits.append(f"path={a.file_path}")
        if a.description:
            bits.append(a.description[:100])
        ts = _ts(a)
        if ts:
            bits.append(f"t={ts}")
        if a.technique_ids:
            bits.append("mitre=" + ",".join(a.technique_ids[:4]))
        rows.append(" | ".join(bits))
    return rows


def cite_block(artifacts: list[Artifact], *, sample: int = 5) -> str:
    if not artifacts:
        return "No artifacts in scope."
    lines = [
        f"Scope: {len(artifacts)} artifacts from sources "
        f"{sorted({a.source.value for a in artifacts})}.",
    ]
    hosts = top_values(artifacts, "host", 5)
    if hosts:
        lines.append("Hosts: " + ", ".join(f"{h} ({n})" for h, n in hosts))
    procs = top_values(artifacts, "process_name", 5)
    if procs:
        lines.append("Processes: " + ", ".join(f"{p} ({n})" for p, n in procs))
    dst = top_values(artifacts, "dest_ip", 5)
    if dst:
        lines.append("Dest IPs: " + ", ".join(f"{ip} ({n})" for ip, n in dst))
    src = top_values(artifacts, "source_ip", 5)
    if src:
        lines.append("Source IPs: " + ", ".join(f"{ip} ({n})" for ip, n in src))
    lines.append("Sample evidence:")
    for row in sample_rows(artifacts, sample):
        lines.append(f"- {row}")
    return "\n".join(lines)


def technique_ids(artifacts: list[Artifact], fallback: list[str] | None = None) -> list[str]:
    tids = sorted({t for a in artifacts for t in (a.technique_ids or []) if t.startswith("T")})
    return tids or list(fallback or [])


def finding(
    title: str,
    artifacts: list[Artifact],
    *,
    severity: str = "high",
    technique_ids_: list[str] | None = None,
    lead: str = "",
) -> dict[str, Any]:
    body = cite_block(artifacts)
    if lead:
        body = lead.rstrip() + "\n\n" + body
    return {
        "title": title,
        "description": body,
        "severity": severity,
        "technique_ids": technique_ids_ if technique_ids_ is not None else technique_ids(artifacts),
    }
