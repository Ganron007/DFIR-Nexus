"""Mode 2 interpretation verdict — analysis/interpretation.md.

Assembled after findings are staged: a deterministic skeleton (facts:
findings, entity coverage, TI, gaps) plus an optional LLM executive
verdict paragraph. The briefing endpoint merges this file so the examiner
sees the Mode 2 verdict, not only the deterministic briefing.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _md_cell(value: Any, limit: int = 120) -> str:
    """One markdown-table cell: pipes/newlines flattened, length bounded."""
    text = " ".join(str(value or "").split())
    text = text.replace("|", "\\|")
    return text[:limit]


def _load_findings(case_dir: Path) -> list[dict[str, Any]]:
    path = Path(case_dir) / "findings.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [f for f in data if isinstance(f, dict)] if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


async def write_interpretation_summary(
    case_dir: Path,
    *,
    findings: list[dict[str, Any]] | None = None,
    gaps: list[dict[str, str]] | None = None,
    reconciliation: dict[str, Any] | None = None,
    model: Any = None,
) -> Path | None:
    """Write analysis/interpretation.md: verdict + coverage + gaps + TI.

    ``reconciliation`` (deterministic) lists digest items no finding mentions —
    the verdict MUST address them; they are also written into the file so the
    examiner can see exactly what the LLM had to answer for.
    """
    case_dir = Path(case_dir)
    analysis = case_dir / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    findings = findings if findings is not None else _load_findings(case_dir)
    gaps = gaps or []
    reconciliation = reconciliation or {}

    ti_path = analysis / "ti_context.md"
    ti_md = ti_path.read_text(encoding="utf-8", errors="replace").strip() if ti_path.is_file() else ""
    inv_path = analysis / "entity_inventory.json"
    inv_count = 0
    if inv_path.is_file():
        try:
            inv = json.loads(inv_path.read_text(encoding="utf-8"))
            for key in ("processes", "paths", "users", "hosts", "commands"):
                inv_count += len(inv.get(key) or [])
            net = inv.get("network") or {}
            inv_count += sum(len(net.get(k) or []) for k in ("ipv4", "domain", "url"))
            hashes = inv.get("hashes") or {}
            inv_count += sum(len(hashes.get(k) or []) for k in ("sha256", "sha1", "md5"))
        except (OSError, ValueError):
            inv_count = 0

    lines = [
        "# Mode 2 interpretation (LLM-assisted)",
        "",
        f"- Findings staged (DRAFT): **{len(findings)}**",
        f"- Entity inventory items: **{inv_count}** — unaddressed by findings: **{len(gaps)}**",
    ]
    unaddressed = list(reconciliation.get("unaddressed") or [])
    if reconciliation:
        lines.append(
            f"- Digest reconciliation: **{len(reconciliation.get('addressed') or [])} "
            f"addressed / {len(unaddressed)} unaddressed** "
            f"(alerts {reconciliation.get('alerts_total', 0)}, "
            f"needles with hits {reconciliation.get('needles_with_hits', 0)})"
        )
    if findings:
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        lines.append("| # | Severity | Confidence | Title |")
        lines.append("|---|----------|------------|-------|")
        for idx, f in enumerate(findings, start=1):
            lines.append(
                f"| {idx} | {_md_cell(f.get('severity') or 'n/a', 16)} "
                f"| {_md_cell(f.get('confidence') or 'n/a', 16)} "
                f"| {_md_cell(f.get('title'), 160)} |"
            )
    if unaddressed:
        lines.append("")
        lines.append("## Reconciliation — digest items no finding mentions (must be addressed)")
        lines.append("")
        lines.append("| Kind | Item |")
        lines.append("|------|------|")
        for item in unaddressed[:30]:
            lines.append(
                f"| {_md_cell(item.get('kind'), 20)} | {_md_cell(item.get('value'))} |"
            )
    if gaps:
        lines.append("")
        lines.append("## Coverage gaps (not yet explained by any finding)")
        lines.append("")
        lines.append("| Entity type | Value |")
        lines.append("|-------------|-------|")
        for g in gaps[:25]:
            lines.append(
                f"| {_md_cell(g.get('kind'), 24)} | {_md_cell(g.get('value'))} |"
            )
    if ti_md:
        lines.append("")
        lines.append(ti_md)

    verdict = ""
    if model is not None:
        try:
            summary_lines = "\n".join(
                f"{f.get('title')} — {str(f.get('interpretation') or '')[:200]} "
                f"(confidence {f.get('confidence')})"
                for f in findings[:12]
            )
            gaps_line = ", ".join(f"{g['kind']}:{g['value']}" for g in gaps[:12]) or "(none)"
            # Keep the verdict prompt inside the model's window too.
            try:
                from nexus.langgraph.prompt_budget import budget_chars

                reconcile_cap = max(8_000, budget_chars() // 20)
            except Exception:  # noqa: BLE001
                reconcile_cap = 40_000
            reconcile_lines = "\n".join(
                f"- [{i.get('kind')}] {i.get('value')}" for i in unaddressed[:40]
            )[:reconcile_cap]
            response = await model.ainvoke([
                {"role": "system", "content": (
                    "You are the lead DFIR analyst. Write the case verdict as "
                    "COMPACT MARKDOWN (this renders in the examiner's briefing "
                    "— never a wall of text):\n"
                    "1) One short paragraph: what the evidence supports (or "
                    "that it is insufficient), the strongest signal, confidence.\n"
                    "2) A markdown disposition table with exactly these "
                    "columns: | Item | Disposition | Basis | — one row per "
                    "digest reconciliation item below (disposition = covered / "
                    "benign / gap).\n"
                    "3) A short `Next steps` bullet list (max 5).\n"
                    "HARD RULES:\n"
                    "- Address the reconciliation list item by item. Never "
                    "omit an item.\n"
                    "- Absence of an evidence class (e.g. no memory, no "
                    "network, no disk) is SCOPE — never phrase it as 'no "
                    "compromise'.\n"
                    "- Base every claim on the staged findings and evidence "
                    "below; no invented facts."
                )},
                {"role": "user", "content": (
                    f"Findings:\n{summary_lines or '(none staged)'}\n\n"
                    f"Coverage gaps: {gaps_line}\n\n"
                    f"Digest reconciliation (unaddressed items):\n"
                    f"{reconcile_lines or '(none — all digest items are covered)'}\n\n"
                    f"Threat intel:\n{ti_md[:1500] or '(none)'}"
                )},
            ])
            verdict = str(getattr(response, "content", str(response))).strip()[:2000]
        except Exception as exc:  # noqa: BLE001 — verdict is best-effort
            log.warning("Verdict LLM pass failed: %s", exc)

    if verdict:
        lines.insert(4, "")
        lines.insert(5, "## Executive verdict")
        lines.insert(6, verdict)

    path = analysis / "interpretation.md"
    try:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path
    except OSError as exc:
        log.warning("interpretation.md write failed: %s", exc)
        return None
