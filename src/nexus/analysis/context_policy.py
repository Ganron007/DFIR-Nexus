"""WO-1C item 3 — the context policy for an analysis run.

One case runs three modes (D5 = C). A later mode must be able to see what an
earlier mode concluded, but that material is *examiner context*, never
evidence: it is what a previous analyst said, and treating it as ground truth
is how a chain of LLM runs launders a guess into a fact.

Two policies:

``independent``
    The run sees the evidence, the leads, the digest and its own tool results
    only. This is the default and it is what makes a mode's verdict worth
    comparing: two independent modes that agree reached the same place from
    the same rows.

``informed``
    Additionally passes prior reports and DRAFT finding summaries as labelled
    context. The label is load-bearing: the prompt states that these are a
    prior analysis's conclusions, that they are not evidence, and that every
    claim still has to cite an ``audit_id`` from a real row. A finding that
    only cites prior context is rejected at staging (FD-001), so the policy
    can never manufacture a finding.

The policy is decided BEFORE the run and written to the run record
(``context_policy``), so a report can always say which policy produced it.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

POLICIES = ("independent", "informed")
DEFAULT_POLICY = "independent"


def normalize_policy(raw: Any) -> str:
    """Coerce any input to a valid policy; unknown values fall back safely."""
    value = str(raw or "").strip().lower()
    if value in POLICIES:
        return value
    return DEFAULT_POLICY


def policy_from_body(body: Any) -> str:
    """Read the policy off a request body, under either accepted key.

    The HTTP surface grew one endpoint at a time, so ``/mode2/run`` reads
    ``context`` and ``/mode3/run`` reads ``context_policy``. Both spellings are
    accepted here so a client cannot silently get the default by guessing the
    wrong one — a policy that is not recorded is a policy that did not run.
    """
    if not isinstance(body, dict):
        return DEFAULT_POLICY
    for key in ("context", "context_policy"):
        if key in body:
            return normalize_policy(body.get(key))
    return DEFAULT_POLICY


def prior_context(case_dir: Path) -> dict[str, Any]:
    """Everything a prior analysis produced on this case, labelled as such.

    Reads the case's own artifacts: ``reports/REPORT.md`` (or the legacy root
    ``REPORT.md``) and the DRAFT findings already staged. Both are returned
    under a single ``label`` that the prompt must repeat, so the model cannot
    mistake them for evidence.
    """
    case_dir = Path(case_dir)
    report_text = ""
    for candidate in (case_dir / "reports" / "REPORT.md", case_dir / "REPORT.md"):
        try:
            if candidate.is_file():
                report_text = candidate.read_text(encoding="utf-8")
                break
        except OSError:
            continue

    drafts: list[dict[str, Any]] = []
    fp = case_dir / "findings.json"
    if fp.is_file():
        try:
            loaded = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            loaded = []
        if isinstance(loaded, list):
            for f in loaded:
                if not isinstance(f, dict):
                    continue
                state = str(f.get("state") or f.get("approval_state") or "").upper()
                if state and state != "DRAFT":
                    continue
                drafts.append({
                    "title": str(f.get("title") or ""),
                    "severity": str(f.get("severity") or ""),
                    "observation": str(f.get("observation") or ""),
                    "interpretation": str(f.get("interpretation") or ""),
                    "technique_ids": f.get("technique_ids") or [],
                })

    return {
        "label": (
            "PRIOR ANALYSIS CONTEXT — a previous examiner or a previous mode's "
            "conclusions. This is NOT evidence. Do not cite it as a finding; "
            "cite the indexed rows it came from."
        ),
        "report": report_text[:8000],
        "drafts": drafts[:40],
        "report_present": bool(report_text),
        "draft_count": len(drafts),
    }


def render_prior_context(ctx: dict[str, Any]) -> str:
    """Render prior context as a prompt section (empty when there is none)."""
    if not ctx.get("report") and not ctx.get("drafts"):
        return ""
    parts: list[str] = [f"### {ctx.get('label', 'PRIOR ANALYSIS CONTEXT')}"]
    if ctx.get("report"):
        parts.append("Prior report (examiner conclusions, not evidence):")
        parts.append("```")
        parts.append(str(ctx["report"]))
        parts.append("```")
    if ctx.get("drafts"):
        parts.append("Draft findings already staged on this case:")
        for d in ctx["drafts"]:
            title = d.get("title") or "(untitled)"
            parts.append(
                f"- [{d.get('severity') or '?'}] {title} — "
                f"{d.get('interpretation') or d.get('observation') or ''}"
            )
    return "\n".join(parts)


def context_sections(case_dir: Path, policy: str) -> list[tuple[int, str, str]]:
    """Prompt sections this policy contributes, in priority order.

    ``independent`` contributes nothing — the run sees evidence only.
    ``informed`` contributes one labelled section, at a low priority so it is
    the first thing dropped when the context window is tight.
    """
    policy = normalize_policy(policy)
    if policy != "informed":
        return []
    try:
        ctx = prior_context(case_dir)
    except Exception as exc:  # noqa: BLE001 — context is best-effort, never fatal
        log.debug("prior context build failed for %s: %s", case_dir, exc)
        return []
    text = render_prior_context(ctx)
    if not text:
        return []
    return [(90, "prior_analysis_context", text)]
