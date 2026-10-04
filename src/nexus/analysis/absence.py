"""WO-K7 — absence honesty.

"No findings" is not a result. It collapses three different situations into one
sentence, and only one of them is good news:

* the sources ran and observed nothing (**not observed by X, Y**);
* a source never ran because it is switched off or was never configured;
* a family was never examined at all.

An examiner reading "no findings" cannot tell those apart, and the third is a
coverage failure that would read as a clean case. `absence_statement` builds the
sentence the work order asks for - *"not observed by X, Y; not examined: Z"* -
from what actually ran, and names the disabled layers separately so an ablation
run cannot be mistaken for an ordinary one.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from nexus.analysis.layers import ENV_LEADS_DISABLE

log = logging.getLogger(__name__)

#: Lead-source names as they appear in a sentence.
SOURCE_LABELS: dict[str, str] = {
    "needles": "needles",
    "rules": "rule engines",
    "baselines": "baselines",
    "anomaly": "anomaly probes",
    "analytics": "behavioural analytics",
    "skills": "skills",
}

#: Layer name -> the lead source it feeds, for reporting a disabled layer.
LAYER_TO_SOURCE: dict[str, str] = {
    "needles": "needles",
    "rules": "rules",
    "baselines": "baselines",
    "anomaly": "anomaly",
    "analytics": "analytics",
    "skills": "skills",
}


def _as_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    to_dict = getattr(item, "to_dict", None)
    return to_dict() if callable(to_dict) else {}


def source_activity(
    case_dir: Path | str,
    *,
    leads: Iterable[Any] | None = None,
    families: Iterable[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Which lead sources ran, and how much each contributed.

    A source is reported as `ran` with a count, `disabled` (listed in a toggle),
    or `no-output` with the reason. A disabled source is never counted as having
    run - that is the difference between an ablation and an ordinary run.
    """
    case_dir = Path(case_dir)
    if leads is None:
        try:
            from nexus.analysis.leads import read_leads

            leads = read_leads(case_dir)
        except Exception:  # noqa: BLE001
            leads = []
    lead_dicts = [_as_dict(item) for item in leads or []]
    kinds = [str(d.get("kind") or "") for d in lead_dicts]
    rule_leads = [d for d in lead_dicts if str(d.get("kind")) == "rule_engine"]
    engines = {str((d.get("extra") or {}).get("engine") or "") for d in rule_leads}

    from nexus.analysis.layers import leads_enabled

    try:
        from nexus.analysis.rule_leads import ruleset_note

        rules_note = ruleset_note(case_dir)
    except Exception:  # noqa: BLE001
        rules_note = {}

    try:
        from nexus.analysis.behavioural_analytics import analytics, analytics_for

        analytics_total = len(analytics())
        analytics_here = len(analytics_for(list(families or []))) if families else analytics_total
    except Exception:  # noqa: BLE001
        analytics_total = analytics_here = 0

    anomaly_count = sum(
        1 for k in kinds if k in ("rarity", "ancestry", "first_seen", "burst")
    )

    out: dict[str, dict[str, Any]] = {}

    def add(source: str, *, ran: bool, count: int, note: str) -> None:
        enabled = leads_enabled(source)
        out[source] = {
            "label": SOURCE_LABELS.get(source, source),
            "enabled": enabled,
            "ran": bool(ran) and enabled,
            "count": int(count),
            "note": note,
            "reason": "" if enabled else f"disabled by {ENV_LEADS_DISABLE}",
        }

    add("needles", ran=True, count=0,
        note="the briefing needle scan runs on every indexed family")

    add("rules", ran=bool(rules_note.get("detections")) or bool(engines),
        count=int((rules_note or {}).get("detections") or 0),
        note=("" if (rules_note or {}).get("detections") else "no rule-engine detection in this case"))

    add("baselines", ran=True, count=0,
        note="the triage baselines answer per-value checks; they do not produce leads")

    add("anomaly", ran=True, count=anomaly_count,
        note="" if anomaly_count else "no anomaly probe raised a lead")

    add("analytics", ran=analytics_total > 0, count=analytics_here,
        note="" if analytics_total else "the analytic pack is unavailable")

    add("skills", ran=True, count=0,
        note="skills are executed per work order; see the run record for step results")
    return out


def absence_statement(
    case_dir: Path | str,
    *,
    families: Iterable[str] | None = None,
    leads: Iterable[Any] | None = None,
) -> dict[str, Any]:
    """The run's honest absence record, and the sentence that replaces "no findings".

    Returns the per-source activity, the per-family coverage, and `statement`.
    Never raises: a case with nothing to report yields a statement that says so
    rather than an empty string.
    """
    case_dir = Path(case_dir)
    family_list = [str(f) for f in (families or []) if str(f).strip()]

    sources = source_activity(case_dir, leads=leads, families=family_list)

    coverage: list[dict[str, Any]] = []
    if family_list:
        try:
            from nexus.analysis.work_orders import coverage_lines

            coverage = coverage_lines(case_dir, family_list, leads=leads)
        except Exception as exc:  # noqa: BLE001
            log.warning("coverage computation failed: %s", exc)
            coverage = [{"family": f, "examined": False, "examined_by": [],
                         "not_examined": [f"coverage could not be computed: {exc}"],
                         "summary": f"{f}: not examined"} for f in family_list]

    examined_by = sorted({s for line in coverage for s in (line.get("examined_by") or [])})
    not_examined = [str(line.get("family")) for line in coverage if not line.get("examined")]
    ran = [s["label"] for s in sources.values() if s["ran"]]
    never_ran = [s["label"] for s in sources.values() if not s["ran"] and s["enabled"]]
    disabled = [s["label"] for s in sources.values() if not s["enabled"]]

    from nexus.analysis.layers import disabled_names, layer_status

    statement = _sentence(ran=ran, never_ran=never_ran, disabled=disabled,
                          not_examined=not_examined, examined=bool(coverage))
    return {
        "sources": sources,
        "examined_by": examined_by,
        "not_examined": not_examined,
        "ran": ran,
        "never_ran": never_ran,
        "disabled": disabled,
        "disabled_names": disabled_names(),
        "layers": layer_status(),
        "coverage": coverage,
        "statement": statement,
        # The exact phrase a caller may show instead of "no findings".
        "instead_of_no_findings": statement,
    }


def _sentence(
    *,
    ran: list[str],
    never_ran: list[str],
    disabled: list[str],
    not_examined: list[str],
    examined: bool,
) -> str:
    parts: list[str] = []
    if ran:
        parts.append(f"not observed by {', '.join(ran)}")
    elif examined or never_ran or disabled:
        parts.append("not observed by any lead source")
    if never_ran:
        parts.append(f"no output from {', '.join(never_ran)}")
    if disabled:
        parts.append(f"layers disabled for this run: {', '.join(disabled)}")
    if not_examined:
        shown = ", ".join(not_examined[:12])
        more = f" (+{len(not_examined) - 12} more)" if len(not_examined) > 12 else ""
        parts.append(f"not examined: {shown}{more}")
    elif examined:
        parts.append("every family was examined")
    if not parts:
        return "no lead source ran and no family was examined - this run observed nothing"
    return "; ".join(parts)


def record(
    case_dir: Path | str,
    families: Iterable[str] | None = None,
    *,
    leads: Iterable[Any] | None = None,
) -> dict[str, Any]:
    """The block to embed in a run record (small: no per-family table)."""
    full = absence_statement(case_dir, families=families, leads=leads)
    return {
        "statement": full["statement"],
        "ran": full["ran"],
        "never_ran": full["never_ran"],
        "disabled": full["disabled"],
        "not_examined": full["not_examined"],
        "examined_by": full["examined_by"],
    }
