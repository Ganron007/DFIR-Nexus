"""WO-K5 — lead-driven work orders and coverage.

The director ranked families by **row count** and gave evidence orders to the top
`max_orders - 2`. That is the wrong signal twice over:

* volume is not value. `$MFT` on any real host has a million rows and rarely
  answers the question; prefetch holds a handful and often does.
* an order that says "family X has N rows" states no hypothesis, so the agent
  reads rows and summarises them. An examiner's order names what they think
  happened, what innocent explanation would look the same, and what would settle
  it.

So an order is built from a **lead** (WO-K3 / WO-K4) and carries its hypothesis,
its benign alternative, and the evidence that would refute it. Family order
follows artifact value, not volume.

`coverage_lines` is the other half: every family ends the run accounted for -
examined, by which lead sources - or named as not examined with the reason. A
family that silently never ran is the failure this prevents.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

#: Artifact value order (WO-K5). Earlier buckets are worked first because they
#: answer "what ran" and "how did it survive" before "what moved".
VALUE_BUCKETS: tuple[str, ...] = (
    "execution",
    "persistence",
    "logon_credential",
    "lateral",
    "network",
    "bulk_filesystem",
)

#: Real registry family names (measured against the 62 families the field
#: registry declares). A family with no entry ranks last rather than being
#: dropped - an unranked family must still be named in the coverage line.
FAMILY_BUCKET: dict[str, str] = {
    # execution
    "pecmd": "execution",
    "amcache": "execution",
    "appcompat": "execution",
    "hayabusa": "execution",
    "evtxecmd": "execution",
    "deepbluecli": "execution",
    "chainsaw": "execution",
    "zircolite": "execution",
    "capa": "execution",
    "yara": "execution",
    "densityscout": "execution",
    "suzaku": "execution",
    # persistence
    "tasks": "persistence",
    "recmd": "persistence",
    "sbecmd": "persistence",
    "jlecmd": "persistence",
    "lecmd": "persistence",
    "wxtcmd": "persistence",
    "usbdeview": "persistence",
    "ingest-windows_registry": "persistence",
    "ingest-windows_services": "persistence",
    "ingest-scheduled_tasks": "persistence",
    # logon / credential
    "srumecmd": "logon_credential",
    "sqlecmd": "logon_credential",
    "hindsight": "logon_credential",
    "ingest-auditd": "logon_credential",
    "ingest-authlog": "logon_credential",
    # lateral
    "tshark-flows": "lateral",
    "ingest-zeek": "lateral",
    "ingest-velociraptor": "lateral",
    # network
    "nfdump": "network",
    "ingest-suricata": "network",
    "ingest-netflow": "network",
    "ingest-wireshark": "network",
    "ingest-syslog": "network",
    # bulk filesystem
    "mftecmd": "bulk_filesystem",
    "mftecmd-i30": "bulk_filesystem",
    "mftecmd-usn": "bulk_filesystem",
    "fls": "bulk_filesystem",
    "mactime": "bulk_filesystem",
    "logfileparser": "bulk_filesystem",
    "rbcmd": "bulk_filesystem",
    "thumbcache": "bulk_filesystem",
    "plaso": "bulk_filesystem",
    "ingest-plaso": "bulk_filesystem",
    "vol": "bulk_filesystem",
    "ingest-volatility": "bulk_filesystem",
}

#: Families whose evidence is event-log shaped, so the rule engines cover them.
RULE_ENGINE_FAMILIES: frozenset[str] = frozenset({
    "hayabusa", "chainsaw", "evtxecmd", "deepbluecli", "zircolite", "suzaku",
})

#: Families the examiner toolkit's baseline checks can speak to.
BASELINE_FAMILIES: frozenset[str] = frozenset({
    "recmd", "pecmd", "amcache", "appcompat", "mftecmd", "tasks",
    "ingest-windows_registry", "ingest-windows_services", "ingest-scheduled_tasks",
    "yara", "lecmd", "jlecmd", "sbecmd",
})

#: Families the anomaly probes (rarity / ancestry / first-seen / burst) read.
ANOMALY_FAMILIES: frozenset[str] = frozenset({
    "evtxecmd", "hayabusa", "security", "sysmon", "prefetch", "pecmd", "amcache",
    "recmd", "tasks",
}) | RULE_ENGINE_FAMILIES

#: What an innocent explanation looks like per lead kind. An order that names no
#: benign alternative invites confirmation bias.
BENIGN_ALTERNATIVE: dict[str, str] = {
    "rarity": "genuine third-party software or a first-run artefact that simply is not in the baseline",
    "ancestry": "a legitimate parent for this application (an updater, a launcher, a shell the user opened)",
    "first_seen": "a new install, a first-time logon, or a service starting after a patch",
    "burst": "scheduled activity - a backup, a patch cycle, log rotation, or a bulk import",
    "rule_engine": "a rule that fired on benign activity; the rows decide, not the rule's name",
}

#: What would settle it, per lead kind.
REFUTATION: dict[str, str] = {
    "rarity": "the value in a known-good catalogue, or a change record naming who introduced it",
    "ancestry": "the baseline's valid_parents for this process including the observed parent",
    "first_seen": "the same value present before the evidence window",
    "burst": "a maintenance window or scheduled task covering that bucket",
    "rule_engine": "the same rows explained by a change record, and no follow-on behaviour in the surrounding window",
}


def bucket_of(family: str) -> str:
    """The artifact-value bucket for *family* ("" when unranked)."""
    return FAMILY_BUCKET.get(str(family or "").strip().lower(), "")


def family_value(family: str) -> int:
    """Sort key: lower is more valuable. Unranked families sort last."""
    bucket = bucket_of(family)
    if bucket in VALUE_BUCKETS:
        return VALUE_BUCKETS.index(bucket)
    return len(VALUE_BUCKETS)


def rank_families(families: Iterable[str]) -> list[str]:
    """Families by artifact value, then name.

    Deliberately takes no row counts: passing them would let volume creep back
    into the ordering, which is the defect this replaces.
    """
    unique = sorted({str(f) for f in families if str(f).strip()})
    return sorted(unique, key=lambda f: (family_value(f), f))


def _lead_dict(lead: Any) -> dict[str, Any]:
    if isinstance(lead, dict):
        return lead
    to_dict = getattr(lead, "to_dict", None)
    return to_dict() if callable(to_dict) else {}


def orders_from_leads(
    case_dir: Path | str,
    question: str,
    *,
    families: Iterable[str] | None = None,
    leads: list[Any] | None = None,
    max_orders: int = 6,
) -> list[dict[str, Any]]:
    """Evidence orders built from the strongest leads.

    Each order carries the hypothesis, its benign alternative, and what would
    refute it. When there are fewer leads than orders the remainder is filled
    from artifact value alone, so the run still covers the host.
    """
    case_dir = Path(case_dir)
    if leads is None:
        try:
            from nexus.analysis.leads import build_leads

            leads = build_leads(case_dir, write=False)
        except Exception as exc:  # noqa: BLE001 - the director must still plan
            log.warning("could not read leads for planning: %s", exc)
            leads = []

    known_families = {str(f) for f in (families or [])}
    ordered_leads = sorted(
        (_lead_dict(lead) for lead in leads or []),
        key=lambda d: (-float(d.get("score") or 0.0), str(d.get("kind") or "")),
    )

    orders: list[dict[str, Any]] = []
    seen_families: set[str] = set()
    for lead in ordered_leads:
        if len(orders) >= max_orders:
            break
        kind = str(lead.get("kind") or "lead")
        family = _family_for_lead(lead, known_families)
        hypothesis = _hypothesis(lead)
        orders.append({
            "role": "evidence",
            "lead_kind": kind,
            "family": family,
            "hypothesis": hypothesis,
            "benign_alternative": BENIGN_ALTERNATIVE.get(
                kind, "benign activity that resembles the pattern"),
            "refutation": REFUTATION.get(
                kind, "evidence that the pattern has an innocent explanation"),
            "evidence_rows": lead.get("rows") or [],
            "audit_ids": lead.get("audit_ids") or [],
            "score": float(lead.get("score") or 0.0),
            "task": (
                f"Test this hypothesis for the case question "
                f"{question or '(no examiner question)'}: {hypothesis}"
            ),
        })
        if family:
            seen_families.add(family)

    # Coverage remainder: families ranked by artifact value that no lead reached.
    for family in rank_families(known_families - seen_families):
        if len(orders) >= max_orders:
            break
        orders.append({
            "role": "evidence",
            "lead_kind": "coverage",
            "family": family,
            "hypothesis": f"No lead points at '{family}'; confirm it holds nothing of interest",
            "benign_alternative": "the family is ordinary host activity",
            "refutation": "a lead raised in a later round, or an artefact that disagrees",
            "evidence_rows": [],
            "audit_ids": [],
            "score": 0.0,
            "task": (
                f"Examine family '{family}' ({bucket_of(family) or 'unranked'}) "
                f"and state coverage for: {question or '(no examiner question)'}"
            ),
        })
    return orders


def _family_for_lead(lead: dict[str, Any], known: set[str]) -> str:
    """Which evidence family a lead belongs to.

    A rule-engine lead names its engine; an anomaly lead names the field it
    probed, which is not a family - so those fall back to the first known family
    whose concept the lead could have come from, or to "".
    """
    family = str(lead.get("family") or "").strip()
    if family in known:
        return family
    engine = str((lead.get("extra") or {}).get("engine") or "").strip()
    if engine and engine in known:
        return engine
    return family if family in known else ""


def _hypothesis(lead: dict[str, Any]) -> str:
    kind = str(lead.get("kind") or "lead")
    subject = str(lead.get("subject") or "").strip()
    detail = str(lead.get("detail") or "").strip()
    if kind == "rule_engine":
        return f"a detection rule fired: {detail or subject}"
    if kind == "ancestry":
        return f"process parentage disagrees with the baseline: {detail or subject}"
    if kind == "burst":
        return f"activity is concentrated in one window: {detail or subject}"
    if kind == "first_seen":
        return f"a value appears for the first time in this window: {detail or subject}"
    return detail or f"{kind}: {subject}"


def coverage_lines(
    case_dir: Path | str,
    families: Iterable[str],
    *,
    leads: list[Any] | None = None,
    rules_note: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """One line per family: the lead sources that ran, or why none could.

    Sources are the WO-K7 set: needles, rule engines, baselines, anomaly,
    analytics. A source counts only when it can actually apply to that family -
    claiming a rule engine examined a prefetch family would be a false coverage
    line, which is worse than an honest "not examined".
    """
    case_dir = Path(case_dir)
    if leads is None:
        try:
            from nexus.analysis.leads import read_leads

            leads = read_leads(case_dir)
        except Exception:  # noqa: BLE001
            leads = []
    lead_dicts = [_lead_dict(lead) for lead in leads or []]
    kinds = {str(d.get("kind") or "") for d in lead_dicts}
    rule_leads = [d for d in lead_dicts if str(d.get("kind")) == "rule_engine"]
    engines = {str((d.get("extra") or {}).get("engine") or d.get("family") or "")
               for d in rule_leads}

    try:
        from nexus.analysis.behavioural_analytics import analytics_for

        have_analytics = True
    except Exception:  # noqa: BLE001
        have_analytics = False

    if rules_note is None:
        try:
            from nexus.analysis.rule_leads import ruleset_note

            rules_note = ruleset_note(case_dir)
        except Exception:  # noqa: BLE001
            rules_note = {}

    out: list[dict[str, Any]] = []
    for family in rank_families(families):
        examined_by: list[str] = []
        reasons: list[str] = []

        # Needles: the briefing scan covers every indexed family.
        examined_by.append("needles")

        if family in RULE_ENGINE_FAMILIES:
            if family in engines and engines:
                examined_by.append("rule engines")
            elif rules_note.get("detections"):
                reasons.append(
                    "rule engines ran but produced no detection in this family")
            else:
                reasons.append("no rule-engine output in this case")
        else:
            reasons.append("rule engines do not read this family")

        if have_analytics:
            try:
                if analytics_for([family]):
                    examined_by.append("analytics")
                else:
                    reasons.append("no behavioural analytic claims this family")
            except Exception:  # noqa: BLE001
                reasons.append("analytics pack unavailable")
        else:
            reasons.append("analytics pack unavailable")

        if family in ANOMALY_FAMILIES:
            examined_by.append("anomaly")
        else:
            reasons.append("no anomaly probe reads this family")

        if family in BASELINE_FAMILIES:
            examined_by.append("baselines")
        else:
            reasons.append("no baseline check applies to this family")

        if {"rarity", "ancestry", "first_seen", "burst"} & kinds and family in ANOMALY_FAMILIES:
            pass  # already counted; kept for readability of the intent

        out.append({
            "family": family,
            "bucket": bucket_of(family) or "unranked",
            "examined": bool(examined_by),
            "examined_by": examined_by,
            "not_examined": [] if examined_by == ["needles"] else reasons,
            "summary": (
                f"{family}: examined by {', '.join(examined_by)}"
                if examined_by else f"{family}: not examined"
            ),
        })
    return out


def coverage_summary(lines: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts for the run record and the report."""
    examined = [line for line in lines if line.get("examined")]
    return {
        "families": len(lines),
        "examined": len(examined),
        "not_examined": len(lines) - len(examined),
        "sources_used": sorted({s for line in lines for s in line.get("examined_by") or []}),
    }
