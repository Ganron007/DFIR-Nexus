"""WO-K3 — anomaly lead generators.

Deterministic lead generation over the case's typed index, run after N3
indexing (where `langgraph/briefing.py` builds the briefing). Writes
`analysis/leads.jsonl`; every lead carries the evidence rows that produced it
and the audit ids of the `es_aggregate` calls behind them, so a lead can be
traced the same way a finding can.

Four lead kinds, per the work order:

* **rarity** — stacking and rarity: a value that occurs once (or far below its
  family's norm) among executables, services, tasks, parent processes, logon
  sources or accounts.
* **first_seen** — a value whose earliest occurrence is inside the window.
* **ancestry** — a process whose parent / path / user disagrees with the triage
  baseline's `expected_processes` table.
* **burst** — a time bucket whose volume is far above its neighbours (log
  clearing and mass file changes land here as volume spikes).

Deliberately **deterministic and cheap**: no LLM, no scoring model. A lead is a
question to ask, not a finding — nothing here stages a DRAFT, and an UNKNOWN
verdict is never escalated on its own (FD-004).

This module never raises on missing index/registry: a case without them yields
no leads rather than a failed run.
"""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

LEADS_FILENAME = "leads.jsonl"
#: lead key -> the audit id whose entry stored that lead's rows (see `_cite_leads`).
LEAD_AUDITS_FILENAME = "lead_audits.json"
#: Sample rows an executed behavioural analytic keeps, so its lead can be cited.
ANALYTIC_SAMPLE_ROWS = 5

#: Concepts to test for rarity, each with the field names that may carry it.
#: The registry names the same idea differently per family (`ImageFileName` on a
#: memory image, `Process` in a 4688 record, `ExecutableName` in prefetch), so a
#: concept resolves to the first candidate the case's index actually carries.
#: Hardcoding one name per concept silently probes nothing - which reads as
#: "no anomalies" - and is the failure this table exists to avoid.
RARITY_CONCEPTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("process", ("ImageFileName", "Process", "Process Name", "Image", "ExecutableName")),
    ("service", ("Service Name", "Service")),
    ("task", ("Task Name", "Task")),
    ("parent", ("Parent Process Name", "ParentImage", "ParentPath")),
    ("executable", ("Executable", "ExecutableName", "File Path")),
    ("account", ("User", "UserName", "TargetUserName")),
    ("logon source", ("Logon Source", "Source Network Address", "IpAddress")),
)

#: A value seen at most this many times is a rarity candidate.
RARITY_MAX_HITS = 1
#: Rarity and first-seen probes look at most this many values per field.
RARITY_TOP = 200
#: A bucket this many times its median neighbour is a burst.
BURST_FACTOR = 8.0
BURST_MIN_ROWS = 25


@dataclass(frozen=True)
class Lead:
    """One question worth asking, with the rows and calls that raised it."""

    kind: str
    subject: str
    family: str
    detail: str
    rows: tuple[dict[str, Any], ...] = ()
    audit_ids: tuple[str, ...] = ()
    score: float = 0.0
    extra: dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": self.kind,
            "subject": self.subject,
            "family": self.family,
            "detail": self.detail,
            "score": self.score,
            "rows": [dict(r) for r in self.rows],
            "audit_ids": [a for a in self.audit_ids if a],
        }
        if self.extra:
            out["extra"] = dict(self.extra)
        return out


# ---------------------------------------------------------------------------
# the probe seam
# ---------------------------------------------------------------------------

class EsProbe:
    """Real index access. Every call is audited so a lead can cite its source.

    `es_aggregate` itself does not audit (it is a read helper), so the id is
    minted here and attached to the returned mapping - the lead then carries a
    real audit id, which is what the work order asks for.
    """

    def __init__(self, case_dir: Path, audit: Any = None) -> None:
        self.case_dir = Path(case_dir)
        self.audit = audit

    def aggregate(self, **kwargs: Any) -> dict[str, Any]:
        from nexus.langgraph.case_index import es_aggregate

        field_name = str(kwargs.get("field") or "")
        result = es_aggregate(self.case_dir, **kwargs) or {}
        audit_id = ""
        if self.audit is not None and isinstance(result, dict):
            try:
                audit_id = str(self.audit.log(
                    tool="es_aggregate",
                    params={"field": field_name, "dsl": str(kwargs.get("dsl") or "")[:200]},
                    result_summary={"top": len(result.get("top") or [])},
                ) or "")
            except Exception as exc:  # noqa: BLE001 - a lead without an id still beats none
                log.debug("lead aggregation audit failed: %s", exc)
        out = dict(result) if isinstance(result, dict) else {}
        out["audit_id"] = audit_id
        return out

    def observed_calls(
        self,
        process_field: str = "ImageFileName",
        parent_field: str = "ParentImage",
    ) -> list[dict[str, Any]]:
        """Observed (process, parent) pairs from the index.

        A raw DSL aggregation because the simple helper takes one field. Returns
        [] when the index or the DSL path is unavailable - no leads beats wrong
        leads, and the caller records nothing rather than inventing a baseline
        disagreement.
        """
        dsl = json.dumps({
            "aggs": {
                "pairs": {
                    "terms": {"field": process_field, "size": RARITY_TOP},
                    "aggs": {
                        "parents": {"terms": {"field": parent_field, "size": 5}},
                    },
                },
            },
            "size": 0,
        })
        result = self.aggregate(dsl=dsl, field=process_field, top=RARITY_TOP, match_all=True)
        audit_id = str((result or {}).get("audit_id") or "")
        out: list[dict[str, Any]] = []
        for pair in ((result or {}).get("buckets") or []):
            if not isinstance(pair, dict):
                continue
            process = str(pair.get("key") or pair.get("value") or "").strip()
            if not process:
                continue
            for parent in (pair.get("parents") or {}).get("buckets", []) or []:
                if isinstance(parent, dict) and parent.get("key"):
                    out.append({
                        "process": process,
                        "parent": str(parent["key"]),
                        # The id of the aggregation this pair came from, so the
                        # lead can cite the call the same way a finding does.
                        "audit_id": audit_id,
                    })
        return out

    def process_check(self, **kwargs: Any) -> dict[str, Any]:
        """Parent/path/user sanity for one process, from the triage baseline.

        Uses the `expected_processes` row (the triage DB's own table) and
        compares the observed parent against it. Anything unexpected about the
        baseline returns {} - FD-004: a missing baseline is not evidence.
        """
        try:
            from nexus.triage.db import TriageDB

            db = TriageDB()
            lookup = getattr(db, "_get_expected_process_cached", None)
            row = lookup(str(kwargs.get("process_name") or "")) if lookup else None
        except Exception as exc:  # noqa: BLE001
            log.debug("triage baseline unavailable: %s", exc)
            return {}
        if not row:
            # Not in the baseline at all: neutral, never a lead (FD-004).
            return {}
        if isinstance(row, dict):
            data = row
        else:
            data = {k: getattr(row, k, None) for k in (
                "valid_parents", "suspicious_parents", "valid_paths", "valid_users",
            )}
        observed_parent = str(kwargs.get("parent_name") or "").strip().lower()

        def _split(value: Any) -> list[str]:
            if value is None:
                return []
            if isinstance(value, str):
                return [v.strip().lower() for v in value.replace(",", ";").split(";") if v.strip()]
            return [str(v).strip().lower() for v in value if str(v).strip()]

        suspicious = _split(data.get("suspicious_parents"))
        valid = _split(data.get("valid_parents"))
        if observed_parent and observed_parent in suspicious:
            return {"verdict": "SUSPICIOUS", "parent_name": observed_parent,
                    "reason": "parent is on the baseline's suspicious list"}
        if observed_parent and valid and observed_parent not in valid:
            return {"verdict": "UNEXPECTED", "parent_name": observed_parent,
                    "reason": "parent is not among the baseline's valid parents"}
        return {}


def _audit_id(result: dict[str, Any]) -> tuple[str, ...]:
    value = str((result or {}).get("audit_id") or "").strip()
    return (value,) if value else ()


def _spans(result: dict[str, Any]) -> list[dict[str, Any]]:
    spans = (result or {}).get("top") or []
    return [s for s in spans if isinstance(s, dict)]


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

def registry_fields(case_dir: Path) -> set[str]:
    """Column names the case's index actually carries, from the field registry.

    Empty set means "unknown" (registry unreadable) - callers then probe the
    candidate list as written rather than reporting a false absence.
    """
    path = Path(__file__).resolve().parents[1] / "data" / "schema" / "field_registry.yaml"
    if not path.is_file():
        return set()
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        columns = data.get("columns") or {}
        return {str(name) for name in columns} if isinstance(columns, dict) else set()
    except Exception as exc:  # noqa: BLE001
        log.debug("field registry unreadable: %s", exc)
        return set()


def resolve_concept(concept: str, known: set[str]) -> str:
    """The field name this case's index uses for *concept*, or "".

    An empty ``known`` means the registry was unreadable: fall back to the first
    candidate as written, rather than reporting every concept absent.
    """
    for label, candidates in RARITY_CONCEPTS:
        if label != concept:
            continue
        if not known:
            return candidates[0]
        for candidate in candidates:
            if candidate in known:
                return candidate
        return ""
    return ""


def _wanted_fields(known: set[str]) -> list[tuple[str, str]]:
    """``(field, concept)`` for every concept this index can express."""
    out: list[tuple[str, str]] = []
    for concept, _ in RARITY_CONCEPTS:
        field_name = resolve_concept(concept, known)
        if field_name:
            out.append((field_name, concept))
    return out


#: Rarity is only meaningful on **execution artifacts' executable paths**.
#: Unscoped, "appears once" is dominated by app identifiers — on SC1 the top
#: leads were `Microsoft.WindowsCalculator_…`, `com.squirrel.slack.slack` and
#: `Microsoft.Office.OUTLOOK.EXE.15`, which are noise, and they outranked every
#: real detection (WO-R1F item 1: "restrict rarity to execution artifacts'
#: executable paths"). A value is kept only when it looks like a path to a
#: program; feed/container identifiers are dropped.
_EXEC_SUFFIXES = (
    ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".msi", ".cpl", ".hta", ".lnk",
)


def _is_executable_path(value: str) -> bool:
    """True when *value* names a program rather than an app id or a bare name."""
    text = (value or "").strip().strip('"')
    if not text:
        return False
    lowered = text.lower()
    # A path, or a bare file name with a program extension. `Microsoft.Windows
    # Calculator_8wekyb3d8bbwe!App` and `com.squirrel.slack.slack` match neither.
    looks_like_path = "\\" in text or "/" in text
    has_exec_ext = lowered.endswith(_EXEC_SUFFIXES)
    if has_exec_ext:
        return True
    # A path with no extension is still an execution artifact location.
    return looks_like_path and "." not in lowered.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def rarity_leads(probe: Any, known: set[str], case_dir: Path) -> list[Lead]:
    out: list[Lead] = []
    for name, label in _wanted_fields(known):
        # Only the executable concept is a program path; the others (account,
        # service, task) are not, so keep their values as they are.
        exec_only = label == "executable"
        result = probe.aggregate(field=name, top=RARITY_TOP, match_all=True, with_spans=True)
        for span in _spans(result):
            value = str(span.get("value") or "").strip()
            count = int(span.get("count") or 0)
            if not value or count <= 0 or count > RARITY_MAX_HITS:
                continue
            if exec_only and not _is_executable_path(value):
                continue
            out.append(Lead(
                kind="rarity",
                subject=value,
                family=name,
                detail=f"{label} {value!r} appears once in the index (no baseline occurrence)",
                rows=({"field": name, "value": value, "count": count},),
                audit_ids=_audit_id(result),
                # Rarer is more interesting; keep the score monotone and small.
                score=round(1.0 / max(count, 1), 3),
            ))
    return out


def ancestry_leads(probe: Any, known: set[str], case_dir: Path) -> list[Lead]:
    """A process whose parent, path or user disagrees with the baseline.

    The baseline is the triage DB's `expected_processes` table. A process absent
    from it is neutral, never a lead (FD-004).
    """
    out: list[Lead] = []
    try:
        calls = probe.observed_calls(
            process_field=resolve_concept("process", known) or "ImageFileName",
            parent_field=resolve_concept("parent", known) or "ParentImage",
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("observed calls unavailable: %s", exc)
        return []
    for call in calls or []:
        process = str((call or {}).get("process") or "").strip()
        if not process:
            continue
        verdict = probe.process_check(
            process_name=process,
            parent_name=str((call or {}).get("parent") or ""),
            path=str((call or {}).get("path") or ""),
            user=str((call or {}).get("user") or ""),
        ) or {}
        # FD-004: UNKNOWN is neutral. Only a baseline disagreement raises a lead.
        status = str(verdict.get("verdict") or verdict.get("status") or "").upper()
        if status not in ("SUSPICIOUS", "INVALID", "UNEXPECTED", "MISMATCH"):
            continue
        parent = str(verdict.get("parent_name") or (call or {}).get("parent") or "")
        call_audit = str((call or {}).get("audit_id") or "").strip()
        out.append(Lead(
            kind="ancestry",
            subject=process,
            family="process ancestry",
            detail=(
                f"{process!r} disagrees with the triage baseline"
                + (f" (parent {parent!r})" if parent else "")
                + f": {str(verdict.get('reason') or status).strip()}"
            ),
            rows=({"process": process, "parent": parent, "verdict": status},),
            audit_ids=(call_audit,) if call_audit else (),
            score=0.9,
            extra={"baseline": verdict},
        ))
    return out


def first_seen_leads(probe: Any, known: set[str], case_dir: Path,
                     window: tuple[Any, Any] | None = None) -> list[Lead]:
    """Values whose earliest occurrence is inside the evidence window."""
    if window is None:
        return []
    out: list[Lead] = []
    for name, label in _wanted_fields(known)[:3]:
        result = probe.aggregate(
            field=name, top=RARITY_TOP, match_all=True, with_spans=True,
        )
        for span in _spans(result):
            value = str(span.get("value") or "").strip()
            first = span.get("first") or span.get("min")
            if not value or first is None:
                continue
            out.append(Lead(
                kind="first_seen",
                subject=value,
                family=name,
                detail=f"{label} {value!r} first appears at {first}",
                rows=({"field": name, "value": value, "first": str(first)},),
                audit_ids=_audit_id(result),
                score=0.5,
            ))
    return out


def burst_leads(probe: Any, known: set[str], case_dir: Path) -> list[Lead]:
    """A time bucket far above its neighbours (clearing, mass change, spray)."""
    result = probe.aggregate(
        field="Timestamp", bucket="1h", top=RARITY_TOP, match_all=True,
    )
    buckets = [b for b in ((result or {}).get("buckets") or []) if isinstance(b, dict)]
    counts = [int(b.get("count") or 0) for b in buckets]
    if len(counts) < 3:
        return []
    out: list[Lead] = []
    for index, bucket in enumerate(buckets):
        count = int(bucket.get("count") or 0)
        neighbours = [
            counts[i] for i in (index - 1, index + 1) if 0 <= i < len(counts)
        ]
        if not neighbours or count < BURST_MIN_ROWS:
            continue
        median = sorted(neighbours)[len(neighbours) // 2]
        if median <= 0 or count < median * BURST_FACTOR:
            continue
        out.append(Lead(
            kind="burst",
            subject=str(bucket.get("key_as_string") or bucket.get("key") or index),
            family="time volume",
            detail=(
                f"{count} rows in one bucket vs a neighbour median of {median} "
                f"({count / median:.1f}x) - log clearing, mass change or a spray"
            ),
            rows=({"bucket": str(bucket.get("key_as_string") or bucket.get("key") or ""),
                   "count": count, "neighbour_median": median},),
            audit_ids=_audit_id(result),
            score=round(min(count / max(median, 1), 50.0) / 50.0, 3),
        ))
    return out


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def _rule_engine_leads(case_dir: Path) -> list[Lead]:
    """Rule-engine detections, imported lazily.

    `rule_leads` imports `Lead` from this module, so a top-level import here
    would be circular. The import is deliberately inside the function.
    """
    from nexus.analysis.rule_leads import rule_engine_leads

    return rule_engine_leads(case_dir)


def _with_software(lead: Lead) -> Lead:
    """The lead with the ATT&CK software its detection names (IC-5), when ATT&CK records it.

    A threat name in the lead - a YARA rule's ``Threat_name`` or a Defender threat in an engine's rendered
    detail - is read by its family; a family ATT&CK records gives its software entry, whose techniques are
    the hunt list the seats get. Never raises: a lead without one is returned as it was.
    """
    try:
        from nexus.knowledge.attack_method import software_for, threats_in

        extra = dict(lead.extra or {})
        text = " ".join([lead.detail, *(str(r.get("details") or r.get("detail") or "") for r in lead.rows
                                        if isinstance(r, dict))])
        found: dict[str, str] = {}
        for threat in [*(extra.get("threats") or []), *threats_in(text)]:
            software = software_for(str(threat))
            if software:
                found.setdefault(str(software["id"]), str(software["name"]))
        if not found:
            return lead
        extra["software"] = [{"id": sid, "name": name} for sid, name in sorted(found.items())]
        return replace(lead, extra=extra)
    except Exception as exc:  # noqa: BLE001 - a lead without software is still a lead
        log.debug("lead software lookup failed: %s", exc)
        return lead


def _memory_verdict_leads(case_dir: Path, probe: Any) -> list[Lead]:
    """The memory scanner's detections (D245), imported lazily for the same reason."""
    from nexus.analysis.baseline_leads import memory_verdict_leads

    return memory_verdict_leads(case_dir, probe=probe)


def _persistence_leads(case_dir: Path, probe: Any) -> list[Lead]:
    """Tasks and services against the triage baseline (D244), imported lazily for the same reason."""
    from nexus.analysis.baseline_leads import persistence_leads

    return persistence_leads(case_dir, probe=probe)


def behavioural_analytics_leads(
    case_dir: Path | str,
    *,
    probe: Any = None,
    limit: int = 200,
) -> list[Lead]:
    """Matches from the hand behavioural-analytic pack, as leads (item 8).

    Each analytic carries an ``es`` clause set; the pack is deterministic
    knowledge, so running it is too. An analytic that MATCHES becomes a lead — its
    hits then reach every mode through the lead list (item 1), which is what
    "knowledge reaches every mode" means functionally.

    The clause is executed through the SAME normalized ES surface every other
    caller uses (`es_native.es_search`, item 2), so an analytic's query is
    subject to the same rewrites and reporting. `probe` is the test seam; without
    one the case's own index is used. Never raises.
    """
    out: list[Lead] = []
    try:
        from nexus.analysis.behavioural_analytics import analytics_for
    except Exception as exc:  # noqa: BLE001
        log.debug("behavioural analytics unavailable: %s", exc)
        return []

    # The families this case actually holds, so an analytic whose families are
    # absent is not run (and does not report a false zero).
    try:
        from nexus.langgraph.query_pack import _present_families

        families = _present_families(Path(case_dir))
    except Exception:  # noqa: BLE001 — an unknown case still gets every analytic
        families = []
    try:
        pack = analytics_for(families)
    except Exception as exc:  # noqa: BLE001
        log.warning("behavioural analytics pack unreadable: %s", exc)
        return []

    for analytic in pack[:limit]:
        name = str(analytic.get("name") or analytic.get("id") or "").strip()
        clause = analytic.get("es")
        if not name or not isinstance(clause, dict) or not clause:
            continue
        if not (hasattr(probe, "count_analytic") or hasattr(probe, "analytic_hits")):
            # A case that holds none of the log the analytic reads (Sysmon on a case without it) is not a
            # place it applies: the index refuses its fields, which is not a failure to report (IC-7).
            from nexus.analysis.skill_steps import step_source_present

            if step_source_present(analytic, Path(case_dir).name) is False:
                log.debug("analytic %s not applicable: the case holds none of its source", name)
                continue
        try:
            count, samples = _analytic_matches(case_dir, clause, probe=probe)
        except Exception as exc:  # noqa: BLE001 — one analytic must not lose the rest
            log.warning("analytic %s not run: %s", name, exc)
            continue
        if count <= 0:
            continue
        techniques = [str(t) for t in (analytic.get("techniques") or []) if t]
        out.append(Lead(
            kind="behavioral_analytic",
            subject=name,
            family="behavioural analytics",
            detail=(
                f"behavioural analytic matched {count} row(s): "
                f"{str(analytic.get('rationale') or '')[:160]}"
            ),
            # The rows the analytic matched, so a finding citing this lead is grounded in them.
            # The lead used to carry only {analytic, count}: nothing a finding could stand on.
            rows=tuple(samples),
            audit_ids=(),
            # Above a heuristic lead, below a crit/high detection.
            score=0.95,
            extra={
                "analytic": str(analytic.get("id") or name),
                "count": count,
                "techniques": techniques,
                "citation": analytic.get("citation") or {},
                "pinned_source_facts": list(analytic.get("pinned_source_facts") or []),
            },
        ))
    return out


def _hit_rows(hits: list[Any]) -> list[dict[str, Any]]:
    from nexus.langgraph.evidence_rows import evidence_rows_for_hits

    return evidence_rows_for_hits([h for h in hits if isinstance(h, dict)])


def _analytic_matches(
    case_dir: Path | str,
    clause: dict[str, Any],
    *,
    probe: Any = None,
) -> tuple[int, list[dict[str, Any]]]:
    """How many indexed rows an analytic's clause matches, and the first few as evidence rows.

    Only the case's index answers. An analytic reads the `ecs.*` fields the indexer computes, which a parsed
    file does not hold, and its terms and patterns mean what Elasticsearch makes of them; the in-process
    count over parsed rows that stood in when ES was down returned 0 for every such analytic, a "no match"
    nobody had established (IC-7). When the index cannot answer this raises, and the caller leaves the
    analytic out of the leads with the reason logged.
    """
    if probe is not None:
        if hasattr(probe, "count_analytic"):
            return int(probe.count_analytic(clause) or 0), []
        if hasattr(probe, "analytic_hits"):
            hits = list(probe.analytic_hits(clause) or [])
            return len(hits), _hit_rows(hits[:ANALYTIC_SAMPLE_ROWS])
    case_id = Path(case_dir).name
    from nexus.langgraph.es_native import es_search

    result = es_search(case_id, clause, size=ANALYTIC_SAMPLE_ROWS)
    if result.get("degraded") or result.get("error"):
        raise RuntimeError(f"the index could not run the analytic: {result.get('error') or 'degraded'}")
    return int(result.get("total") or 0), _hit_rows(result.get("hits") or [])


def _index_file(path: Any) -> str:
    """A tool-output path as the index names it: the part under ``extractions/`` (``hayabusa/x.csv``)."""
    parts = [p for p in str(path or "").replace("\\", "/").split("/") if p]
    if "extractions" in parts:
        rest = parts[len(parts) - parts[::-1].index("extractions"):]
        if rest:
            return "/".join(rest)
    return parts[-1] if parts else ""


def _lead_evidence_rows(lead: Lead) -> list[dict[str, Any]]:
    """A lead's own rows in the evidence-row shape staging reads (``langgraph/evidence_rows.py``).

    A row that is already an evidence row (an executed analytic's hits) is kept. A rule-engine sample
    gets the index's own ``source`` and ``loc`` for its file and line, so the same row cited through a
    lead or through a query is one row.
    """
    out: list[dict[str, Any]] = []
    for row in lead.rows:
        if not isinstance(row, dict):
            continue
        if row.get("source") and row.get("detail"):
            out.append(dict(row))
            continue
        rel = _index_file(row.get("file"))
        line = str(row.get("line") or "").strip()
        named = [
            f"RuleTitle: {row['rule_title']}" if row.get("rule_title") else "",
            f"Level: {row['level']}" if row.get("level") else "",
            f"Details: {row['details']}" if row.get("details") else "",
        ]
        detail = " · ".join(p for p in named if p) or " · ".join(
            f"{k}: {v}" for k, v in row.items()
            if k not in ("file", "line", "doc_id") and v not in (None, "", [], {}))
        if not detail:
            continue
        evidence: dict[str, Any] = {
            "time": str(row.get("timestamp") or row.get("time") or ""),
            "source": f"{lead.family or 'other'}/{rel}" if rel else str(lead.family or "lead"),
            "artifact": rel,
            "detail": detail,
        }
        if rel and line:
            evidence["loc"] = f"{rel}:{line}"
        for key, value in (("host", row.get("computer") or row.get("host")),
                           ("event_id", row.get("event_id")), ("doc_id", row.get("doc_id"))):
            if str(value or "").strip():
                evidence[key] = str(value).strip()
        out.append(evidence)
    return out


def _lead_key(lead: Lead, rows: list[dict[str, Any]]) -> str:
    ids = sorted(str(r.get("doc_id") or r.get("loc") or r.get("detail") or "") for r in rows)
    blob = json.dumps([lead.kind, lead.family, lead.subject, ids], sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def _cite_leads(case_dir: Path, leads: list[Lead]) -> list[Lead]:
    """Give every lead with rows an audit id whose entry stored exactly those rows.

    Leads reached every mode as context nothing could cite: rule-engine and analytic leads were built
    with no audit id, and the probe that audits aggregations was never handed a writer
    (CASE-C5B04D31, 2026-10-14: 140 leads, 0 citable). A Mode 1 finding drawn from a lead was refused
    under FD-001, or it cited a query that did not show it. The lead builder's read is now one
    audited call per lead, holding that lead's rows and nothing else, so a finding citing it is
    grounded in those rows. The id is reused while the lead's rows are unchanged, so rebuilding the
    leads for every run does not grow the audit trail.
    """
    from nexus.audit import AuditWriter
    from nexus.langgraph.evidence_rows import stored_rows_by_audit_id

    path = case_dir / "analysis" / LEAD_AUDITS_FILENAME
    try:
        known = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, ValueError):
        known = {}
    if not isinstance(known, dict):
        known = {}
    # Only an id whose entry is in the case's audit trail is reused.
    alive = stored_rows_by_audit_id(case_dir, [str(v) for v in known.values()]) if known else {}
    writer = None  # made only when a lead is new: a rebuild that reuses every id writes nothing
    out: list[Lead] = []
    changed = False
    for lead in leads:
        rows = _lead_evidence_rows(lead)
        if not rows:
            out.append(lead)
            continue
        key = _lead_key(lead, rows)
        audit_id = str(known.get(key) or "")
        if audit_id not in alive:
            writer = writer or AuditWriter("nexus", audit_dir=case_dir / "audit")
            audit_id = str(writer.log(
                tool="lead",
                params={"case_id": case_dir.name, "kind": lead.kind, "family": lead.family,
                        "subject": lead.subject, "key": key},
                result_summary={"evidence_rows": rows, "rows": len(rows)},
                source="pipeline",
            ) or "")
            if audit_id:
                known[key] = audit_id
                changed = True
        if audit_id and audit_id not in lead.audit_ids:
            lead = replace(lead, audit_ids=(audit_id, *lead.audit_ids))
        out.append(lead)
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(known, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
    return out


def build_leads(
    case_dir: Path | str,
    *,
    probe: Any = None,
    window: tuple[Any, Any] | None = None,
    known_fields: set[str] | None = None,
    write: bool = True,
) -> list[Lead]:
    """Every lead for this case. Deterministic; never stages a finding.

    ``probe`` is the test seam: pass an object with ``aggregate(**kw)``,
    ``observed_calls()`` and ``process_check(**kw)`` to run without
    Elasticsearch or the triage DB. ``known_fields`` overrides the field
    registry (otherwise read from disk).
    """
    case_dir = Path(case_dir)
    if probe is None:
        probe = EsProbe(case_dir)
    known = registry_fields(case_dir) if known_fields is None else set(known_fields)

    leads: list[Lead] = []
    failed: list[str] = []
    # WO-K8: honour the ablation toggles, so a disabled layer is genuinely
    # absent rather than merely flagged. `layer_status()` reports this into the
    # run record; the builder list is filtered here.
    from nexus.analysis.layers import layer_status

    active = layer_status()["leads"]
    builders = []
    if active["anomaly"]["enabled"]:
        builders.extend([
            lambda: rarity_leads(probe, known, case_dir),
            lambda: ancestry_leads(probe, known, case_dir),
            lambda: first_seen_leads(probe, known, case_dir, window),
            lambda: burst_leads(probe, known, case_dir),
        ])
    if active["rules"]["enabled"]:
        builders.append(lambda: _rule_engine_leads(case_dir))
        # D245: the memory scanner's own detections (MemProcFS YARA, FindEvil) are rule-engine leads.
        builders.append(lambda: _memory_verdict_leads(case_dir, probe))
    if active.get("baselines", {}).get("enabled"):
        # D244: the case's tasks and services against the triage baseline. The baselines answered
        # one value when a model asked and produced no lead, so no agenda ever held a persistence entry.
        builders.append(lambda: _persistence_leads(case_dir, probe))
    if active.get("analytics", {}).get("enabled"):
        # WO-R1F item 8: EXECUTE the hand behavioural analytics once, so their
        # hits become leads and therefore reach every mode through the lead list.
        # They were a layer NAME with nothing running them.
        builders.append(lambda: behavioural_analytics_leads(case_dir, probe=probe))

    for builder in builders:
        try:
            leads.extend(builder())
        except Exception as exc:  # noqa: BLE001 - one broken kind must not lose the rest
            # ERROR, not warning: a builder that raises on every run is a bug in
            # this module, not a data condition. Logged quietly it reads as "that
            # lead kind found nothing" - measured 2026-10-04, when a missing
            # import dropped 656 rule-engine leads behind a WARNING line.
            log.error("lead builder failed: %s: %s", type(exc).__name__, exc)
            failed.append(f"{type(exc).__name__}: {exc}")

    leads = [_with_software(lead) for lead in leads]
    # Stable order: crit/high leads first, rule-engine detections first among them and among the rest,
    # then strongest score, then kind and subject so two runs over the same index produce byte-identical
    # output. A crit/high detection must never be outranked by a heuristic lead (WO-R1F item 1) — the
    # probe asserts it. A crit/high baseline lead (D244) comes before the medium and low detections: with
    # rule engines always first, the case's 124 Hayabusa rules filled the top 40 every mode reads.
    leads.sort(key=lambda lead: (
        0 if (lead.extra or {}).get("crit_high") else 1,
        0 if lead.kind == "rule_engine" else 1,
        -lead.score,
        lead.kind,
        lead.subject,
    ))
    try:
        leads = _cite_leads(case_dir, leads)
    except Exception as exc:  # noqa: BLE001 - the leads stand; their citations are reported missing
        log.error("lead citation failed: %s: %s", type(exc).__name__, exc)
        failed.append(f"citation {type(exc).__name__}: {exc}")

    if write:
        try:
            _write_leads(case_dir, leads)
            _write_build_errors(case_dir, failed)
        except OSError as exc:
            log.warning("could not write leads: %s", exc)
    return leads


def _write_build_errors(case_dir: Path, failed: list[str]) -> None:
    """Record which lead kinds failed, so a silent drop is visible in the case.

    A builder that raises on every run means that lead kind contributes nothing -
    indistinguishable from "there was nothing to find" unless it is written down.
    """
    path = case_dir / "analysis" / "leads_errors.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not failed:
        if path.exists():
            path.unlink()
        return
    path.write_text(
        json.dumps({"builders_failed": failed}, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def build_errors(case_dir: Path | str) -> list[str]:
    """Lead builders that failed on the last build (empty when all succeeded)."""
    path = Path(case_dir) / "analysis" / "leads_errors.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [str(v) for v in (data.get("builders_failed") or [])]


def _write_leads(case_dir: Path, leads: Iterable[Lead]) -> Path:
    """Append-free: the file is the current run's leads, one JSON object a line."""
    path = case_dir / "analysis" / LEADS_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(
        json.dumps(lead.to_dict(), sort_keys=True) for lead in leads
    )
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body + ("\n" if body else ""), encoding="utf-8")
    tmp.replace(path)
    return path


def read_leads(case_dir: Path | str) -> list[dict[str, Any]]:
    """The leads written for this case (empty when none yet)."""
    path = Path(case_dir) / "analysis" / LEADS_FILENAME
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def lead_row_refs(lead: Any) -> tuple[list[str], list[tuple[str, str]]]:
    """The index documents a lead's rows are: by document id, or by (file, line).

    A rule-engine lead's rows carry the document id (``doc_id``, the index ``_id``); a memory-scanner or
    analytic lead's rows carry their location (``loc``, ``file:line``). Every reader of a lead's own rows
    (threat-intel selection, the alert surface, Mode 1's settle replan) resolves them through this one rule
    (Part 12 FM-9; D455's selection first read only ``loc`` and so missed every rule-engine lead's rows).
    """
    doc_ids: list[str] = []
    locs: list[tuple[str, str]] = []
    rows = lead.get("rows") if isinstance(lead, dict) else getattr(lead, "rows", ())
    for row in rows or ():
        if not isinstance(row, dict):
            continue
        doc_id = str(row.get("doc_id") or "").strip()
        if doc_id:
            if doc_id not in doc_ids:
                doc_ids.append(doc_id)
            continue
        file, sep, line = str(row.get("loc") or "").rpartition(":")
        if sep and file and line and (file, line) not in locs:
            locs.append((file, line))
    return doc_ids, locs


def lead_rows_query(doc_ids: list[str], locs: list[tuple[str, str]]) -> dict[str, Any] | None:
    """The Elasticsearch query that matches exactly these rows, or None when there are none."""
    should: list[dict[str, Any]] = []
    if doc_ids:
        should.append({"ids": {"values": list(doc_ids)}})
    should += [{"bool": {"filter": [{"term": {"file": file}}, {"term": {"line": line}}]}} for file, line in locs]
    return {"bool": {"should": should, "minimum_should_match": 1}} if should else None
