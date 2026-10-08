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

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

LEADS_FILENAME = "leads.jsonl"

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
        try:
            count = _analytic_match_count(case_dir, clause, probe=probe)
        except Exception as exc:  # noqa: BLE001 — one analytic must not lose the rest
            log.debug("analytic %s failed: %s", name, exc)
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
            rows=({"analytic": str(analytic.get("id") or name), "count": count,
                   "techniques": techniques},),
            audit_ids=(),
            # Above a heuristic lead, below a crit/high detection.
            score=0.95,
            extra={
                "analytic": str(analytic.get("id") or name),
                "count": count,
                "techniques": techniques,
                "citation": analytic.get("citation") or {},
            },
        ))
    return out


def _analytic_match_count(
    case_dir: Path | str,
    clause: dict[str, Any],
    *,
    probe: Any = None,
) -> int:
    """How many indexed rows an analytic's clause matches.

    Prefers the case's ES index (exact total, no scan); falls back to counting
    over the parsed rows the case already holds when ES is not available, so an
    unindexed case still gets analytics rather than silence.
    """
    if probe is not None:
        if hasattr(probe, "count_analytic"):
            return int(probe.count_analytic(clause) or 0)
        if hasattr(probe, "analytic_hits"):
            return len(probe.analytic_hits(clause) or [])
    case_id = Path(case_dir).name
    try:
        from nexus.langgraph.es_native import es_search

        result = es_search(case_id, clause, size=1)
        if result.get("degraded"):
            return 0
        return int(result.get("total") or 0)
    except Exception:  # noqa: BLE001 — ES down: count over the case's own rows
        return _count_analytic_csv(Path(case_dir), clause)


def _count_analytic_csv(case_dir: Path, clause: dict[str, Any]) -> int:
    """Count an analytic's matches over the case's own parsed rows."""
    import json

    from nexus.analysis.behavioural_analytics import matches_record
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    total = 0
    base = resolve_tools_extractions(case_dir)
    if not base.is_dir():
        return 0
    analytic = {"es": clause}
    for path in base.rglob("*.jsonl"):
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    try:
                        if matches_record(analytic, row):
                            total += 1
                    except Exception:  # noqa: BLE001
                        continue
        except OSError:
            continue
    return total


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

    # Stable order: rule-engine detections first, then strongest score, then kind
    # and subject so two runs over the same index produce byte-identical output.
    # A crit/high detection must never be outranked by a heuristic lead
    # (WO-R1F item 1) — the probe asserts it.
    leads.sort(key=lambda lead: (
        0 if lead.kind == "rule_engine" else 1,
        -lead.score,
        lead.kind,
        lead.subject,
    ))

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
