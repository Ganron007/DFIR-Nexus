"""Leads the case's own inventory raises against the triage baseline, and the memory scanner's verdicts (D244, D245).

**Why every mode missed the second persistence task on CASE-C5B04D31 (2026-10-16).** The lead list held 140
leads: Hayabusa detections, the behavioural analytics and value rarity. The triage baseline (2.68 M files of 254
Windows builds, 606 tasks, 4,901 services) answered one value when a model called ``check_*``, and produced no
lead (``absence.py``: "the triage baselines answer per-value checks; they do not produce leads"). So
``\\SRL Update Service`` - a task outside the baseline, running ``C:\\Windows\\System32\\STUN.exe`` (a file no
Windows build ships) as SYSTEM at boot - never reached an agenda: Mode 1 and Mode 2 never looked at it, and
Mode 3 met it in 756 calls without a reason to weigh it. And MemProcFS's FindEvil had matched Cobalt Strike YARA
rules in the memory of STUN.exe, explorer.exe, msedge.exe and lsass.exe: 9 rows among 7 M, read by no mode.

**Persistence (lead source ``baselines``).** Every task and service the evidence names - in its event data
(``TaskName``/``Path``, ``ServiceName``/``ImagePath``/``ServiceFileName``, the names of the providers' own
manifests), the task XML inventory, the TaskCache key, and the memory image's task and service lists - is checked
against the baseline. One lead per executable the baseline does not hold: the lead names the tasks and services
that run it and when they were seen. An executable in the Windows directory that no Windows build ships is the
strongest case (crit/high: every mode must dispose of it); a kernel driver there is routine for hardware and
vendor packages, so it ranks high without being crit; one elsewhere ranks below. A task or service whose
executables are all Windows' own raises nothing. FD-004 holds: a lead is a question, never a finding.

**Memory verdicts (lead source ``rules``).** MemProcFS's YARA report is a rule engine's detection like Hayabusa's:
one lead per process, scored by the matching rules' own ``Severity``, crit/high when a rule names the threat it
identifies (``Threat_name``). FindEvil's other verdict types are one neutral lead per (type, process).
"""
from __future__ import annotations

import fnmatch
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import Any

from nexus.analysis.leads import ANALYTIC_SAMPLE_ROWS, Lead

log = logging.getLogger(__name__)

#: Where the evidence names a task or a service and what it runs: (kind, name field, executable field, rows).
#: Field paths are the index's; ``rows`` is the ES filter for the rows that carry the pair.
_ED = "ecs.winlog.event_data."
PERSISTENCE_SOURCES: tuple[tuple[str, str, str, dict[str, Any]], ...] = (
    ("task", _ED + "TaskName", _ED + "Path", {"exists": {"field": _ED + "TaskName"}}),
    ("service", _ED + "ServiceName", _ED + "ImagePath", {"exists": {"field": _ED + "ServiceName"}}),
    ("service", _ED + "ServiceName", _ED + "ServiceFileName", {"exists": {"field": _ED + "ServiceName"}}),
    # The product's task XML importer.
    ("task", "fields.task_uri.kw", "fields.action_command.kw", {"term": {"family": "scheduled_tasks"}}),
    # RECmd's TaskCache plugin.
    ("task", "fields.Path.kw", "fields.Command.kw",
     {"bool": {"filter": [{"term": {"family": "recmd"}}, {"wildcard": {"file": "*TaskCache*"}}]}}),
    # The memory image's own task and service lists (MemProcFS).
    ("task", "fields.TaskPath.kw", "fields.CommandLine.kw",
     {"bool": {"filter": [{"term": {"family": "memprocfs"}}, {"wildcard": {"file": "*/csv/tasks.csv"}}]}}),
    ("service", "fields.ServiceName.kw", "fields.ImagePath.kw",
     {"bool": {"filter": [{"term": {"family": "memprocfs"}}, {"wildcard": {"file": "*/csv/services.csv"}}]}}),
)

#: Score of a persistence lead. A program no Windows build ships is a review item (data reduction against the
#: baseline, SANS FOR508 Memory Baseliner; UNKNOWN is neutral, FD-004), ordered by where it sits. It is crit/high
#: only with corroboration: its name is a well-known Windows process at a path none of that process's valid paths
#: names (masquerading, ATT&CK T1036.005; the triage context's ``expected_processes``, from SANS and MemProcFS), or
#: a detection or scanner verdict names the same program (``corroborate_baseline_leads``). Any Windows file name at
#: another path is not enough: on T22 that took VMware's vmxnet3.sys and pvscsi.sys (Windows keeps copies in its
#: driver store) and Chrome's elevation_service.exe (Edge ships one) for masquerades.
#: Part 12 FM-5 (operator 2026-10-28): every unknown program in the Windows directory used to be crit/high, which
#: on T22 flagged Sysmon, McAfee and the responders' own F-Response and Mnemosyne.
SCORE_MASQUERADE = 1.0
SCORE_WINDOWS_PROGRAM = 0.5
SCORE_WINDOWS_DRIVER = 0.45
SCORE_ELSEWHERE = 0.3
#: A FindEvil verdict by MemProcFS's own false-positive rating (``findevil_rating``); unrated is neutral.
SCORE_BY_FP = {"LOW": 0.7, "MEDIUM": 0.5, "HIGH": 0.2, "": 0.5}
SCORE_MEMORY_NEUTRAL = SCORE_BY_FP[""]
#: The EPROCESS image name MemProcFS and Volatility report is cut to 14 characters.
_IMAGE_NAME_CHARS = 14

_DRIVER_SUFFIXES = (".sys",)


@dataclass
class _Entry:
    kind: str
    name: str
    executables: dict[str, str] = field(default_factory=dict)  # normalized -> as written
    raw: dict[str, set[tuple[str, str]]] = field(default_factory=dict)  # normalized -> {(field, raw value)}
    count: int = 0
    first: str = ""
    last: str = ""


def _dotted(doc: dict[str, Any], path: str) -> str:
    """A field of an indexed document by its index path (``fields.X.kw`` reads ``fields.X``)."""
    node: Any = doc
    parts = path[:-3].split(".") if path.endswith(".kw") else path.split(".")
    if parts[0] == "fields" and len(parts) > 2:  # a column name may itself hold a dot
        parts = ["fields", ".".join(parts[1:])]
    for part in parts:
        node = node.get(part) if isinstance(node, dict) else None
    return str(node).strip() if node not in (None, "") else ""


def _doc_matches(doc: dict[str, Any], rows: dict[str, Any]) -> bool:
    """Whether an indexed document is one of a source's rows (the subset of ES the filters above use)."""
    if "exists" in rows:
        return bool(_dotted(doc, rows["exists"]["field"]))
    if "term" in rows:
        (key, value), = rows["term"].items()
        return str(doc.get(key) or "") == value
    if "wildcard" in rows:
        (key, pattern), = rows["wildcard"].items()
        return re.fullmatch(re.escape(pattern).replace(r"\*", ".*"), str(doc.get(key) or ""), re.I) is not None
    if "bool" in rows:
        return all(_doc_matches(doc, clause) for clause in rows["bool"].get("filter") or [])
    return False


def task_key(name: str) -> str:
    """A task as the baseline names it: its full path from the root, ``\\Folder\\Name``."""
    text = str(name or "").strip()
    return text if text.startswith("\\") else "\\" + text


def executable_of(value: str) -> tuple[str, str]:
    """(normalized path, path as written) of the program a task action or service image path runs."""
    from nexus.triage.analysis import parse_service_binary_path

    text = str(value or "").strip()
    if not text or text in ("---", "-"):
        return "", ""
    # A kernel object path names the same file: `\??\C:\windows\Mnemosyne.sys` is `C:\windows\Mnemosyne.sys`.
    text = re.sub(r'^"?\\\?\?\\', lambda m: m.group(0)[:-4] if m.group(0).startswith('"') else "", text)
    written = text[1:text.find('"', 1)] if text.startswith('"') and text.find('"', 1) > 0 else text
    match = re.match(r'^([^"]*?\.(?:exe|sys|dll|ocx|bat|cmd|ps1|vbs|js))(?:\s|$)', written, re.I)
    if match:
        written = match.group(1)
    elif " " in written and not text.startswith('"'):
        written = written.split(" ", 1)[0]
    return parse_service_binary_path(text), written.strip()


def entries_from_documents(docs: Iterable[dict[str, Any]]) -> list[_Entry]:
    """The tasks and services indexed documents name, with what they run."""
    return _merge(rows_from_documents(docs))


def rows_from_documents(
    docs: Iterable[dict[str, Any]],
) -> list[tuple[tuple[str, str, str, dict[str, Any]], str, str, int, str, str]]:
    """The (source, name, executable, count, first, last) rows the index aggregation gives, from documents."""
    buckets: dict[tuple[int, str, str], dict[str, Any]] = {}
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        for i, (_kind, name_field, exe_field, rows) in enumerate(PERSISTENCE_SOURCES):
            if not _doc_matches(doc, rows):
                continue
            name = _dotted(doc, name_field)
            if not name:
                continue
            exe = _dotted(doc, exe_field)
            bucket = buckets.setdefault((i, name, exe), {"count": 0, "first": "", "last": ""})
            bucket["count"] += 1
            ts = str(doc.get("ts") or "")
            if ts:
                bucket["first"] = min(filter(None, [bucket["first"], ts]))
                bucket["last"] = max(bucket["last"], ts)
    return [(PERSISTENCE_SOURCES[i], name, exe, b["count"], b["first"], b["last"])
            for (i, name, exe), b in buckets.items()]


def _merge(rows: Iterable[tuple[tuple[str, str, str, dict[str, Any]], str, str, int, str, str]]) -> list[_Entry]:
    """One entry per (kind, name) across sources, with every executable any source names for it."""
    entries: dict[tuple[str, str], _Entry] = {}
    for (kind, _name_field, exe_field, _rows), name, exe, count, first, last in rows:
        key = (kind, task_key(name).lower() if kind == "task" else name.lower())
        entry = entries.setdefault(key, _Entry(kind=kind, name=task_key(name) if kind == "task" else name))
        entry.count += int(count or 0)
        if first:
            entry.first = min(filter(None, [entry.first, first]))
        if last:
            entry.last = max(entry.last, last)
        normalized, written = executable_of(exe)
        if normalized:
            entry.executables.setdefault(normalized, written)
            entry.raw.setdefault(normalized, set()).add((exe_field, exe))
    return list(entries.values())


def _in_windows_directory(normalized: str) -> bool:
    return normalized.startswith("\\windows\\") and not normalized.startswith("\\windows\\temp\\")


def _executable_known(baseline: Any, normalized: str, written: str) -> bool:
    """Whether a Windows build ships this program: its path, or (for a bare name resolved through PATH) its name."""
    if "\\" not in normalized.strip("\\"):
        name = normalized.strip("\\")
        return bool(baseline.filename_exists(name) or baseline.filename_exists(name + ".exe"))
    return bool(baseline.path_exists(written) or baseline.path_exists(normalized))


def _entry_known(baseline: Any, entry: _Entry) -> bool:
    if entry.kind == "task":
        return bool(baseline.lookup_task(task_key(entry.name)))
    return bool(baseline.lookup_service(entry.name))


def masquerades(context: Any, normalized: str) -> bool:
    """A well-known Windows process name at a path none of its valid paths names (T1036.005)."""
    name = normalized.rsplit("\\", 1)[-1]
    if context is None or not name or "\\" not in normalized:
        return False
    row = context.get_expected_process(name) or {}
    paths = [str(p).lower() for p in row.get("valid_paths") or [] if p]
    return bool(paths) and not any(fnmatch.fnmatch(normalized.lower(), p) for p in paths)


def persistence_leads_from(entries: Iterable[_Entry], baseline: Any, context: Any = None) -> list[Lead]:
    """One lead per executable outside the baseline, naming the tasks and services that run it."""
    by_exe: dict[str, dict[str, Any]] = {}
    for entry in entries:
        for normalized, written in entry.executables.items():
            if _executable_known(baseline, normalized, written):
                continue
            item = by_exe.setdefault(normalized, {"written": written, "entries": [], "raw": set(),
                                                  "first": "", "last": "", "count": 0})
            item["entries"].append(entry)
            item["raw"] |= entry.raw.get(normalized, set())
            item["count"] += entry.count
            if entry.first:
                item["first"] = min(filter(None, [item["first"], entry.first]))
            item["last"] = max(item["last"], entry.last)
    from nexus.knowledge.attack_method import technique_by_name

    # IC-5: the ATT&CK technique each kind of entry is, by ATT&CK's own names (looked up, not typed as ids).
    kind_technique = {"task": technique_by_name("Scheduled Task", parent="Scheduled Task/Job"),
                      "service": technique_by_name("Windows Service", parent="Create or Modify System Process")}
    leads: list[Lead] = []
    for normalized, item in by_exe.items():
        entries_here = sorted(item["entries"], key=lambda e: (e.kind, e.name.lower()))
        in_windows = _in_windows_directory(normalized)
        driver = normalized.endswith(_DRIVER_SUFFIXES)
        masquerade = masquerades(context, normalized)
        crit = masquerade
        score = (SCORE_MASQUERADE if masquerade else SCORE_WINDOWS_DRIVER if in_windows and driver
                 else SCORE_WINDOWS_PROGRAM if in_windows else SCORE_ELSEWHERE)
        named = [
            f"{e.kind} {e.name}" + ("" if _entry_known(baseline, e) else " (not in the Windows baseline)")
            for e in entries_here[:4]
        ] + ([f"{len(entries_here) - 4} more"] if len(entries_here) > 4 else [])
        where = ("in the Windows directory, which holds Windows' own files" if in_windows
                 else "outside the Windows directory")
        leads.append(Lead(
            kind="baseline",
            subject=item["written"],
            family="triage baseline",
            detail=(
                f"{item['written']} is run by {', '.join(named)}; no Windows build in the triage baseline ships "
                f"it, and it sits {where}"
                + (" (a kernel driver)" if driver else "")
                + (f"; seen {item['first']} to {item['last']}" if item["first"] else "")
                + ("; its name is a well-known Windows process at a path none of its valid paths names "
                   "(masquerading, T1036.005)"
                   if masquerade else "; a review item: absent from the baseline is not suspicious by itself")
            ),
            rows=(),
            audit_ids=(),
            score=score,
            extra={
                "crit_high": crit,
                "level": "high" if crit else "",
                "engine": "triage baseline",
                "executable": item["written"],
                "in_windows_directory": in_windows,
                "masquerade": masquerade,
                "entries": [{"kind": e.kind, "name": e.name, "in_baseline": _entry_known(baseline, e)}
                            for e in entries_here],
                "first": item["first"],
                "last": item["last"],
                "count": item["count"],
                "query": _sample_query(item["raw"]),
                "attack_ids": sorted({kind_technique[e.kind] for e in entries_here if kind_technique.get(e.kind)}),
            },
        ))
    leads.sort(key=lambda lead: (-lead.score, lead.subject.lower()))
    return leads


def _sample_query(raw: set[tuple[str, str]]) -> dict[str, Any]:
    """The ES query for rows that name this executable as written, so a lead can be cited and read again."""
    return {"bool": {"should": [{"term": {f: v}} for f, v in sorted(raw)][:8], "minimum_should_match": 1}}


# --------------------------------------------------------------------------- the case's own index


def _case_id(case_dir: Path) -> str:
    return Path(case_dir).name


def _indexed(case_dir: Path) -> bool:
    """The case has an index to read: one was built (``analysis/es_index.json``) and Elasticsearch answers.

    A case without one yields no lead, as every lead source does (``leads.py``): nothing was read, so
    nothing was found, and the build is not a failure.
    """
    from nexus.langgraph.case_index import elasticsearch_ready

    return (Path(case_dir) / "analysis" / "es_index.json").is_file() and elasticsearch_ready()


def _composite_rows(case_id: str) -> list[tuple[tuple[str, str, str, dict[str, Any]], str, str, int, str, str]]:
    """Every (name, executable) pair each source holds, with its count and time span (composite paging)."""
    from nexus.langgraph.es_native import es_aggregate

    out = []
    for source in PERSISTENCE_SOURCES:
        _kind, name_field, exe_field, rows = source
        after: dict[str, Any] | None = None
        while True:
            composite: dict[str, Any] = {"size": 1000, "sources": [
                {"name": {"terms": {"field": name_field}}},
                {"exe": {"terms": {"field": exe_field, "missing_bucket": True}}},
            ]}
            if after:
                composite["after"] = after
            result = es_aggregate(case_id, {"pairs": {"composite": composite, "aggs": {
                "first": {"min": {"field": "ts"}}, "last": {"max": {"field": "ts"}}}}}, query=rows)
            if result.get("degraded") or result.get("error"):
                break  # a field this case's index does not hold: the source has nothing here
            agg = (result.get("aggregations") or {}).get("pairs") or {}
            buckets = agg.get("buckets") or []
            for b in buckets:
                key = b.get("key") or {}
                out.append((source, str(key.get("name") or ""), str(key.get("exe") or ""), int(b.get("doc_count") or 0),
                            str((b.get("first") or {}).get("value_as_string") or ""),
                            str((b.get("last") or {}).get("value_as_string") or "")))
            after = agg.get("after_key")
            if not after or not buckets:
                break
    return out


def _sample_rows(case_id: str, query: dict[str, Any]) -> list[dict[str, Any]]:
    from nexus.analysis.leads import _hit_rows
    from nexus.langgraph.es_native import es_search

    try:
        result = es_search(case_id, query, size=ANALYTIC_SAMPLE_ROWS, sort=[{"ts": {"order": "asc"}}])
    except Exception as exc:  # noqa: BLE001 - a lead without rows is still a question
        log.debug("baseline lead rows unavailable: %s", exc)
        return []
    return _hit_rows(result.get("hits") or [])


def _baseline() -> Any:
    from nexus.triage.server import _open_dbs

    known_good, _context = _open_dbs()
    if known_good is None:
        raise RuntimeError("the triage baseline (known_good.db) is not installed: run triage_download")
    return known_good


def _context() -> Any:
    """The triage context database (expected processes); None when it is not installed."""
    from nexus.triage.server import _open_dbs

    _known_good, context = _open_dbs()
    return context


def persistence_leads(case_dir: Path | str, *, probe: Any = None) -> list[Lead]:
    """Persistence leads for a case from its index. ``probe`` may supply ``persistence_rows()`` and ``baseline``."""
    case_id = _case_id(Path(case_dir))
    if probe is not None and hasattr(probe, "persistence_rows"):
        rows = list(probe.persistence_rows())
        baseline = probe.baseline
        context = getattr(probe, "context", None)
    elif probe is not None and not hasattr(probe, "case_dir"):
        return []  # a test probe without the inventory seam
    elif not _indexed(Path(case_dir)):
        return []
    else:
        rows = _composite_rows(case_id)
        baseline = _baseline()
        context = _context()
    leads = persistence_leads_from(_merge(rows), baseline, context)
    if probe is not None and hasattr(probe, "persistence_rows"):
        return leads
    return [Lead(kind=lead.kind, subject=lead.subject, family=lead.family, detail=lead.detail,
                 rows=tuple(_sample_rows(case_id, lead.extra["query"])), audit_ids=(), score=lead.score,
                 extra=lead.extra) for lead in leads]


# --------------------------------------------------------------------------- memory verdicts

#: MemProcFS's YARA report and FindEvil table, as the index holds them.
YARA_ROWS = {"bool": {"filter": [{"term": {"family": "memprocfs"}}, {"wildcard": {"file": "*findevil/yara.txt"}},
                                 {"exists": {"field": "fields.Rule"}}]}}
FINDEVIL_ROWS = {"bool": {"filter": [{"term": {"family": "memprocfs"}}, {"wildcard": {"file": "*/csv/findevil.csv"}}],
                          "must_not": [{"prefix": {"fields.Type.kw": "YR_"}}]}}


@lru_cache(maxsize=1)
def findevil_ratings() -> dict[str, str]:
    """MemProcFS's own false-positive rating of each FindEvil type, from the pinned wiki (FM-6).

    ``data/knowledge/sources/memprocfs_findevil.yaml`` is generated by
    ``devtools/knowledge/import_memprocfs_findevil.py`` from the page's snapshot, never typed.
    """
    import yaml

    path = Path(__file__).resolve().parents[1] / "data" / "knowledge" / "sources" / "memprocfs_findevil.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(name): str((entry or {}).get("fp") or "") for name, entry in (doc.get("types") or {}).items()}


def findevil_rating(verdict: str) -> str:
    """LOW, MEDIUM or HIGH as MemProcFS rates the type's false positives; "" when it rates none."""
    ratings = findevil_ratings()
    name = str(verdict or "").strip().upper()
    return ratings.get(name) or (ratings.get("YR_*", "") if name.startswith("YR_") else "")


def same_program(path_or_name: str, process: str) -> bool:
    """Whether an executable and a process name are one program; the image name may be cut to 14 characters."""
    name = str(path_or_name or "").replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()
    image = str(process or "").strip().lower()
    if not name or not image or image in ("?", "---"):
        return False
    return name == image or (len(image) >= _IMAGE_NAME_CHARS and name.startswith(image))


def _severity(value: Any) -> float | None:
    try:
        return max(0.0, min(float(str(value).strip()), 100.0))
    except (TypeError, ValueError):
        return None


def memory_verdict_leads_from(yara_hits: Iterable[dict[str, Any]],
                              findevil_hits: Iterable[dict[str, Any]]) -> list[Lead]:
    """One lead per process a YARA rule matched in memory, and one per (FindEvil verdict type, process)."""
    from nexus.analysis.leads import _hit_rows

    def fields_of(hit: dict[str, Any]) -> dict[str, Any]:
        return hit.get("fields") if isinstance(hit.get("fields"), dict) else {}

    leads: list[Lead] = []
    by_process: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for hit in yara_hits:
        f = fields_of(hit)
        by_process.setdefault((str(f.get("ProcessName") or "?"), str(f.get("PID") or "?")), []).append(hit)
    for (process, pid), hits in sorted(by_process.items()):
        rules = sorted({str(fields_of(h).get("Rule") or "") for h in hits} - {""})
        threats = sorted({str(fields_of(h).get("Threat_name") or "") for h in hits} - {""})
        severities = [s for s in (_severity(fields_of(h).get("Severity")) for h in hits) if s is not None]
        first = fields_of(hits[0])
        path = str(first.get("ProcessPath") or first.get("CommandLine") or "")
        leads.append(Lead(
            kind="rule_engine",
            subject=f"{process} (pid {pid})",
            family="memprocfs",
            detail=(f"MemProcFS YARA: {len(rules)} rule(s) matched the memory of {process} (pid {pid}"
                    + (f", {path}" if path else "") + f", user {first.get('User') or '?'})"
                    + (f": {', '.join(threats)}" if threats else "") + f" [{', '.join(rules[:4])}]"),
            rows=tuple(_hit_rows(hits[:ANALYTIC_SAMPLE_ROWS])),
            audit_ids=(),
            score=(max(severities) / 100.0) if severities else 0.9,
            extra={"engine": "memprocfs-yara", "level": f"severity {int(max(severities))}" if severities else "",
                   "crit_high": bool(threats), "rules": rules, "threats": threats, "count": len(hits),
                   "process": process, "pid": pid},
        ))
    by_type: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for hit in findevil_hits:
        f = fields_of(hit)
        verdict = str(f.get("Type") or "").strip()
        if not verdict or verdict.upper().startswith("YR_"):
            continue
        by_type.setdefault((verdict, str(f.get("ProcessName") or "---")), []).append(hit)
    for (verdict, process), hits in sorted(by_type.items()):
        pids = sorted({str(fields_of(h).get("PID") or "") for h in hits} - {""})
        sample = [str(fields_of(h).get("Description") or "")[:120] for h in hits[:3]]
        rating = findevil_rating(verdict)
        # FM-6: a type MemProcFS rates HIGH for false positives is context for a process already of
        # interest (attach_findevil_context), not a lead of its own.
        leads.append(Lead(
            kind="context" if rating == "HIGH" else "rule_engine",
            subject=f"{verdict} {process}",
            family="memprocfs",
            detail=(f"MemProcFS FindEvil {verdict}: {len(hits)} row(s) in {process}"
                    + (f" (pid {', '.join(pids[:4])})" if pids else "") + f": {'; '.join(sample)}"
                    + (f" [MemProcFS rates {verdict} false positives {rating}]" if rating else "")),
            rows=tuple(_hit_rows(hits[:ANALYTIC_SAMPLE_ROWS])),
            audit_ids=(),
            score=SCORE_BY_FP.get(rating, SCORE_MEMORY_NEUTRAL),
            extra={"engine": "memprocfs-findevil", "level": "", "crit_high": False, "count": len(hits),
                   "verdict": verdict, "process": process, "fp_rating": rating},
        ))
    return leads


def _programs(lead: Lead) -> list[str]:
    """The program names a lead is about: its executable, its process, or its YARA match's process."""
    extra = lead.extra or {}
    return [str(v) for v in (extra.get("executable"), extra.get("process")) if v]


def attach_findevil_context(leads: list[Lead]) -> list[Lead]:
    """Each HIGH-false-positive FindEvil verdict joins the lead about the same process as context (FM-6).

    A verdict with no lead about its process stays a ``context`` lead, ranked after every other lead.
    """
    context = [lead for lead in leads if lead.kind == "context"]
    others = [lead for lead in leads if lead.kind != "context"]
    attached: dict[int, list[dict[str, Any]]] = {}
    unattached: list[Lead] = []
    for item in context:
        process = str((item.extra or {}).get("process") or "")
        index = next((i for i, lead in enumerate(others)
                      if any(same_program(p, process) or same_program(process, p) for p in _programs(lead))),
                     None)
        if index is None:
            unattached.append(item)
            continue
        attached.setdefault(index, []).append(
            {"verdict": item.extra.get("verdict"), "fp_rating": item.extra.get("fp_rating"),
             "count": item.extra.get("count"), "detail": item.detail})
    merged = [replace(lead, extra={**lead.extra, "findevil_context": attached[i]}) if i in attached else lead
              for i, lead in enumerate(others)]
    return merged + unattached


def corroborate_baseline_leads(leads: list[Lead], responder_tools: str = "") -> list[Lead]:
    """Raise a baseline review item to high when a detection or scanner verdict names the same program (FM-5),
    and label the programs the examiner names among the responders' tools (D224)."""
    detections = [lead for lead in leads if lead.kind == "rule_engine"]
    tools = [t.strip() for t in str(responder_tools or "").replace(";", ",").split(",") if t.strip()]
    out: list[Lead] = []
    for lead in leads:
        if lead.kind != "baseline":
            out.append(lead)
            continue
        extra = dict(lead.extra)
        detail, score = lead.detail, lead.score
        executable = str(extra.get("executable") or "")
        names = " ".join([executable] + [str(e.get("name") or "") for e in extra.get("entries") or []]).lower()
        named = [t for t in tools if t.lower() in names]
        if named:
            extra["responder_tool"] = named[0]
            detail += f"; the examiner names {named[0]} among the responders' tools"
        by = [d for d in detections if any(same_program(executable, p) for p in _programs(d))]
        if by and not extra.get("crit_high"):
            extra.update(crit_high=True, level="high", corroborated_by=[d.subject for d in by])
            detail += "; corroborated by " + "; ".join(d.subject for d in by)
            score = max(score, SCORE_MASQUERADE)
        out.append(replace(lead, detail=detail, score=score, extra=extra))
    return out
    return leads


def _all_hits(case_id: str, query: dict[str, Any]) -> list[dict[str, Any]]:
    from nexus.langgraph.es_native import PAGE_SIZE, es_search

    out: list[dict[str, Any]] = []
    after = None
    while True:
        result = es_search(case_id, query, size=PAGE_SIZE, sort=[{"line": {"order": "asc"}}], search_after=after)
        if result.get("degraded") or result.get("error"):
            return out
        hits = result.get("hits") or []
        out.extend(hits)
        after = result.get("next_search_after")
        if not after or not hits or not result.get("has_more"):
            return out


def memory_verdict_leads(case_dir: Path | str, *, probe: Any = None) -> list[Lead]:
    """Memory verdict leads for a case from its index. ``probe`` may supply ``memory_hits()``."""
    if probe is not None and hasattr(probe, "memory_hits"):
        yara_hits, findevil_hits = probe.memory_hits()
        return memory_verdict_leads_from(yara_hits, findevil_hits)
    if (probe is not None and not hasattr(probe, "case_dir")) or not _indexed(Path(case_dir)):
        return []
    case_id = _case_id(Path(case_dir))
    return memory_verdict_leads_from(_all_hits(case_id, YARA_ROWS), _all_hits(case_id, FINDEVIL_ROWS))
