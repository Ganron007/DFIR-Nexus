"""WO-1C item 7 — the per-run family coverage ledger (KR4 / D58).

"No run accounts for every indexed family" (operator question 2b; D58). The old
code credited a layer as having run because it was merely *available* — third-eye
R20 — so a run could settle having never queried the family that held the
evidence, and the run record said the family was covered.

This module builds the ledger **from execution records only**: for every indexed
family it shows

* the documents the index holds for it;
* the queries run against it, succeeded and failed;
* the rows those queries returned;
* the leads touched.

A family that was never examined is listed with the reason. The ledger is what
the settle rule reads: a Mode 2 or Mode 3 run does not settle while an indexed
family with rows has no successful query, unless the record says why.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

__all__ = [
    "indexed_families",
    "record_query",
    "record_queries",
    "record_needle_scan",
    "build_family_ledger",
    "unexamined_families",
    "settle_blockers",
    "render_family_ledger_markdown",
]


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def indexed_families(case_dir: Path) -> dict[str, int]:
    """``{family: document_count}`` for every family the case's index holds.

    Read from the digest's inventory when it is present (it is rebuilt on every
    interpret run and carries the ES counts), and from the index directly
    otherwise. A family with no rows is not returned: the ledger accounts for
    what is there, and an empty family is a different statement the digest
    already makes.
    """
    case_dir = Path(case_dir)
    out: dict[str, int] = {}
    digest = _load_json(case_dir / "analysis" / "case_digest.json") or {}
    inventory = digest.get("inventory") if isinstance(digest, dict) else None
    if isinstance(inventory, Mapping):
        for family, rows in inventory.items():
            name = str(family or "").strip()
            if not name:
                continue
            try:
                count = int(rows)
            except (TypeError, ValueError):
                # Some inventories carry {"docs": n, ...} instead of a bare int.
                if isinstance(rows, Mapping):
                    try:
                        count = int(rows.get("docs") or rows.get("count") or 0)
                    except (TypeError, ValueError):
                        count = 0
                else:
                    count = 0
            if count > 0:
                out[name] = count
        if out:
            return out
    # No digest (or an empty one): ask the index. ES is the only backend that
    # can answer; a CSV-only case has no index families to account for.
    try:
        from nexus.config import settings
        from nexus.langgraph.case_index import case_family_counts

        counts = case_family_counts(settings.cases_root / case_dir.name)
    except Exception:  # noqa: BLE001 — best effort; the caller records the reason
        log.debug("family ledger: index counts unavailable for %s", case_dir.name)
        return {}
    for family, count in (counts or {}).items():
        name = str(family or "").strip()
        try:
            n = int(count)
        except (TypeError, ValueError):
            continue
        if name and n > 0:
            out[name] = n
    return out


def _query_family(query: Any) -> str:
    """The family a stored ES query targets, when it names one.

    A stored query is ES query JSON (KR2). The family is the ``term``/``terms``
    value on the family field the index writes — ``family`` or
    ``event.dataset`` — and the ``ecs.*`` spelling ``event.dataset`` is read
    alongside it. The field is looked for both at the top level and inside the
    query clauses (``term``/``terms``/``match``/``bool``), because the runs store
    both the bare clause (``{"term": {"family": "evtxecmd"}}``) and a wrapped
    ``bool`` query. A query that does not name a family is not attributed to
    one: guessing would credit a family with a query that never touched it.
    """
    if not isinstance(query, Mapping):
        return ""
    fields = ("family", "event.dataset", "event.dataset.keyword")

    def _value_of(node: Any, field: str) -> str:
        """The scalar/list value a clause holds for ``field``, or ""."""
        if not isinstance(node, Mapping):
            return ""
        for key in ("term", "terms", "match", "match_phrase"):
            sub = node.get(key)
            if isinstance(sub, Mapping):
                for fname, value in sub.items():
                    if fname.split(".")[0] != field.split(".")[0]:
                        continue
                    if isinstance(value, (list, tuple)):
                        for one in value:
                            name = str(one or "").strip()
                            if name:
                                return name
                    else:
                        name = str(value or "").strip()
                        if name:
                            return name
            elif isinstance(sub, str) and sub.strip():
                return sub.strip()
        return ""

    def _walk(node: Any, depth: int = 0) -> str:
        if not isinstance(node, Mapping) or depth > 6:
            return ""
        # The clause form: {"term": {"family": "evtxecmd"}}.
        for field in fields:
            found = _value_of(node, field)
            if found:
                return found
        # The direct form: {"family": "evtxecmd"} (an already-extracted filter).
        for field in fields:
            value = node.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
        # Nested clauses: bool/filter/must/should/... — walk them.
        for value in node.values():
            if isinstance(value, Mapping):
                found = _walk(value, depth + 1)
                if found:
                    return found
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, Mapping):
                        found = _walk(item, depth + 1)
                        if found:
                            return found
        return ""

    return _walk(query)


def _queries_from_run(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every stored query in one run record, with its outcome.

    Mode 2 and Mode 3 records both keep ``orders``/``results`` with the query
    JSON and the rows the worker read; Mode 1's interpret loop keeps the same
    shape under its round artifacts. All three are read here so one ledger
    serves every mode.
    """
    out: list[dict[str, Any]] = []
    for order in _as_list(record.get("orders")):
        if not isinstance(order, Mapping):
            continue
        query = order.get("es") or order.get("query")
        if query is None:
            continue
        out.append({
            "run_id": str(order.get("run_id") or record.get("run_id") or ""),
            "query": query,
            "status": str(order.get("status") or "unknown"),
            "rows": order.get("rows") if isinstance(order.get("rows"), int) else 0,
            "hits": order.get("hits") if isinstance(order.get("hits"), int) else 0,
            "audit_id": str(order.get("audit_id") or ""),
        })
    for result in _as_list(record.get("results")):
        if not isinstance(result, Mapping):
            continue
        query = result.get("es") or result.get("query")
        if query is None:
            continue
        rows = result.get("rows")
        out.append({
            "run_id": str(result.get("run_id") or record.get("run_id") or ""),
            "query": query,
            "status": str(result.get("status") or ("OK" if result.get("ok") else "unknown")),
            "rows": rows if isinstance(rows, int) else 0,
            "hits": result.get("hits") if isinstance(result.get("hits"), int) else 0,
            "audit_id": str(result.get("audit_id") or ""),
        })
    # Deduplicate on the query JSON itself: a stored plan item and its executed
    # result are the same query, and counting both would double the ledger.
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for row in out:
        key = json.dumps(row.get("query"), sort_keys=True, default=str)
        if key in seen:
            # Keep the executed row (the one that carries rows/hits).
            for prior in unique:
                if json.dumps(prior.get("query"), sort_keys=True, default=str) == key:
                    if row.get("rows") or row.get("hits"):
                        prior.update({k: v for k, v in row.items() if k != "query"})
                    break
            continue
        seen.add(key)
        unique.append(row)
    return unique


def _queries_from_interpret_loop(case_dir: Path) -> list[dict[str, Any]]:
    """Mode 1's executed queries, from the interpret round artifacts."""
    rounds_dir = Path(case_dir) / "analysis" / "interpret_rounds"
    if not rounds_dir.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(rounds_dir.glob("round-*.json")):
        payload = _load_json(path)
        if not isinstance(payload, Mapping):
            continue
        for item in _as_list(payload.get("executed")):
            if not isinstance(item, Mapping):
                continue
            query = item.get("es") or item.get("query")
            if query is None:
                continue
            out.append({
                "run_id": str(payload.get("run_id") or ""),
                "query": query,
                "status": "OK" if not item.get("error") else "FAIL",
                "rows": item.get("rows") if isinstance(item.get("rows"), int) else 0,
                "hits": item.get("hits") if isinstance(item.get("hits"), int) else 0,
                "audit_id": str(item.get("audit_id") or ""),
            })
    return out


def record_query(case_dir: Path, query: Any, *, status: str, rows: int = 0,
                 audit_id: str = "", run_id: str = "") -> None:
    """Persist one executed query so the run's ledger can account for it.

    Called by the run's own execute path (the interpret loop, the Mode 2/3
    workers) — never reconstructed after the fact, so a query that was planned
    but never ran is never credited.
    """
    case_dir = Path(case_dir)
    path = case_dir / "analysis" / "family_queries.jsonl"
    entry = {
        "run_id": str(run_id or ""),
        "query": query,
        "status": str(status or "unknown"),
        "rows": int(rows or 0),
        "audit_id": str(audit_id or ""),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")
    except OSError as exc:  # noqa: BLE001 — a ledger write must not kill a run
        log.debug("family query ledger write failed: %s", exc)


def record_queries(case_dir: Path, entries: Iterable[Mapping[str, Any]]) -> None:
    for entry in entries:
        if isinstance(entry, Mapping):
            record_query(case_dir, entry.get("query"), status=str(entry.get("status") or ""),
                         rows=int(entry.get("rows") or 0),
                         audit_id=str(entry.get("audit_id") or ""),
                         run_id=str(entry.get("run_id") or ""))


def record_needle_scan(
    case_dir: Path,
    *,
    run_id: str = "",
    families: Iterable[str] = (),
    scanned: int = 0,
    failed: Iterable[str] = (),
) -> int:
    """Persist the briefing needle scan as executed queries (WO-1C item 7).

    The briefing scan is an execution record: it queried the index for each
    needle across every indexed family. Crediting it here is what lets a run's
    ledger show a family as ``examined`` by the needle source instead of
    "no query was run against this family" — which is what it said before,
    even though the scan had run.

    A needle the scan could not query (``failed``) is recorded as a FAIL, never
    as an examined family: an unqueried needle is not "checked, absent".
    """
    fams = [str(f).strip() for f in families if str(f).strip()]
    if not fams or scanned <= 0:
        return 0
    failed_set = {str(f).strip().lower() for f in failed if str(f).strip()}
    entries: list[dict[str, Any]] = []
    for family in fams:
        entries.append({
            "run_id": run_id,
            "query": {"term": {"family": family}},
            "status": "FAIL" if family.lower() in failed_set else "OK",
            "rows": 0,
            "audit_id": "",
        })
    record_queries(case_dir, entries)
    return len(entries)


def _executed_queries(case_dir: Path, run_id: str = "") -> list[dict[str, Any]]:
    """Every executed query the ledger may credit, scoped to ``run_id``.

    A run's ledger is built from **its own** execution records. When a run_id
    is given, only that run's rows are returned — never a fallback to the
    whole file: another run's work must not credit this one (KR4). Rows with no
    run_id (the briefing needle scan, which runs once per case before any
    mode) are shared, because they are case-level facts, not one run's work.
    """
    case_dir = Path(case_dir)
    out: list[dict[str, Any]] = []
    path = case_dir / "analysis" / "family_queries.jsonl"
    if path.is_file():
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    out.append(entry)
        except OSError:
            pass
    if run_id:
        scoped = [
            q for q in out
            if str(q.get("run_id") or "") == run_id or not str(q.get("run_id") or "")
        ]
        out = scoped
    if not run_id:
        out.extend(_queries_from_interpret_loop(case_dir))
    for sub, prefix in (("mode2_runs", "M2-"), ("mode3_runs", "M3-")):
        d = case_dir / "analysis" / sub
        if not d.is_dir():
            continue
        for rec in sorted(d.glob(f"{prefix}*.json")):
            record = _load_json(rec)
            if not isinstance(record, Mapping):
                continue
            rec_id = str(record.get("run_id") or rec.stem)
            if run_id and rec_id != run_id:
                continue
            out.extend(_queries_from_run(record))
    return out


def _leads_by_family(case_dir: Path) -> dict[str, list[str]]:
    """``{family: [lead subject, ...]}`` from the case's leads."""
    case_dir = Path(case_dir)
    try:
        from nexus.analysis.leads import read_leads

        leads = read_leads(case_dir)
    except Exception:  # noqa: BLE001
        return {}
    out: dict[str, list[str]] = {}
    for lead in leads or []:
        data = lead if isinstance(lead, Mapping) else (
            lead.to_dict() if hasattr(lead, "to_dict") else {}
        )
        if not isinstance(data, Mapping):
            continue
        family = str(data.get("family") or "").strip()
        subject = str(data.get("subject") or data.get("title") or "").strip()
        if not family:
            continue
        out.setdefault(family, [])
        if subject and subject not in out[family]:
            out[family].append(subject)
    return out


def build_family_ledger(case_dir: Path, *, run_id: str = "") -> dict[str, Any]:
    """The ledger: every indexed family, its queries, its rows, its leads.

    Built from execution records only. A family is ``examined`` when at least
    one query that names it ran without error; a family whose only queries
    failed is ``queried_failed`` and is reported with the failure, because a
    query that errored observed nothing.
    """
    case_dir = Path(case_dir)
    families = indexed_families(case_dir)
    queries = _executed_queries(case_dir, run_id)
    leads = _leads_by_family(case_dir)

    by_family: dict[str, dict[str, Any]] = {}
    for name, docs in sorted(families.items()):
        by_family[name] = {
            "family": name,
            "docs": int(docs),
            "queries": [],
            "queries_ok": 0,
            "queries_failed": 0,
            "rows_returned": 0,
            "leads_touched": list(leads.get(name) or [])[:8],
            "examined": False,
            "reason": "",
        }

    unattributed: list[dict[str, Any]] = []
    for query in queries:
        family = _query_family(query.get("query"))
        status = str(query.get("status") or "unknown").upper()
        ok = status in ("OK", "SUCCESS", "COMPLETED", "DONE") or (
            status not in ("FAIL", "FAILED", "ERROR", "TIMEOUT", "UNKNOWN")
            and not str(query.get("error") or "")
        )
        row = {
            "status": status or "unknown",
            "ok": bool(ok),
            "rows": int(query.get("rows") or 0),
            "audit_id": str(query.get("audit_id") or ""),
            "run_id": str(query.get("run_id") or ""),
        }
        if not family:
            unattributed.append(row)
            continue
        target = by_family.get(family)
        if target is None:
            # The query names a family the index does not hold (a stale family
            # name, or a query against evidence that is not indexed). It is
            # recorded so the ledger does not silently drop it.
            target = {
                "family": family, "docs": 0, "queries": [], "queries_ok": 0,
                "queries_failed": 0, "rows_returned": 0, "leads_touched": [],
                "examined": False, "reason": "queried but not in the index",
            }
            by_family[family] = target
        target["queries"].append(row)
        if ok:
            target["queries_ok"] += 1
            target["examined"] = True
        else:
            target["queries_failed"] += 1
        target["rows_returned"] += int(query.get("rows") or 0)

    for target in by_family.values():
        if target["examined"]:
            continue
        if target["queries_failed"] and not target["queries_ok"]:
            target["reason"] = (
                f"{target['queries_failed']} query/queries ran against this family "
                "and failed — it was not observed"
            )
        elif target["docs"]:
            target["reason"] = "no query was run against this family"
        elif target["reason"] != "queried but not in the index":
            target["reason"] = "not in the index"

    rows = list(by_family.values())
    examined = [r for r in rows if r["examined"]]
    return {
        "run_id": run_id,
        "families": rows,
        "families_indexed": len([r for r in rows if r["docs"]]),
        "families_examined": len(examined),
        "families_not_examined": [r["family"] for r in rows if not r["examined"]],
        "queries_total": len(queries),
        "queries_unattributed": len(unattributed),
        "summary": (
            f"{len(examined)}/{len([r for r in rows if r['docs']])} indexed families examined"
        ),
    }


def unexamined_families(ledger: Mapping[str, Any]) -> list[str]:
    """Families with rows in the index that no successful query touched."""
    out: list[str] = []
    for row in ledger.get("families") or []:
        if not isinstance(row, Mapping):
            continue
        if int(row.get("docs") or 0) > 0 and not row.get("examined"):
            out.append(str(row.get("family") or ""))
    return [f for f in out if f]


def settle_blockers(ledger: Mapping[str, Any]) -> list[str]:
    """Why this run may not settle yet, from the ledger alone.

    An empty list means the ledger does not block settlement. This is the
    WO-1C item 7 rule: a family with rows and no successful query blocks
    settlement unless the run record states why — the caller records that
    reason on the run record, and this function only reports the raw gap.
    """
    return unexamined_families(ledger)


def render_family_ledger_markdown(ledger: Mapping[str, Any]) -> str:
    """The ledger as the report shows it, so "not observed" is bounded."""
    if not ledger:
        return ""
    lines = ["## Family coverage ledger", ""]
    lines.append(f"**{ledger.get('summary', '')}**")
    lines.append("")
    lines.append("| Family | Docs | Queries (ok/failed) | Rows | Leads | Examined | Reason |")
    lines.append("|---|---|---|---|---|---|---|")
    for row in ledger.get("families") or []:
        if not isinstance(row, Mapping):
            continue
        lines.append(
            "| {fam} | {docs} | {ok}/{fail} | {rows} | {leads} | {exam} | {reason} |".format(
                fam=row.get("family", ""),
                docs=row.get("docs", 0),
                ok=row.get("queries_ok", 0),
                fail=row.get("queries_failed", 0),
                rows=row.get("rows_returned", 0),
                leads=len(row.get("leads_touched") or []),
                exam="yes" if row.get("examined") else "NO",
                reason=str(row.get("reason") or ""),
            )
        )
    blockers = settle_blockers(ledger)
    if blockers:
        lines += ["", "**Not examined (blocks settlement unless the record says why):** "
                   + ", ".join(blockers)]
    lines.append("")
    return "\n".join(lines)
