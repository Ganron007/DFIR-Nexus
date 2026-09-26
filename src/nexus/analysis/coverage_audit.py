"""Coverage audit — WIRING-PLAN 10.2.

Answers the three questions an examiner asks before sealing a case:

1. **Tools** — which lane tools were *applicable* to this evidence but never
   produced output? (planned vs ledger, cross-checked against the artifact YAML
   that declares ``related_tools``)
2. **Sources** — which indexed evidence families were never cited by any
   finding, and (the inverse, an integrity signal) did anything cite a family
   that is not in the index?
3. **Needles** — 0-hit reconciliation: which needles were genuinely scanned and
   found nothing (true negatives) versus never queried at all (NOT evidence of
   absence), plus every truncation reason.

Two rules govern this module:

**Honesty over completeness.** Every section reports ``status`` in
``ok | gaps | unknown``. When an input cannot be read — no ledger, ES
unreachable, no signal map — the section is ``unknown`` with the reason and the
top-level ``unavailable`` list, never a silent pass. A coverage audit that
claims coverage it could not prove is worse than no audit.

**No fabrication.** Nothing here invents a tool, a family or a needle. Every
row is derived from an artifact the pipeline wrote: the tool-lane ledger
(``_tool_lane_ledger.json``), the ES family aggregation, and
``analysis/signal_map.csv``.

Persisted to ``analysis/coverage_audit.json`` (schema 1).
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
AUDIT_FILENAME = "coverage_audit.json"

_OK = "ok"
_GAPS = "gaps"
_UNKNOWN = "unknown"

#: Section status → counts as an actionable gap in the overall verdict.
_GAP_STATUSES = {_GAPS}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# ── inputs ────────────────────────────────────────────────────────────────────


def _ledger_rows(case_dir: Path) -> tuple[list[dict[str, Any]], str]:
    """Tool-lane ledger rows + a reason when unavailable."""
    from nexus.langgraph.audit_linkage import _ledger_path

    path = _ledger_path(case_dir)
    if path is None:
        return [], "no tool-lane ledger (_tool_lane_ledger.json) — the tool lane has not run for this case"
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"ledger unreadable: {exc}"
    if not isinstance(rows, list):
        return [], "ledger is not a list of job rows"
    return [r for r in rows if isinstance(r, dict)], ""


def _evidence_roots(case_dir: Path) -> list[Path]:
    """Filesystem roots of the registered evidence (best effort)."""
    roots: list[Path] = []
    for record in _evidence_records(case_dir):
        raw = str(record.get("file_path") or "").strip()
        if not raw:
            continue
        p = Path(raw)
        if p.exists():
            roots.append(p)
    return roots


def _evidence_records(case_dir: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    ev = case_dir / "evidence.json"
    if ev.is_file():
        try:
            raw = json.loads(ev.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                out.extend(r for r in raw if isinstance(r, dict))
            elif isinstance(raw, dict) and isinstance(raw.get("evidence"), list):
                out.extend(r for r in raw["evidence"] if isinstance(r, dict))
        except (OSError, json.JSONDecodeError):
            pass
    if out:
        return out
    # Fall back to the case store (the portal's source of truth).
    try:
        from nexus.case import CaseManager
        from nexus.config import settings

        mgr = CaseManager(settings.cases_root / "cases.db")
        try:
            for rec in mgr.list_evidence(case_dir.name):
                out.append(
                    {
                        "name": getattr(rec, "name", ""),
                        "file_path": getattr(rec, "file_path", "") or "",
                        "file_hash_sha256": getattr(rec, "file_hash_sha256", "") or "",
                    }
                )
        finally:
            mgr.close()
    except Exception:  # noqa: BLE001
        return out
    return out


def _artifact_hits(case_dir: Path) -> tuple[list[Any], str]:
    """Windows artifact YAML vs the registered evidence roots."""
    from nexus.langgraph.artifact_map import discover_windows_artifacts
    from nexus.langgraph.tool_lane import find_windows_root

    roots: list[Path] = []
    for candidate in _evidence_roots(case_dir):
        root = find_windows_root(candidate) or (candidate if candidate.is_dir() else candidate.parent)
        if root not in roots:
            roots.append(root)
    if not roots:
        return [], "no registered evidence root to evaluate the artifact YAML against"
    hits: list[Any] = []
    for root in roots:
        try:
            hits.extend(discover_windows_artifacts(root))
        except Exception as exc:  # noqa: BLE001
            return hits, f"artifact discovery failed on {root}: {exc}"
    return hits, ""


# ── section 1: tools ──────────────────────────────────────────────────────────


def _tools_section(case_dir: Path) -> dict[str, Any]:
    rows, ledger_reason = _ledger_rows(case_dir)
    out: dict[str, Any] = {
        "status": _UNKNOWN,
        "reason": ledger_reason,
        "applicable_not_parsed": [],
        "failed": [],
        "pending": [],
        "counts": {"ledger_rows": len(rows)},
    }
    if not rows:
        return out

    # (a) ledger-side: applicable = not SKIP; never invoked = PENDING; failed = FAIL
    for row in rows:
        status = str(row.get("status") or "").upper()
        tool = str(row.get("tool") or "")
        entry = {
            "tool": tool,
            "purpose": str(row.get("purpose") or "")[:160],
            "reason": str(row.get("reason") or "")[:200],
            "audit_id": str(row.get("audit_id") or "")[:64],
        }
        if status == "PENDING":
            out["pending"].append(entry)
        elif status == "FAIL":
            out["failed"].append(entry)

    # (b) evidence-side: artifact YAML present, but no related tool ever ran
    hits, hits_reason = _artifact_hits(case_dir)
    ran_keys: set[str] = set()
    for row in rows:
        if str(row.get("status") or "").upper() == "OK":
            ran_keys.add(str(row.get("tool") or "").lower())
    if hits_reason and not hits:
        out["reason"] = (out["reason"] + "; " if out["reason"] else "") + hits_reason
    if hits:
        from nexus.langgraph.artifact_map import completeness_table, invokable_tool_key

        scheduled = {str(row.get("tool") or "") for row in rows}
        for item in completeness_table(hits, scheduled, rows):
            if item["status"] in {"PRESENT_NO_PARSER", "SCHEDULED"}:
                tools = [t.strip() for t in str(item.get("tools") or "").split(",") if t.strip()]
                never = [t for t in tools if t.lower() not in ran_keys]
                out["applicable_not_parsed"].append(
                    {
                        "artifact": item.get("artifact", ""),
                        "status": item["status"],
                        # Display names for the examiner, normalized planner keys
                        # for anything consuming this programmatically.
                        "tools": tools,
                        "never_invoked": never,
                        "never_invoked_keys": [invokable_tool_key(t) for t in never],
                        "hits": item.get("hits", ""),
                        "reason": item.get("reason", ""),
                    }
                )

    gaps = bool(out["applicable_not_parsed"] or out["failed"] or out["pending"])
    out["counts"].update(
        {
            "applicable_not_parsed": len(out["applicable_not_parsed"]),
            "failed": len(out["failed"]),
            "pending": len(out["pending"]),
            "ok": sum(1 for r in rows if str(r.get("status") or "").upper() == "OK"),
        }
    )
    out["status"] = _GAPS if gaps else _OK
    return out


# ── section 2: sources ───────────────────────────────────────────────────────


def _finding_citations(case_dir: Path) -> tuple[set[str], int]:
    """Families cited by any finding + the finding count.

    Uses the same family convention as FD-006 (``llm_guided.corroboration_check``):
    the evidence row's ``source`` prefix before the first ``/``.
    """
    findings: list[dict[str, Any]] = []
    fp = case_dir / "findings.json"
    if fp.is_file():
        try:
            raw = json.loads(fp.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                findings = [f for f in raw if isinstance(f, dict)]
        except (OSError, json.JSONDecodeError):
            findings = []
    if not findings:
        try:
            from nexus.case import CaseManager
            from nexus.config import settings

            mgr = CaseManager(settings.cases_root / "cases.db")
            try:
                for rec in mgr.list_findings(case_dir.name):
                    meta = dict(getattr(rec, "metadata", None) or {})
                    findings.append(
                        {
                            "id": getattr(rec, "id", ""),
                            "evidence": meta.get("evidence") or [],
                            "metadata": meta,
                        }
                    )
            finally:
                mgr.close()
        except Exception:  # noqa: BLE001
            pass

    families: set[str] = set()
    for finding in findings:
        rows = finding.get("evidence") or (finding.get("metadata") or {}).get("evidence") or []
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key in ("source", "family", "file"):
                val = str(row.get(key) or "").strip()
                if not val:
                    continue
                fam = val.split("/")[0].strip()
                if fam and fam not in {"-", "(none)", "n/a"}:
                    families.add(fam)
                if key != "source":
                    break
    return families, len(findings)


def _sources_section(case_dir: Path) -> dict[str, Any]:
    out: dict[str, Any] = {
        "status": _UNKNOWN,
        "reason": "",
        "indexed_families": [],
        "indexed_never_cited": [],
        "cited_not_indexed": [],
        "findings": 0,
    }
    cited, n_findings = _finding_citations(case_dir)
    out["findings"] = n_findings
    out["cited_families"] = sorted(cited)

    try:
        from nexus.langgraph.case_index import es_aggregate

        agg = es_aggregate(case_dir, field="family", top=200, match_all=True)
    except Exception as exc:  # noqa: BLE001
        out["reason"] = f"per-family index counts unavailable: {exc}"
        return out

    # `es_aggregate` returns either `top: [{value, count}]` (terms path) or
    # `buckets: {key: count}` (time-bucket path). Read both.
    indexed: dict[str, int] = {}
    if isinstance(agg, dict):
        for item in agg.get("top") or []:
            if not isinstance(item, dict):
                continue
            key = str(item.get("value") or item.get("key") or "").strip()
            if not key:
                continue
            try:
                indexed[key] = int(item.get("count") or item.get("doc_count") or 0)
            except (TypeError, ValueError):
                indexed[key] = 0
        buckets = agg.get("buckets")
        if isinstance(buckets, dict):
            for key, count in buckets.items():
                name = str(key).strip()
                if not name:
                    continue
                try:
                    indexed[name] = int(count or 0)
                except (TypeError, ValueError):
                    indexed[name] = 0
        out["backend"] = str(agg.get("backend") or "")
        out["indexed_rows"] = int(agg.get("rows_scanned") or 0)

    if not indexed:
        state = case_dir / "analysis" / "index_state.json"
        total = ""
        if state.is_file():
            try:
                docs = int(json.loads(state.read_text(encoding="utf-8")).get("docs") or 0)
                total = f"; index_state reports {docs:,} docs total"
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                total = ""
        out["reason"] = f"no indexed rows to audit{total}"
        return out

    out["indexed_families"] = [
        {"family": fam, "docs": docs}
        for fam, docs in sorted(indexed.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    out["indexed_never_cited"] = [
        {"family": row["family"], "docs": row["docs"]}
        for row in out["indexed_families"]
        if row["family"] not in cited
    ]
    out["cited_not_indexed"] = sorted(f for f in cited if f not in indexed)
    out["status"] = _GAPS if (out["indexed_never_cited"] or out["cited_not_indexed"]) else _OK
    return out


# ── section 3: needles ───────────────────────────────────────────────────────


def _needles_section(case_dir: Path) -> dict[str, Any]:
    out: dict[str, Any] = {
        "status": _UNKNOWN,
        "reason": "",
        "requested": 0,
        "scanned": 0,
        "not_scanned": 0,
        "hit": 0,
        "zero_hit_scanned": 0,
        "not_scanned_needles": [],
        "truncated_reasons": [],
    }
    csv_path = case_dir / "analysis" / "signal_map.csv"
    if not csv_path.is_file():
        out["reason"] = "no analysis/signal_map.csv — the needle scan has not run for this case"
        return out
    try:
        with csv_path.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = [r for r in reader if r]
    except (OSError, csv.Error) as exc:
        out["reason"] = f"signal_map.csv unreadable: {exc}"
        return out
    if not rows:
        out["reason"] = "signal_map.csv has no rows"
        return out

    for row in rows:
        needle = str(row.get("needle") or "").strip()
        try:
            hits = int(str(row.get("hits") or "0").strip() or 0)
        except ValueError:
            hits = 0
        scanned = str(row.get("scanned") or "").strip().lower() in {"yes", "true", "1"}
        out["requested"] += 1
        if scanned:
            out["scanned"] += 1
            if hits > 0:
                out["hit"] += 1
            else:
                out["zero_hit_scanned"] += 1
        else:
            out["not_scanned"] += 1
            out["not_scanned_needles"].append(needle)

    # Truncation reasons live in the briefing markdown's warning block and in
    # the scan stats; both are optional, so absence is not an error.
    brief_md = case_dir / "analysis" / "briefing.md"
    if brief_md.is_file():
        try:
            text = brief_md.read_text(encoding="utf-8")
        except OSError:
            text = ""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(">") and ("NOT" in stripped or "truncat" in stripped.lower()):
                out["truncated_reasons"].append(stripped.lstrip("> ").strip()[:300])

    out["status"] = _GAPS if out["not_scanned"] else _OK
    return out


# ── assembly ─────────────────────────────────────────────────────────────────


def build_coverage_audit(case_dir: Path | str) -> dict[str, Any]:
    """Build the audit. Never raises: a broken section is ``unknown``."""
    case_dir = Path(case_dir)
    sections: dict[str, Any] = {}
    unavailable: list[str] = []
    for name, fn in (("tools", _tools_section), ("sources", _sources_section), ("needles", _needles_section)):
        try:
            section = fn(case_dir)
        except Exception as exc:  # noqa: BLE001
            section = {"status": _UNKNOWN, "reason": f"section failed: {exc}"[:300]}
        sections[name] = section
        if section.get("status") == _UNKNOWN:
            unavailable.append(f"{name}: {section.get('reason') or 'unknown'}")

    statuses = {s.get("status") for s in sections.values()}
    if _GAPS in statuses:
        overall = _GAPS
    elif _UNKNOWN in statuses:
        overall = _UNKNOWN
    else:
        overall = _OK

    meta_name = ""
    case_yaml = case_dir / "CASE.yaml"
    if case_yaml.is_file():
        try:
            import yaml

            meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
            meta_name = str(meta.get("name") or "") if isinstance(meta, dict) else ""
        except Exception:  # noqa: BLE001
            meta_name = ""

    return {
        "schema": SCHEMA_VERSION,
        "case_id": case_dir.name,
        "case_name": meta_name,
        "generated_at": _now(),
        "overall": overall,
        "unavailable": unavailable,
        **sections,
    }


def write_coverage_audit(case_dir: Path | str) -> tuple[Path, dict[str, Any]]:
    """Persist ``analysis/coverage_audit.json``; return (path, audit)."""
    case_dir = Path(case_dir)
    audit = build_coverage_audit(case_dir)
    analysis = case_dir / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    path = analysis / AUDIT_FILENAME
    path.write_text(json.dumps(audit, indent=2, sort_keys=True), encoding="utf-8")
    return path, audit


def load_coverage_audit(case_dir: Path | str) -> dict[str, Any]:
    """Read a persisted audit; {} when absent or unreadable."""
    path = Path(case_dir) / "analysis" / AUDIT_FILENAME
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def summary_lines(audit: dict[str, Any], *, limit: int = 6) -> list[str]:
    """Briefing/report-safe one-liners. Never hides an unknown."""
    if not audit:
        return []
    overall = str(audit.get("overall") or _UNKNOWN)
    tools = audit.get("tools") or {}
    sources = audit.get("sources") or {}
    needles = audit.get("needles") or {}
    out = [f"Coverage audit: **{overall.upper()}** (tools {tools.get('status')}, sources {sources.get('status')}, needles {needles.get('status')})"]

    if tools.get("status") == _GAPS:
        c = tools.get("counts") or {}
        out.append(
            f"- Tools: {c.get('applicable_not_parsed', 0)} applicable artifact(s) never parsed, "
            f"{c.get('failed', 0)} tool failure(s), {c.get('pending', 0)} job(s) still pending."
        )
        for row in (tools.get("applicable_not_parsed") or [])[:limit]:
            out.append(
                f"  - **{row.get('artifact', '?')}** present ({row.get('hits', '?')} hit(s)) but never parsed "
                f"by {', '.join(row.get('never_invoked') or row.get('tools') or []) or 'any scheduled tool'}"
            )
    elif tools.get("status") == _UNKNOWN:
        out.append(f"- Tools: NOT AUDITED — {tools.get('reason') or 'unknown'}")

    if sources.get("status") == _GAPS:
        never = sources.get("indexed_never_cited") or []
        out.append(
            f"- Sources: {len(never)} indexed famil{'y' if len(never) == 1 else 'ies'} never cited by any finding"
            + (f" ({', '.join(str(r.get('family')) for r in never[:limit])})" if never else "")
        )
        missing = sources.get("cited_not_indexed") or []
        if missing:
            out.append(
                f"- Sources: {len(missing)} cited famil{'y' if len(missing) == 1 else 'ies'} not in the index "
                f"({', '.join(missing[:limit])}) — citation integrity check."
            )
    elif sources.get("status") == _UNKNOWN:
        out.append(f"- Sources: NOT AUDITED — {sources.get('reason') or 'unknown'}")

    if needles.get("status") == _GAPS:
        out.append(
            f"- Needles: {needles.get('not_scanned', 0)} of {needles.get('requested', 0)} never queried — "
            f"their absence is NOT evidence. {needles.get('zero_hit_scanned', 0)} genuinely scanned needle(s) found nothing."
        )
        for needle in (needles.get("not_scanned_needles") or [])[:limit]:
            out.append(f"  - not queried: `{needle}`")
    elif needles.get("status") == _UNKNOWN:
        out.append(f"- Needles: NOT AUDITED — {needles.get('reason') or 'unknown'}")

    if overall == _OK:
        out.append("- Every applicable tool ran, every indexed family is cited, every needle was genuinely scanned.")
    for note in audit.get("unavailable") or []:
        out.append(f"- unavailable: {note}")
    return out


def report_section(audit: dict[str, Any]) -> list[str]:
    """Markdown block for REPORT.md (empty when there is no audit yet)."""
    if not audit:
        return []
    lines = ["## Coverage audit", ""]
    lines.extend(summary_lines(audit, limit=10))
    lines.append("")
    return lines
