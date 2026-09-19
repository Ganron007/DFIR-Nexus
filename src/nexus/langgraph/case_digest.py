"""Case Digest — the deterministic "everything" the Mode 2/3 LLM receives.

Operator rule (2026-09-17): *feed the LLM everything, in however efficient a
form.* The digest is that form: every deterministic fact the case holds —
signal map **including 0-hit needles** (negative evidence), the alert surface,
entities with first/last seen, coverage/ledger, timeline shape, threat intel,
and an explicit **scope statement** (what artifact classes exist — and what
does not: no disk/memory/network when that is the truth).

It is compact at the aggregate level and complete at the case level; raw
detail is pulled on demand (`n4_sample`/`n4_query`). Built from the briefing
primitives + ES aggregations (exact counts, CSV parity). Written to
``analysis/case_digest.json`` + ``.md``.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_NETWORK_FAMILIES = ("suricata", "zeek", "wireshark", "sysdig", "pcap", "netflow", "arkime")
_CLOUD_FAMILIES = ("cloudtrail", "azure", "m365", "o365", "entra", "gcp", "aws")
_EMAIL_FAMILIES = ("email", "eml", "msg", "mbox", "pst")
_SIEM_FAMILIES = ("splunk", "elastic", "security_onion", "wazuh", "socrates", "syslog", "socrate")
_MEMORY_FAMILIES = ("volatility", "memprocfs", "memory")
_LINUX_FAMILIES = ("auditd", "authlog", "auth", "bash_history", "linux")
_DISK_FAMILIES = ("plaso", "log2timeline", "super_timeline")


def _classify(families: list[str]) -> dict[str, list[str]]:
    low = {f.lower(): f for f in families}

    def pick(hints: tuple[str, ...]) -> list[str]:
        return [orig for lower, orig in low.items() if any(h in lower for h in hints)]

    host = [
        orig for lower, orig in low.items()
        if not any(h in lower for h in (
            _NETWORK_FAMILIES + _CLOUD_FAMILIES + _EMAIL_FAMILIES
            + _SIEM_FAMILIES + _MEMORY_FAMILIES + _DISK_FAMILIES
        ))
    ]
    return {
        "host": sorted(host),
        "network": sorted(pick(_NETWORK_FAMILIES)),
        "cloud": sorted(pick(_CLOUD_FAMILIES)),
        "email": sorted(pick(_EMAIL_FAMILIES)),
        "siem": sorted(pick(_SIEM_FAMILIES)),
        "memory": sorted(pick(_MEMORY_FAMILIES)),
        "linux": sorted(pick(_LINUX_FAMILIES)),
        "disk_timeline": sorted(pick(_DISK_FAMILIES)),
    }


def _signal_map(case_dir: Path, brief: dict[str, Any]) -> dict[str, Any]:
    """Every scanned needle with its count — 0-hit needles are evidence too.

    A needle the scan could NOT query (``scanned=no``) is never presented as
    "checked, absent": it goes into ``unscanned`` and is excluded from the
    negative-evidence list.
    """
    rows: list[dict[str, Any]] = []
    csv_path = case_dir / "analysis" / "signal_map.csv"
    if csv_path.is_file():
        try:
            import csv as _csv

            with csv_path.open(encoding="utf-8", errors="replace") as fh:
                for row in _csv.DictReader(fh):
                    needle = str(row.get("needle") or "").strip()
                    if not needle:
                        continue
                    rows.append({
                        "needle": needle,
                        "hits": int(row.get("hits") or 0),
                        "source": str(row.get("source") or ""),
                        "scanned": str(row.get("scanned") or "yes").lower() != "no",
                    })
        except (OSError, ValueError):
            rows = []
    if not rows:
        rows = [
            {"needle": s["needle"], "hits": int(s.get("hits") or 0),
             "source": str(s.get("source") or ""), "scanned": True}
            for s in (brief.get("needle_scan") or [])
        ]
    with_hits = sorted([r for r in rows if r["hits"] > 0], key=lambda r: -r["hits"])
    zero_hit = sorted(
        [r for r in rows if r["hits"] == 0 and r.get("scanned", True)],
        key=lambda r: r["needle"],
    )
    unscanned = sorted(
        [r["needle"] for r in rows if not r.get("scanned", True)],
    )
    return {
        "scanned": len(rows),
        "with_hits": with_hits[:150],
        "zero_hit": [r["needle"] for r in zero_hit][:400],
        "unscanned": unscanned[:400],
    }


def _timeline(case_dir: Path) -> dict[str, Any]:
    try:
        from nexus.langgraph.case_index import es_aggregate

        result = es_aggregate(case_dir, "", field="host", bucket="day", match_all=True)
        if result and result.get("buckets"):
            return {"buckets_per_day": result["buckets"], "source": "elasticsearch"}
    except Exception as exc:  # noqa: BLE001
        log.debug("digest timeline unavailable: %s", exc)
    return {"buckets_per_day": {}, "source": "unavailable"}


def _entity_spans(case_dir: Path) -> dict[str, Any]:
    try:
        from nexus.langgraph.case_index import es_aggregate

        out: dict[str, Any] = {}
        for field in ("host", "user"):
            result = es_aggregate(
                case_dir, "", field=field, top=25, match_all=True, with_spans=True,
            )
            if result:
                out[field] = result.get("top") or []
        return out
    except Exception as exc:  # noqa: BLE001
        log.debug("digest entity spans unavailable: %s", exc)
        return {}


def build_case_digest(case_dir: Path, brief: dict[str, Any] | None = None) -> dict[str, Any]:
    """Assemble the deterministic digest for one case (no LLM involved).

    ``brief`` lets the caller hand in an already-cached briefing (the portal
    does) so the digest never re-runs the full extraction scan.
    """
    case_dir = Path(case_dir)
    if brief is None:
        from nexus.langgraph.briefing import case_briefing

        brief = case_briefing(case_dir)
    families = list(brief.get("families") or [])
    classes = _classify(families)
    scope = {
        "families_present": classes,
        "evidence_classes_present": [k for k, v in classes.items() if v],
        "explicitly_absent": [
            label for label, key in (
                ("network flows / PCAP", "network"),
                ("cloud audit logs", "cloud"),
                ("email archives", "email"),
                ("SIEM exports", "siem"),
                ("memory images", "memory"),
                ("linux host logs", "linux"),
                ("disk super-timeline", "disk_timeline"),
            ) if not classes.get(key)
        ],
    }

    ti_md = ""
    ti_path = case_dir / "analysis" / "ti_context.md"
    if ti_path.is_file():
        try:
            ti_md = ti_path.read_text(encoding="utf-8", errors="replace")[:20000]
        except OSError:
            ti_md = ""

    return {
        "case_id": case_dir.name,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": scope,
        "ts_coverage": _ts_coverage(case_dir),
        "inventory": brief.get("inventory") or {},
        "ledger": brief.get("ledger") or {},
        "hosts": brief.get("hosts") or [],
        "time_range": brief.get("time_range") or {},
        "intake": brief.get("intake") or {},
        "signal_map": _signal_map(case_dir, brief),
        "scan_stats": brief.get("scan_stats") or {},
        "alerts": brief.get("alerts") or [],
        "entities": brief.get("entities") or {},
        "entity_spans": _entity_spans(case_dir),
        "timeline": _timeline(case_dir),
        "ti_context_md": ti_md,
        "hits_examined": brief.get("hits_examined", 0),
        "scan_truncated": brief.get("scan_truncated", False),
        "backend": brief.get("backend", ""),
    }


def _ts_coverage(case_dir) -> dict[str, dict[str, int]]:
    """Per-family ts coverage recorded by the indexer (4k.4).

    Read from ``analysis/es_index.json``; empty when the case was never
    indexed (CSV-only) — callers label that instead of assuming zero.
    """
    import json

    path = case_dir / "analysis" / "es_index.json"
    if not path.is_file():
        return {}
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    cov = meta.get("ts_coverage")
    return cov if isinstance(cov, dict) else {}


def render_digest_markdown(digest: dict[str, Any]) -> str:
    lines: list[str] = [
        f"# Case Digest — {digest.get('case_id', '')}",
        "",
        f"Generated: {digest.get('generated_at', '')} · backend: {digest.get('backend', '')}",
        "",
        "## Scope (what this evidence IS — and what it is NOT)",
    ]
    scope = digest.get("scope") or {}
    for label, values in (scope.get("families_present") or {}).items():
        if values:
            lines.append(f"- {label}: {', '.join(values)}")
    absent = scope.get("explicitly_absent") or []
    if absent:
        lines.append(
            "- **NOT in evidence** (state this as scope, never as 'no compromise'): "
            + "; ".join(absent)
        )
    ts_cov = digest.get("ts_coverage") or {}
    if ts_cov:
        lines.append("")
        lines.append("## Timestamp coverage (per family)")
        for fam, cov in sorted(ts_cov.items()):
            present = int(cov.get("present") or 0)
            missing = int(cov.get("missing") or 0)
            synth = int(cov.get("synthesized") or 0)
            tz_a = int(cov.get("tz_assumed") or 0)
            yr_a = int(cov.get("year_assumed") or 0)
            if present + missing + synth == 0:
                continue
            notes = []
            if synth:
                notes.append(f"{synth} synthesized")
            if tz_a:
                notes.append(f"{tz_a} UTC-assumed")
            if yr_a:
                notes.append(f"{yr_a} year-assumed")
            suffix = f" ({'; '.join(notes)})" if notes else ""
            if present == 0:
                lines.append(
                    f"- {fam}: **no parsed event timestamps** — "
                    f"{missing} row(s) undated; do not read absence as timeline evidence{suffix}"
                )
            else:
                lines.append(f"- {fam}: {present} timestamped / {missing} undated{suffix}")
    inv = digest.get("inventory") or {}
    if inv:
        lines.append("")
        lines.append("## Evidence inventory")
        for fam, entry in sorted(inv.items(), key=lambda kv: -int(kv[1].get("rows") or 0)):
            lines.append(
                f"- {fam}: {entry.get('rows', 0)}{'+' if entry.get('capped') else ''} rows "
                f"({entry.get('files', 0)} file(s))"
            )
    led = digest.get("ledger") or {}
    if led.get("entries"):
        lines.append("")
        lines.append(
            f"## Parser ledger — {led.get('ok', 0)} OK / {led.get('skip', 0)} SKIP / "
            f"{led.get('fail', 0)} FAIL"
        )
        for entry in (led.get("entries") or [])[:20]:
            reason = f" — {entry.get('reason')}" if entry.get("reason") else ""
            lines.append(f"- {entry.get('status', '')}: {entry.get('tool', '')}{reason}")
    smap = digest.get("signal_map") or {}
    with_hits = smap.get("with_hits") or []
    if with_hits:
        lines.append("")
        lines.append(f"## Signal map — needles with hits ({len(with_hits)} shown)")
        lines.append(
            ", ".join(f"{r['needle']}({r['hits']})" for r in with_hits[:80])
        )
    zero = smap.get("zero_hit") or []
    if zero:
        lines.append("")
        lines.append(
            f"## Negative evidence — checked, 0 hits ({len(zero)} needles)"
        )
        lines.append(", ".join(zero[:120]))
    unscanned = smap.get("unscanned") or []
    if unscanned:
        lines.append("")
        lines.append(
            f"## NOT scanned — never queried ({len(unscanned)} needles; "
            "their absence is NOT evidence of absence):"
        )
        lines.append(", ".join(unscanned[:120]))
    stats = digest.get("scan_stats") or {}
    if stats.get("truncated"):
        lines.append("")
        lines.append(
            "> Hit counts below are LOWER BOUNDS — the scan was truncated by: "
            + "; ".join(stats.get("truncated_reasons") or ["unknown cap"])
            + ". Do not treat counts as exact."
        )
    alerts = digest.get("alerts") or []
    if alerts:
        lines.append("")
        lines.append(f"## Alert surface ({len(alerts)} high/critical)")
        for a in alerts[:60]:
            lines.append(
                f"- [{str(a.get('level', '')).upper()}] {a.get('family', '')} · "
                f"{a.get('title', '')} · {a.get('host', '')} {a.get('time', '')}"
            )
    entities = digest.get("entities") or {}
    spans = digest.get("entity_spans") or {}
    if entities:
        lines.append("")
        lines.append("## Entities")
        for etype, elist in sorted(entities.items()):
            vals = ", ".join(
                f"{e.get('value')}({e.get('hits', 0)})" for e in elist[:12]
            )
            lines.append(f"- {etype}: {vals}")
    for field in ("host", "user"):
        items = spans.get(field) or []
        if items:
            lines.append(f"- {field} spans: " + ", ".join(
                f"{i['value']}({i['count']}; {i.get('first_seen', '?')}→{i.get('last_seen', '?')})"
                for i in items[:10]
            ))
    tl = digest.get("timeline") or {}
    if tl.get("buckets_per_day"):
        buckets = list((tl.get("buckets_per_day") or {}).items())[:30]
        lines.append("")
        lines.append("## Timeline (events per day)")
        lines.append(", ".join(f"{day}:{count}" for day, count in buckets))
    tr = digest.get("time_range") or {}
    if tr.get("start"):
        lines.append(f"Time range: {tr['start']} → {tr['end']}")
    intake = digest.get("intake") or {}
    if intake:
        lines.append("")
        lines.append("## Examiner intake")
        for key, value in intake.items():
            lines.append(f"- {key}: {value}")
    ti = digest.get("ti_context_md") or ""
    if ti:
        lines.append("")
        lines.append(ti)
    lines.append("")
    lines.append(
        "EVERY item above must receive a disposition in the interpretation: "
        "backed by evidence rows, assessed benign with a reason, or recorded "
        "as a coverage gap. Absence of an artifact class is SCOPE, not a verdict."
    )
    return "\n".join(lines) + "\n"


def write_case_digest(case_dir: Path, digest: dict[str, Any]) -> dict[str, str]:
    """Persist analysis/case_digest.json + .md (best-effort)."""
    try:
        analysis = Path(case_dir) / "analysis"
        analysis.mkdir(parents=True, exist_ok=True)
        json_path = analysis / "case_digest.json"
        md_path = analysis / "case_digest.md"
        payload = {k: v for k, v in digest.items() if k != "ti_context_md"}
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        md_path.write_text(render_digest_markdown(digest), encoding="utf-8")
        return {"json": str(json_path), "md": str(md_path)}
    except OSError as exc:
        log.warning("case digest write failed: %s", exc)
        return {}


def reconciliation_checklist(digest: dict[str, Any],
                             findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic addressed/unaddressed check of the digest vs findings.

    Every alert ≥ high and every high-count needle must be mentioned by at
    least one staged finding; anything not mentioned is an explicit gap the
    verdict must address (never silently omitted).
    """
    parts: list[str] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        parts.extend(
            str(f.get(k) or "") for k in ("title", "observation", "interpretation")
        )
        # Evidence VALUES only — never the dict structure, or every finding
        # with an evidence row would "mention" needles like source/detail.
        for ev in (f.get("evidence") or []):
            if isinstance(ev, dict):
                parts.append(str(ev.get("detail") or ""))
            elif isinstance(ev, str):
                parts.append(ev)
    blob = " ".join(parts).lower()

    unaddressed: list[dict[str, str]] = []
    addressed: list[dict[str, str]] = []
    seen: set[str] = set()
    for alert in (digest.get("alerts") or [])[:60]:
        title = str(alert.get("title") or "").strip()
        key = title[:48].lower()
        if not key or key in seen:
            continue
        seen.add(key)
        item = {
            "kind": "alert",
            "value": f"[{str(alert.get('level', '')).upper()}] {title} ({alert.get('host', '')})",
        }
        (addressed if key in blob else unaddressed).append(item)

    high_needles = [r for r in (digest.get("signal_map") or {}).get("with_hits", []) if r.get("hits", 0) >= 3]
    for row in high_needles[:40]:
        needle = str(row.get("needle") or "").lower()
        if not needle or needle in seen:
            continue
        seen.add(needle)
        item = {"kind": "needle", "value": f"{row.get('needle')} ({row.get('hits')} hits)"}
        (addressed if needle in blob else unaddressed).append(item)

    return {
        "addressed": addressed,
        "unaddressed": unaddressed[:40],
        "alerts_total": len(digest.get("alerts") or []),
        "needles_with_hits": len((digest.get("signal_map") or {}).get("with_hits") or []),
    }
