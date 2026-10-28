"""Case Digest — the deterministic "everything" the Mode 2/3 LLM receives.

Operator rule (2026-09-17): *feed the LLM everything, in however efficient a
form.* The digest is that form: every deterministic fact the case holds —
the alert surface (every crit/high lead, keyed by its audit id), the top
leads, typed entities with first/last seen, coverage/ledger, timeline shape,
and an explicit **scope statement** (what artifact classes exist — and what
does not: no disk/memory/network when that is the truth). Keyword-needle
counts are not facts about the case and are not in it (Part 12 FM-3); the
run's threat-intel block reaches the prompt beside it (D456).

It is compact at the aggregate level and complete at the case level; raw
detail is pulled on demand (`n4_sample`/`n4_query`). Built from the briefing
primitives + ES aggregations (exact counts, CSV parity). Written to
``analysis/case_digest.json`` + ``.md``.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_NETWORK_FAMILIES = ("suricata", "zeek", "wireshark", "sysdig", "pcap", "netflow", "arkime")
_CLOUD_FAMILIES = ("cloudtrail", "azure", "m365", "o365", "entra", "gcp", "aws")
_EMAIL_FAMILIES = ("email", "eml", "msg", "mbox", "pst", "ost")
_SIEM_FAMILIES = ("splunk", "elastic", "security_onion", "wazuh", "socrates", "syslog", "socrate")
_MEMORY_FAMILIES = ("volatility", "memprocfs", "memory")
_LINUX_FAMILIES = ("auditd", "authlog", "auth", "bash_history", "linux")
_DISK_FAMILIES = ("plaso", "log2timeline", "super_timeline")


def _classify(families: list[str]) -> dict[str, list[str]]:
    from nexus.langgraph.lane_gate import _MEMORY_JOB_TOOLS

    low = {f.lower(): f for f in families}

    def named(lower: str, hints: tuple[str, ...]) -> bool:
        # A family is an identifier the lane or an importer chose (`zeek_conn`, `pff-ost`), so a hint
        # names the whole family or one of its parts. It used to match any substring: `pstranscript`
        # (PowerShell transcripts) was email for its "pst", `oauth` would be Linux for its "auth" (D205).
        return lower in hints or any(part in hints for part in re.split(r"[-_.\s]+", lower))

    def pick(hints: tuple[str, ...]) -> list[str]:
        return [orig for lower, orig in low.items() if named(lower, hints)]

    # A family named for the memory job that wrote it is memory: the SIFT lane's Volatility output is
    # the family `vol`, which no name hint matched, so 88,965 memory rows were "host" (D204).
    memory = sorted(set(pick(_MEMORY_FAMILIES))
                    | {orig for lower, orig in low.items() if lower in _MEMORY_JOB_TOOLS})
    host = [
        orig for lower, orig in low.items()
        if orig not in memory and not named(lower, (
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
        "memory": memory,
        "linux": sorted(pick(_LINUX_FAMILIES)),
        "disk_timeline": sorted(pick(_DISK_FAMILIES)),
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
                case_dir, "", field=field, top=0, match_all=True, with_spans=True,
            )
            if result:
                out[field] = result.get("top") or []
        return out
    except Exception as exc:  # noqa: BLE001
        log.debug("digest entity spans unavailable: %s", exc)
        return {}


def _host_identity(case_dir: Path) -> dict[str, Any]:
    """The machines the case's event logs show under several names (D212)."""
    from nexus.analysis.host_identity import host_identity

    return host_identity(case_dir)


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

    # D456: no threat-intel block. The digest is built before the run's TI stage (which needs the
    # leads above), so `analysis/ti_context.md` here was the previous run's; the run's own TI block
    # reaches the prompt beside the digest.
    return {
        "case_id": case_dir.name,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": scope,
        "ts_coverage": _ts_coverage(case_dir),
        "ts_coverage_capped": _ts_coverage_capped(case_dir),
        "inventory": brief.get("inventory") or {},
        "ledger": brief.get("ledger") or {},
        "hosts": brief.get("hosts") or [],
        "time_range": brief.get("time_range") or {},
        "intake": brief.get("intake") or {},
        "alerts": brief.get("alerts") or [],
        "top_leads": top_leads(case_dir),
        "entities": brief.get("entities") or {},
        "entity_spans": _entity_spans(case_dir),
        "host_identity": _host_identity(case_dir),
        "timeline": _timeline(case_dir),
    }


def lead_citation(lead: dict[str, Any]) -> str:
    """`` [audit_id X]`` for a lead whose rows an audited call holds, '' for a lead with none.

    The same marker the loop puts on its own query results, so a model cites a lead the way it
    cites a query (``analysis/leads.py`` `_cite_leads`).
    """
    ids = [str(a) for a in (lead.get("audit_ids") or []) if a]
    citation = f" [audit_id {ids[0]}]" if ids else ""
    extra = lead.get("extra") or {}
    facts = lead.get("pinned_source_facts") or extra.get("pinned_source_facts") or []
    grouped: dict[tuple[str, str, str], list[str]] = {}
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        source = str(fact.get("source") or "").strip()
        version = str(fact.get("source_version") or "").strip()
        digest = str(fact.get("source_sha256") or "").strip()
        key = str(fact.get("source_key") or "").strip()
        if source and version and digest and key:
            grouped.setdefault((source, version, digest), []).append(key)
    if grouped:
        pins = [f"{source}@{version}#{','.join(keys)} sha256={digest}"
                for (source, version, digest), keys in grouped.items()]
        citation += " [pinned sources: " + "; ".join(pins) + "]"
    return citation


def top_leads(case_dir, *, limit: int = 40) -> list[dict[str, Any]]:
    """The case's top leads, for every mode to see the same signals.

    WO-R1F item 1: "Every mode gets the same top leads." Mode 2's director and
    Mode 3's supervisor already read the leads file; this puts the same top
    ``limit`` into the digest, so Mode 1's orient prompt and every Mode 3 seat
    get them too. Never raises — a case that has not built leads yields [].
    """
    path = Path(case_dir) / "analysis" / "leads.jsonl"
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                lead = json.loads(line)
            except ValueError:
                continue
            out.append({
                "kind": str(lead.get("kind") or ""),
                "subject": str(lead.get("subject") or ""),
                "detail": str(lead.get("detail") or "")[:300],
                "score": lead.get("score") or 0.0,
                "level": str((lead.get("extra") or {}).get("level") or ""),
                "engine": str((lead.get("extra") or {}).get("engine") or ""),
                "crit_high": bool((lead.get("extra") or {}).get("crit_high")),
                # The call that holds this lead's rows: a finding drawn from the lead cites it.
                "audit_ids": [str(a) for a in (lead.get("audit_ids") or []) if a],
                "attack_ids": [str(t) for t in ((lead.get("extra") or {}).get("attack_ids")
                                                or (lead.get("extra") or {}).get("techniques") or []) if t],
                "pinned_source_facts": list((lead.get("extra") or {}).get("pinned_source_facts") or []),
                # IC-5: the ATT&CK software the lead's detection names (its hunt list reaches the prompt).
                "software": [str(s.get("id")) for s in ((lead.get("extra") or {}).get("software") or [])
                             if isinstance(s, dict) and s.get("id")],
            })
            if len(out) >= limit:
                break
    except OSError:
        return []
    return out


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


def _ts_coverage_capped(case_dir) -> bool:
    """True when index caps were set, so ts coverage is partial."""
    import json

    path = case_dir / "analysis" / "es_index.json"
    if not path.is_file():
        return False
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return bool(meta.get("capped"))


def render_digest_markdown(digest: dict[str, Any]) -> str:
    lines: list[str] = [
        f"# Case Digest — {digest.get('case_id', '')}",
        "",
        f"Generated: {digest.get('generated_at', '')}",
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
        if digest.get("ts_coverage_capped"):
            lines.append(
                "_Partial: index caps were set (`NEXUS_INDEX_*`) — coverage "
                "counts only the indexed rows._"
            )
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
        # Every job, OK ones counted by tool and every other one whole (D216). The first 20 of 92 rows
        # used to be listed with no word of the rest: the memory jobs (MemProcFS, 31 Volatility runs)
        # came last and never showed, while the triage discovery's SKIP naming the memory image came
        # first, and Mode 1 recorded the memory image as unprocessed. A repeated message is one line with
        # its count (Part 12 FM-12: T22 printed one Volatility WARN eight times).
        entries = led.get("entries") or []
        ok: dict[str, int] = {}
        others: dict[tuple[str, str, str], int] = {}
        for entry in entries:
            status = str(entry.get("status") or "").upper()
            tool = str(entry.get("tool") or "")
            if status == "OK":
                ok[tool] = ok.get(tool, 0) + 1
            else:
                key = (str(entry.get("status") or ""), tool, str(entry.get("reason") or ""))
                others[key] = others.get(key, 0) + 1
        if ok:
            lines.append("- OK: " + ", ".join(
                f"{tool} x{n}" if n > 1 else tool for tool, n in sorted(ok.items())))
        for (status, tool, reason), n in others.items():
            lines.append(f"- {status}: {tool}{' x' + str(n) if n > 1 else ''}"
                         + (f" — {reason}" if reason else ""))
    alerts = digest.get("alerts") or []
    if alerts:
        # Every crit/high lead, each with the audit id of the rows it stands on (Part 12 FM-3, FM-9).
        lines.append("")
        lines.append(f"## Alert surface ({len(alerts)} crit/high leads; each is answered by its audit id)")
        for a in alerts:
            count = f" x{a['count']}" if a.get("count") else ""
            lines.append(
                f"- [{str(a.get('level', '')).upper()}] {a.get('family', '')} · {a.get('title', '')}{count} · "
                f"{a.get('host', '')} {a.get('time', '')} [audit_id {a.get('key', '')}]"
            )
    top_leads = digest.get("top_leads") or []
    if top_leads:
        # The same top leads every mode is handed (WO-R1F item 1). Severity is
        # explicit so a crit detection is never read as one lead among many.
        lines.append("")
        lines.append(f"## Top leads ({len(top_leads)})")
        for lead in top_leads[:40]:
            lvl = str(lead.get("level") or "").upper()
            tag = f"[{lvl}] " if lvl else ""
            lines.append(f"- {tag}{lead.get('subject', '')}: {lead.get('detail', '')}"
                         + lead_citation(lead))
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
    from nexus.analysis.host_identity import host_identity_lines

    identity = host_identity_lines(digest.get("host_identity") or {})
    if identity:
        lines.append("")
        lines.append("## Host identity (one machine, several names)")
        lines.extend(identity)
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
        # D224: the responders' activity is stated with what it means, as Modes 2 and 3 receive it.
        from nexus.langgraph.case_intake import responder_lines

        responder = responder_lines(intake)
        if responder:
            lines.append("")
            lines.append("## Responder activity " + responder[0])
            lines.extend(responder[1:])
    lines.append("")
    lines.append(
        "Each alert above is answered in the interpretation: a finding that cites its audit_id, or a "
        "disposition naming that audit_id (benign, refuted, coverage_gap or not_examined, with the reason "
        "from the rows). Absence of an artifact class is SCOPE, not a verdict."
    )
    return "\n".join(lines) + "\n"


def write_case_digest(case_dir: Path, digest: dict[str, Any]) -> dict[str, str]:
    """Persist analysis/case_digest.json + .md (best-effort)."""
    try:
        analysis = Path(case_dir) / "analysis"
        analysis.mkdir(parents=True, exist_ok=True)
        json_path = analysis / "case_digest.json"
        md_path = analysis / "case_digest.md"
        json_path.write_text(json.dumps(digest, indent=2, default=str), encoding="utf-8")
        md_path.write_text(render_digest_markdown(digest), encoding="utf-8")
        return {"json": str(json_path), "md": str(md_path)}
    except OSError as exc:
        log.warning("case digest write failed: %s", exc)
        return {}


def _cited(item: dict[str, Any]) -> set[str]:
    """Every audit id a finding or disposition cites."""
    ids = {str(a) for a in item.get("audit_ids") or [] if a}
    for key in ("artifacts", "evidence"):
        for entry in item.get(key) or []:
            if isinstance(entry, dict) and entry.get("audit_id"):
                ids.add(str(entry["audit_id"]))
    return ids


def reconciliation_checklist(digest: dict[str, Any],
                             findings: list[dict[str, Any]],
                             dispositions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Which alerts a finding answers (addressed), a disposition answers (dispositioned), or nothing does.

    An alert is a crit/high lead, keyed by the audit id of the rows it stands on. It is addressed when a
    finding cites one of its audit ids and dispositioned when a disposition cites one or names its key
    (Part 12 FM-3, FM-9). It used to be "addressed" when the first 48 characters of its title occurred in
    any finding's text, beside the 40 keyword needles a finding had to "mention".
    """
    finding_ids: set[str] = set()
    for f in findings or []:
        if isinstance(f, dict):
            finding_ids |= _cited(f)
    answered: set[str] = set()
    for d in dispositions or []:
        if isinstance(d, dict):
            answered |= _cited(d) | {" ".join(str(d.get("item") or "").split())}

    unaddressed: list[dict[str, str]] = []
    addressed: list[dict[str, str]] = []
    dispositioned: list[dict[str, str]] = []
    for alert in digest.get("alerts") or []:
        keys = {str(a) for a in alert.get("audit_ids") or [] if a} | {str(alert.get("key") or "")}
        keys.discard("")
        item = {
            "kind": "alert",
            "key": str(alert.get("key") or ""),
            "value": f"[{str(alert.get('level', '')).upper()}] {alert.get('title', '')} ({alert.get('host', '')})",
        }
        if keys & finding_ids:
            addressed.append(item)
        elif keys & answered:
            dispositioned.append(item)
        else:
            unaddressed.append(item)
    return {
        "addressed": addressed,
        "dispositioned": dispositioned,
        "unaddressed": unaddressed,
        "alerts_total": len(digest.get("alerts") or []),
    }
