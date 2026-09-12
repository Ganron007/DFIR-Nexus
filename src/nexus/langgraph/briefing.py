"""Case briefing — WP 4i.1/4i.2.

Auto-generated after N3 indexing (and on demand). The examiner's first view
of a processed case: what was collected, what the signatures already caught,
where the signal density is, and what they said they were looking for.

Deterministic by default — no LLM required. One bounded extraction scan
powers three surfaces: needle hit-counts (playbook auto-scan), alert rows
(Hayabusa/Zircolite severity), and entity top-N. The optional LLM layer
(mode1 directions) consumes this structure, never replaces it.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Bounded scan for the briefing. Larger than a needle query (we want breadth)
# but still capped — a briefing is a map, not the whole dataset.
_BRIEFING_SCAN_TERMS_CAP = 300
_ENTITY_TOP_N = 8
_ALERT_LEVELS = {"critical", "high"}
_ALERT_FAMILY_HINTS = ("hayabusa", "zircolite", "deepblue", "sigma")
_ROW_COUNT_CAP = 5_000_000  # safety valve per file


# ---------------------------------------------------------------------------
# Inventory — what was actually processed
# ---------------------------------------------------------------------------

def _family_inventory(case_dir: Path) -> dict[str, dict[str, Any]]:
    """Per-family file/row counts + hosts seen, from the tools extractions.

    Streams line counts (bounded) — fast on real cases, honest about caps.
    """
    from nexus.langgraph.query_pack import iter_extraction_files

    out: dict[str, dict[str, Any]] = {}
    for path, _root, fam in iter_extraction_files(case_dir, max_bytes=None):
        entry = out.setdefault(fam, {"files": 0, "rows": 0, "capped": False})
        entry["files"] += 1
        try:
            n = 0
            with path.open("rb") as fh:
                for _ in fh:
                    n += 1
                    if n > _ROW_COUNT_CAP:
                        entry["capped"] = True
                        break
            # minus header line for CSV-ish outputs
            entry["rows"] += max(0, n - 1)
        except OSError:
            continue
    return out


def _parser_ledger(case_dir: Path) -> dict[str, Any]:
    """Tool-lane ledger: what ran OK / SKIP'd / FAILed with reasons."""
    from nexus.langgraph.pipeline_runs import resolve_run, resolve_tools_extractions

    candidates: list[Path] = []
    run_id = ""
    try:
        run = resolve_run(case_dir, "tools")
        run_id = run.run_id
        candidates.extend([
            run.extractions / "_tool_lane_ledger.json",
            run.path / "ledger" / "_tool_lane_ledger.json",
        ])
    except Exception:  # noqa: BLE001
        pass
    # Fallback: the plain extractions dir (resolve_tools_extractions default)
    candidates.append(resolve_tools_extractions(case_dir) / "_tool_lane_ledger.json")

    entries: list[dict[str, Any]] = []
    for lp in candidates:
        if lp.is_file():
            try:
                parsed = json.loads(lp.read_text(encoding="utf-8"))
                if isinstance(parsed, list):
                    entries = parsed
                    break
            except (json.JSONDecodeError, OSError):
                continue

    slim = [
        {
            "tool": str(e.get("tool") or e.get("name") or ""),
            "status": str(e.get("status") or "").upper(),
            "family": str(e.get("family") or ""),
            "reason": str(e.get("reason") or e.get("detail") or "")[:200],
        }
        for e in entries
        if isinstance(e, dict)
    ]
    return {
        "run_id": run_id,
        "entries": slim,
        "ok": sum(1 for e in slim if e["status"] == "OK"),
        "skip": sum(1 for e in slim if e["status"] in {"SKIP", "SKIPPED"}),
        "fail": sum(1 for e in slim if e["status"] in {"FAIL", "FAILED", "ERROR"}),
    }


# ---------------------------------------------------------------------------
# Needle sources for the auto-scan
# ---------------------------------------------------------------------------

def _scan_needles(case_dir: Path, families: list[str]) -> dict[str, str]:
    """needle -> source label, for the families present in the case."""
    from nexus.knowledge.attack_needles import attack_needles_for
    from nexus.knowledge.sigma_needles import sigma_needles_for
    from nexus.langgraph.query_pack import (
        playbook_strong_terms_for_families,
        playbook_terms_for_families,
    )

    fams = set(families)
    needles: dict[str, str] = {}
    for t in playbook_strong_terms_for_families(fams):
        needles.setdefault(t.lower(), "playbook-strong")
    for t in playbook_terms_for_families(fams):
        needles.setdefault(t.lower(), "playbook")
    for t in attack_needles_for(fams, limit=8, cap=60):
        needles.setdefault(t.lower(), "attack")
    for t in sigma_needles_for(fams, limit=8, cap=60):
        needles.setdefault(t.lower(), "sigma")

    # Intake extras + question terms the examiner already named
    try:
        from nexus.langgraph.query_pack import collect_query_terms, load_case_intake

        for t in collect_query_terms(load_case_intake(case_dir)):
            needles.setdefault(t.lower(), "intake")
    except Exception:  # noqa: BLE001
        pass

    return dict(list(needles.items())[:_BRIEFING_SCAN_TERMS_CAP])


# ---------------------------------------------------------------------------
# Briefing assembly — one scan powers everything
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# WP 4j.3 — guided first pass: the order an examiner walks a fresh case
# ---------------------------------------------------------------------------

def _alert_needle(alert: dict[str, Any]) -> tuple[str, str]:
    """Best 'run this' term for an alert: top confirm query, else title/family."""
    it = alert.get("interpret") or {}
    for skill in it.get("skills") or []:
        for c in skill.get("confirm") or []:
            q = str(c.get("query") or "").strip()
            if q:
                return q, str(alert.get("family") or "")
    return str(alert.get("title") or alert.get("family") or ""), str(alert.get("family") or "")


def _walkthrough_learn(
    families: list[str],
    alerts: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[str]]:
    """Technique notes + playbook triggers for the case, for teaching steps.

    WP 4j.4: the walkthrough should explain *why* each step matters, not just
    list actions. Reuses the interpretation layer's technique-name/FD-004
    caveat lookup and the playbooks' own suspicion triggers.
    """
    try:
        from nexus.langgraph.interpret import _playbook_triggers, _technique_notes
        from nexus.langgraph.query_pack import playbook_techniques_for_families
    except Exception:  # noqa: BLE001
        return [], []

    tech_ids: set[str] = set(playbook_techniques_for_families(families))
    for a in alerts:
        tech_ids.update((a.get("interpret") or {}).get("techniques") or [])
    notes = _technique_notes(sorted(tech_ids))

    triggers: list[str] = []
    for fam in families[:8]:
        for t in _playbook_triggers(fam, limit=2):
            if t not in triggers:
                triggers.append(t)
    return notes, triggers


def _guided_first_pass(
    *,
    alerts: list[dict[str, Any]],
    entities: dict[str, list[dict[str, Any]]],
    needle_scan: list[dict[str, Any]],
    hosts: list[str],
    families: list[str],
) -> list[dict[str, Any]]:
    """The deterministic Mode 1 walkthrough.

    Four steps in examiner order: triage the alerts, map who/where, read the
    signal clusters, then the concrete starting points. Each step carries
    grounded actions (a needle + family) so the examiner can act without
    thinking about query syntax. Ranking is by real counts, never invented.
    """
    steps: list[dict[str, Any]] = []
    tech_notes, pb_triggers = _walkthrough_learn(families, alerts)
    tech_caveats = [str(t.get("caveat") or "") for t in tech_notes if t.get("caveat")]

    # 1) Triage — the signatures already fired.
    alert_actions: list[dict[str, Any]] = []
    for a in alerts[:5]:
        needle, fam = _alert_needle(a)
        if not needle:
            continue
        alert_actions.append({
            "label": str(a.get("title") or a.get("family") or "")[:120],
            "needle": needle[:120],
            "family": fam[:40],
            "level": str(a.get("level") or ""),
            "host": str(a.get("host") or ""),
        })
    if alerts:
        alert_why = (
            f"{len(alerts)} critical/high detection row(s) already fired. "
            "Confirm or dismiss each before hunting — the signature did the "
            "first pass for you."
        )
    else:
        alert_why = (
            "No critical/high detection rows. That is itself a signal — either "
            "the host is clean of known-bad patterns or logging coverage is "
            "thin. Proceed to map who/where before assuming the first."
        )
    steps.append({
        "order": 1,
        "key": "alerts",
        "title": "Triage the alerts",
        "why": alert_why,
        "count": len(alerts),
        "actions": alert_actions,
        "learn": {
            "headline": "A detection signature is a lead, not a conclusion.",
            "why_matters": (
                tech_caveats
                or ["Signatures have false positives — verify before you escalate."]
            )[:4],
            "sources": [s for s, have in (("technique", bool(tech_caveats)),) if have],
        },
    })

    # 2) Who/where — entity map + hosts.
    ent_actions: list[dict[str, Any]] = []
    for etype, elist in entities.items():
        for e in elist[:2]:
            fam = (e.get("families") or [""])[0]
            ent_actions.append({
                "label": f"{etype}: {e.get('value')}",
                "needle": str(e.get("value") or ""),
                "family": str(fam or ""),
                "hits": int(e.get("hits") or 0),
                "etype": etype,
            })
    steps.append({
        "order": 2,
        "key": "entities",
        "title": "Map who and where",
        "why": (
            f"{len(entities)} entity type(s) across {len(hosts)} host(s). "
            "Pivot on the loudest accounts, processes, and addresses to see "
            "whether the activity concentrates or is broad."
        ),
        "count": len(entities),
        "actions": ent_actions[:8],
        "learn": {
            "headline": "Attackers reuse the same accounts, hosts, and tools.",
            "why_matters": [
                "One account touching many hosts suggests lateral movement; "
                "one host touched by many accounts suggests credential spray.",
                "A process appearing in execution artifacts AND network artifacts "
                "is stronger than either alone (corroboration, FD-006).",
                "Broad, shallow activity is often benign admin; narrow, deep "
                "activity on one target is the pattern worth chasing.",
            ],
            "sources": ["playbook"] if pb_triggers else [],
        },
    })

    # 3) What fired — signal clusters by needle volume.
    scan_actions = [
        {
            "label": str(s.get("needle") or ""),
            "needle": str(s.get("needle") or ""),
            "family": "",
            "hits": int(s.get("hits") or 0),
            "source": str(s.get("source") or ""),
        }
        for s in needle_scan[:8]
    ]
    steps.append({
        "order": 3,
        "key": "signals",
        "title": "Read the signal clusters",
        "why": (
            f"{len(needle_scan)} needle(s) with hits. Volume is not proof, but "
            "a cluster of related needles is where a story forms. Start with "
            "the highest-count needles that fit the intake question."
        ),
        "count": len(needle_scan),
        "actions": scan_actions,
        "learn": {
            "headline": (
                "Techniques present: "
                + ", ".join(f"{t['name']} ({t['id']})" for t in tech_notes if t.get("name"))
            ) if tech_notes else "These needles are the vocabulary of the case.",
            "why_matters": pb_triggers[:4],
            "sources": [s for s, have in (
                ("technique", bool(tech_notes)),
                ("playbook", bool(pb_triggers)),
            ) if have],
        },
    })

    # 4) Starting points — the cross-cutting terms to run first. Alerts beat
    # signal clusters beat entities; each needle appears once.
    starts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for a in [*alert_actions, *scan_actions, *ent_actions]:
        n = str(a.get("needle") or "")
        if n and n.lower() not in seen:
            seen.add(n.lower())
            starts.append(a)
    steps.append({
        "order": 4,
        "key": "starting_points",
        "title": "Run the starting points",
        "why": (
            "Concrete first queries drawn from the alerts, signal clusters, and "
            "top entities above. Run them, read the rows with their "
            "interpretation, then steer with your own questions."
        ),
        "count": len(starts[:6]),
        "actions": starts[:6],
        "learn": {
            "headline": "Start specific, then widen only if the story holds.",
            "why_matters": [
                "Read each row's interpretation before drawing a conclusion — "
                "the meaning and what-to-check panel is the teaching layer.",
                "If a query returns nothing, that absence is evidence too "
                "(negative evidence) — record what you expected and did not find.",
                "When the deterministic steps run dry, switch to Steer Chat and "
                "ask your own question — you stay the driver.",
            ],
            "sources": [],
        },
    })

    return steps


def case_briefing(case_dir: Path, *, limit: int = 1200) -> dict[str, Any]:
    """Deterministic case briefing.

    Returns:
        inventory   — per-family {files, rows}
        ledger      — parser run status (ok/skip/fail + per-tool entries)
        hosts       — hosts seen in hits
        time_range  — {start, end} best-effort from hit timestamps
        alerts      — high/critical severity rows (hayabusa/zircolite/…)
        needle_scan — [{needle, hits, source}] sorted by hit count desc
        entities    — top-N per entity type with family coverage
        intake      — question / subjects / hypothesis / suspicion echo
    """
    from nexus.langgraph.entities import extract_entities
    from nexus.langgraph.query_pack import attach_hit_fields, n4_hits

    case_dir = Path(case_dir)
    inventory = _family_inventory(case_dir)
    families = sorted(inventory)

    needle_map = _scan_needles(case_dir, families)
    terms = list(needle_map)
    hits: list[dict[str, Any]] = []
    backend = ""
    if terms and families:
        try:
            hits, backend = n4_hits(case_dir, terms, (None, None))
        except Exception as exc:  # noqa: BLE001
            log.debug("briefing scan failed: %s", exc)
            hits, backend = [], ""
    # Per-needle counts below are computed inside this window — when the scan
    # is truncated, "rundll32 (21)" means "at least 21", and Explore may find
    # more. The flag lets the UI mark those chips honestly.
    scan_truncated = len(hits) > limit
    hits = attach_hit_fields(case_dir, hits)[:limit]

    # --- needle -> hit count (from matched terms recorded per hit) ---
    counts: dict[str, int] = {t: 0 for t in needle_map}
    for h in hits:
        for t in str(h.get("terms") or "").split(","):
            t = t.strip().lower()
            if t in counts:
                counts[t] += 1
    needle_scan = [
        {"needle": n, "hits": c, "source": needle_map[n]}
        for n, c in counts.items()
        if c > 0
    ]
    needle_scan.sort(key=lambda r: -r["hits"])

    # --- alerts: severity rows from detection families ---
    alerts: list[dict[str, Any]] = []
    alert_hits: list[dict[str, Any]] = []
    for h in hits:
        fam = str(h.get("family") or "").lower()
        if not any(k in fam for k in _ALERT_FAMILY_HINTS):
            continue
        fields = h.get("fields") or {}
        level = str(
            fields.get("Level") or fields.get("level") or fields.get("Severity") or ""
        ).lower()
        if level not in _ALERT_LEVELS:
            continue
        alerts.append(
            {
                "family": fam,
                "level": level,
                "title": str(
                    fields.get("RuleTitle")
                    or fields.get("Title")
                    or fields.get("RuleName")
                    or ""
                )[:160],
                "time": str(
                    fields.get("TimeCreated") or fields.get("Timestamp") or ""
                )[:40],
                "host": str(h.get("host") or fields.get("Computer") or "")[:60],
                "file": str(h.get("file") or ""),
                "line": str(h.get("line") or ""),
            }
        )
        alert_hits.append(h)
    pairs = sorted(
        zip(alerts, alert_hits, strict=False),
        key=lambda p: (0 if p[0]["level"] == "critical" else 1, p[0]["time"]),
    )
    alerts = [a for a, _h in pairs]
    alert_hits = [h for _a, h in pairs]

    # WP 4j.1: interpretation on every alert — what it means + what to check
    # next, from the matching skill + playbook caveats (no RAG here; the
    # on-demand /hit/interpret endpoint carries the methodology chunk).
    try:
        from nexus.langgraph.interpret import interpret_hits

        for alert, interp in zip(
            alerts, interpret_hits(case_dir, alert_hits), strict=False
        ):
            alert["interpret"] = interp
    except Exception as exc:  # noqa: BLE001
        log.debug("alert interpretation failed: %s", exc)

    # --- entity top-N ---
    raw_entities = extract_entities(hits)
    entities: dict[str, list[dict[str, Any]]] = {}
    for etype, elist in raw_entities.items():
        ranked = sorted(elist, key=lambda e: (-len(e.get("families") or []), -len(e.get("hits") or [])))
        entities[etype] = [
            {
                "value": e["value"],
                "hits": len(e.get("hits") or []),
                "families": e.get("families") or [],
            }
            for e in ranked[:_ENTITY_TOP_N]
        ]

    # --- hosts + time range ---
    hosts = sorted({str(h.get("host") or "") for h in hits if h.get("host")})
    times: list[str] = []
    for h in hits:
        f = h.get("fields") or {}
        ts = str(
            f.get("TimeCreated") or f.get("Timestamp") or f.get("LastRun")
            or f.get("LastVisitTime") or h.get("ts") or ""
        )
        if ts:
            times.append(ts)
    time_range = {"start": min(times) if times else "", "end": max(times) if times else ""}

    # --- intake echo ---
    intake: dict[str, str] = {}
    try:
        from nexus.langgraph.query_pack import load_case_intake

        raw = load_case_intake(case_dir) or {}
        intake = {
            k: str(raw.get(k) or "")
            for k in ("question", "subjects", "hypothesis", "mode", "window")
            if raw.get(k)
        }
    except Exception:  # noqa: BLE001
        pass

    # WP 4j.3: guided first pass — the order an examiner walks a fresh case.
    walkthrough = _guided_first_pass(
        alerts=alerts,
        entities=entities,
        needle_scan=needle_scan[:80],
        hosts=hosts,
        families=families,
    )

    out: dict[str, Any] = {
        "inventory": inventory,
        "families": families,
        "total_files": sum(v["files"] for v in inventory.values()),
        "total_rows": sum(v["rows"] for v in inventory.values()),
        "ledger": _parser_ledger(case_dir),
        "hosts": hosts,
        "time_range": time_range,
        "alerts": alerts[:60],
        "alert_count": len(alerts),
        "needle_scan": needle_scan[:80],
        "scanned_needles": len(terms),
        "entities": entities,
        "intake": intake,
        "walkthrough": walkthrough,
        "backend": backend,
        "hits_examined": len(hits),
        "scan_truncated": scan_truncated,
    }

    # WP 4j.5c: persist an offline copy — the briefing and signal map must be
    # reviewable without the UI (DFIR practice: every analysis leaves a file
    # artifact the examiner can open, diff, or attach to notes).
    out["artifacts"] = _write_briefing_artifacts(case_dir, out, counts, needle_map)
    return out


def _write_briefing_artifacts(
    case_dir: Path,
    brief: dict[str, Any],
    needle_counts: dict[str, int],
    needle_map: dict[str, str],
) -> dict[str, str]:
    """Write analysis/briefing.md + analysis/signal_map.csv; return paths.

    Best-effort — a read-only case dir or IO failure must never break the
    briefing itself. The CSV records EVERY scanned needle (0 hits included)
    because "checked, absent" is negative evidence, not noise.
    """
    import csv

    try:
        analysis_dir = case_dir / "analysis"
        analysis_dir.mkdir(parents=True, exist_ok=True)
        md_path = analysis_dir / "briefing.md"
        md_path.write_text(briefing_to_markdown(brief), encoding="utf-8")

        csv_path = analysis_dir / "signal_map.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["needle", "hits", "source"])
            for needle, count in sorted(needle_counts.items(), key=lambda kv: -kv[1]):
                w.writerow([needle, count, needle_map.get(needle, "")])
        return {"briefing_md": str(md_path), "signal_map_csv": str(csv_path)}
    except Exception:  # noqa: BLE001
        return {}


def briefing_to_markdown(brief: dict[str, Any]) -> str:
    """Render the briefing as markdown for the report/CLI surfaces."""
    lines: list[str] = ["# Case Briefing", ""]
    inv = brief.get("inventory") or {}
    lines.append(f"Evidence: {brief.get('total_files', 0)} files, "
                 f"{brief.get('total_rows', 0)} rows across {len(inv)} families")
    for fam, e in sorted(inv.items()):
        cap = "+" if e.get("capped") else ""
        lines.append(f"- `{fam}`: {e['files']} files, {e['rows']}{cap} rows")
    led = brief.get("ledger") or {}
    lines.append(f"\nParser lane: {led.get('ok', 0)} OK / {led.get('skip', 0)} SKIP / "
                 f"{led.get('fail', 0)} FAIL")
    if brief.get("hosts"):
        lines.append(f"Hosts: {', '.join(brief['hosts'][:10])}")
    tr = brief.get("time_range") or {}
    if tr.get("start"):
        lines.append(f"Time range: {tr['start']} → {tr['end']}")
    walk = brief.get("walkthrough") or []
    if walk:
        lines.append("\n## Guided first pass")
        for st in walk:
            lines.append(f"\n### {st.get('order')}. {st.get('title')} ({st.get('count', 0)})")
            if st.get("why"):
                lines.append(str(st["why"]))
            learn = st.get("learn") or {}
            if learn.get("headline"):
                lines.append(f"*Why this matters:* {learn['headline']}")
            for w in (learn.get("why_matters") or [])[:3]:
                lines.append(f"  - {w}")
            for a in (st.get("actions") or [])[:6]:
                lines.append(f"- `{a.get('needle')}` — {a.get('label')}")
    alerts = brief.get("alerts") or []
    if alerts:
        lines.append(f"\n## Alerts ({len(alerts)})")
        for a in alerts[:30]:
            lines.append(f"- [{a['level'].upper()}] {a['title']} — {a['host']} {a['time']}")
            learn = (a.get("interpret") or {}).get("learn") or {}
            if learn.get("headline"):
                lines.append(f"  - why: {learn['headline']}")
            for w in (learn.get("why_matters") or [])[:1]:
                lines.append(f"  - {w}")
    scan = brief.get("needle_scan") or []
    if scan:
        lines.append(f"\n## Signal map ({len(scan)} needles with hits)")
        for s in scan[:40]:
            lines.append(f"- `{s['needle']}` — {s['hits']} hits ({s['source']})")
    ent = brief.get("entities") or {}
    if ent:
        lines.append("\n## Top entities")
        for etype, elist in sorted(ent.items()):
            vals = ", ".join(e["value"] for e in elist[:_ENTITY_TOP_N])
            lines.append(f"- **{etype}**: {vals}")
    intake = brief.get("intake") or {}
    if intake:
        lines.append("\n## Intake")
        for k, v in intake.items():
            lines.append(f"- **{k}**: {v}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# WP 4i.5 — LLM briefing layer: directions grounded in deterministic numbers
# ---------------------------------------------------------------------------

_DIRECTIONS_SYSTEM = """\
You are a senior DFIR examiner writing an investigation briefing for a peer.

You receive a DETERMINISTIC case briefing: evidence inventory, parser ledger,
alert surface (Hayabusa/Sigma severity), a signal map (which playbook/ATT&CK/
Sigma needles already hit and how many times), top entities, hosts, the time
range, and the intake question.

Produce 3-6 investigation DIRECTIONS — concrete starting points an examiner
can run immediately. Rules:
- Ground every direction in the briefing's actual numbers — cite "47 lsass
  hits" or "critical: LSASS Memory Access on WS01", never invent evidence.
- Each direction = {title, why, needles, family}. needles are search terms
  the examiner can paste into the query box.
- Order by investigative value: confirmed alerts first, then high-count
  needle clusters, then negative-evidence checks (things that SHOULD be
  there if the suspicion is right but aren't).
- If the intake question names subjects/hosts/times, prioritise directions
  that address it directly.
- Return ONLY JSON: {"directions": [{title, why, needles, family}, ...]}
"""


def llm_directions(
    case_dir: Path,
    brief: dict[str, Any],
    model: Any = None,
) -> list[dict[str, Any]]:
    """Optional LLM layer over the deterministic briefing.

    Returns a list of investigation directions grounded in the briefing's
    real numbers. Empty list when no model is configured — the deterministic
    briefing stands alone.
    """
    if model is None:
        return []

    scan = brief.get("needle_scan") or []
    alerts = brief.get("alerts") or []
    ents = brief.get("entities") or {}
    intake = brief.get("intake") or {}

    user_parts = [
        f"Evidence: {brief.get('total_files', 0)} files, "
        f"{brief.get('total_rows', 0)} rows, families={', '.join(brief.get('families') or [])}",
        f"Hosts: {', '.join((brief.get('hosts') or [])[:10])}",
        f"Window: {(brief.get('time_range') or {}).get('start', '?')} → "
        f"{(brief.get('time_range') or {}).get('end', '?')}",
        "Parser lane: " + ", ".join(
            f"{led}={n}" for led, n in (
                ("OK", (brief.get('ledger') or {}).get('ok', 0)),
                ("SKIP", (brief.get('ledger') or {}).get('skip', 0)),
                ("FAIL", (brief.get('ledger') or {}).get('fail', 0)),
            )
        ),
        "Alerts: " + ("; ".join(
            f"[{a.get('level','')}] {a.get('title','')} @{a.get('host','')}"
            for a in alerts[:10]
        ) or "none"),
        "Signal map: " + (", ".join(
            f"{s['needle']}({s['hits']})" for s in scan[:25]
        ) or "none"),
        "Top entities: " + (" | ".join(
            f"{t}={', '.join(e['value'] for e in (ents.get(t) or [])[:5])}"
            for t in ("process_name", "ipv4", "domain", "domain_user")
            if ents.get(t)
        ) or "none"),
        f"Intake: question={intake.get('question', '(none)')} "
        f"subjects={intake.get('subjects', '(none)')} "
        f"hypothesis={intake.get('hypothesis', '(none)')}",
    ]

    try:
        resp = model.invoke([
            {"role": "system", "content": _DIRECTIONS_SYSTEM},
            {"role": "user", "content": "\n".join(user_parts)},
        ])
        text = getattr(resp, "content", str(resp))
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            return []
        parsed = json.loads(text[start:end + 1])
        out = []
        for d in (parsed.get("directions") or [])[:6]:
            if not isinstance(d, dict):
                continue
            out.append({
                "title": str(d.get("title") or "")[:160],
                "why": str(d.get("why") or "")[:400],
                "needles": [str(n)[:80] for n in (d.get("needles") or [])[:8]],
                "family": str(d.get("family") or "")[:40],
            })
        return out
    except Exception as exc:  # noqa: BLE001
        log.debug("LLM briefing directions failed: %s", exc)
        return []

