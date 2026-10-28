"""Case briefing — WP 4i.1/4i.2.

Auto-generated after N3 indexing (and on demand). The examiner's first view
of a processed case: what was collected, what the signatures already caught,
where the signal density is, and what they said they were looking for.

Deterministic by default — no LLM required. One exhaustive extraction scan
powers three surfaces: needle hit-counts (playbook auto-scan), alert rows
(Hayabusa/Zircolite severity), and the entity inventory. The optional LLM layer
(mode1 directions) consumes this structure, never replaces it.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

#: Alert levels that sort above `high`, in order. An alert is a crit/high lead (`alerts_from_leads`); the
#: leads spell Hayabusa's top level `crit` (rule_leads._LEVEL_SCORE).
_ALERT_LEVEL_RANK = {"critical": 0, "crit": 0, "high": 1}


# ---------------------------------------------------------------------------
# Inventory — what was actually processed
# ---------------------------------------------------------------------------

def _family_inventory(case_dir: Path) -> dict[str, dict[str, Any]]:
    """Per-family file/row counts + hosts seen, from the tools extractions.

    Streams complete line counts for every indexed extraction file.
    Imported non-host evidence (network/cloud/TI) is counted per source from
    the case artifact store so the briefing shows it as a family.
    """
    from nexus.langgraph.query_pack import iter_extraction_files, iter_ingest_rows

    out: dict[str, dict[str, Any]] = {}
    for path, _root, fam in iter_extraction_files(case_dir):
        entry = out.setdefault(fam, {"files": 0, "rows": 0})
        entry["files"] += 1
        try:
            n = 0
            with path.open("rb") as fh:
                for _ in fh:
                    n += 1
            # minus header line for CSV-ish outputs
            entry["rows"] += max(0, n - 1)
        except OSError:
            continue
    ingest_sources: dict[str, int] = {}
    for _n, fam, _text, _ts in iter_ingest_rows(case_dir):
        ingest_sources[fam] = ingest_sources.get(fam, 0) + 1
    for fam, rows in ingest_sources.items():
        entry = out.setdefault(fam, {"files": 0, "rows": 0})
        entry["files"] += 1
        entry["rows"] += rows
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

def _scan_needles(
    case_dir: Path,
    families: list[str],
    dropped: list[str] | None = None,
) -> dict[str, str]:
    """needle -> source label, for the families present in the case.

    The returned vocabulary contains every scannable term from each source.
    ``dropped`` is retained for call compatibility and remains empty because
    the scanner no longer discards terms by count.
    """
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
    for t in attack_needles_for(fams, limit=None, cap=None):
        needles.setdefault(t.lower(), "attack")
    for t in sigma_needles_for(fams, limit=None, cap=None):
        needles.setdefault(t.lower(), "sigma")

    # Insider Threat Matrix hard artifacts (section-grounded packs).
    try:
        from nexus.knowledge.itm_needles import itm_needles_for, itm_strong_for

        for t in itm_strong_for(fams, limit=None, cap=None):
            needles.setdefault(t.lower(), "itm-strong")
        for t in itm_needles_for(fams, limit=None, cap=None):
            needles.setdefault(t.lower(), "itm")
    except Exception:  # noqa: BLE001 — optional needles
        pass

    # External-threat hard artifacts (ATT&CK-grounded packs).
    try:
        from nexus.knowledge.external_needles import (
            external_needles_for,
            external_strong_for,
        )

        for t in external_strong_for(fams, limit=None, cap=None):
            needles.setdefault(t.lower(), "external-strong")
        for t in external_needles_for(fams, limit=None, cap=None):
            needles.setdefault(t.lower(), "external")
    except Exception:  # noqa: BLE001 — optional needles
        pass

    # Intake extras + question terms the examiner already named
    try:
        from nexus.langgraph.query_pack import collect_query_terms, load_case_intake

        for t in collect_query_terms(load_case_intake(case_dir)):
            needles.setdefault(t.lower(), "intake")
    except Exception:  # noqa: BLE001
        pass

    from nexus.knowledge.needle_terms import is_scannable_term
    from nexus.langgraph.query_pack import is_needle_like

    # Vocabulary hygiene, two gates by provenance:
    # - content gate (F6): bare numbers / container file names never become
    #   needles, whoever authored them;
    # - free-text tokens (intake/question/query_extra) additionally reject
    #   machine paths and schema labels - the live leak of 2026-09-23
    #   (STUDY\Github, domain_user).
    # Curated packs are hand-authored: their command fragments and registry
    # paths ARE evidence strings and stay scannable (cipher /w,
    # currentversion\run, auditpol /clear; ubiquity demotion handles the
    # generic ones). A blanket separator rule here silently ate 28 real
    # needles, contradicting the packs and their F6 export tests.
    clean: dict[str, str] = {}
    for k, v in needles.items():
        term = k.strip()
        if len(term) < 3 or not is_scannable_term(term):
            continue
        if v == "intake" and not is_needle_like(term):
            continue
        clean[k] = v
    return clean


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


def _exact_needle_counts(case_dir: Path, needles: list[str], scan_stats: dict[str, Any]) -> dict[str, int] | None:
    """Each needle's exact row count on the case index (IC-13), or None when the scan did not use the index.

    `count_hits` counts a term exactly as the scan matches it; four at a time, 295 needles take about a
    minute on 7 M documents. A needle whose count fails keeps no number at all rather than a sampled one.
    """
    if str((scan_stats or {}).get("backend") or "") != "elasticsearch" or not needles:
        return None
    from concurrent.futures import ThreadPoolExecutor

    from nexus.langgraph.query_pack import count_hits

    def one(term: str) -> tuple[str, int | None]:
        try:
            result = count_hits(case_dir, [term], (None, None), backend="elasticsearch")
            return term, int(result["count"]) if result.get("exact") else None
        except Exception:  # noqa: BLE001 - one needle's failure is recorded below
            return term, None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(pool.map(one, needles))
    failed = sorted(t for t, n in results.items() if n is None)
    if failed:
        scan_stats["count_failed"] = failed
    return {t: n for t, n in results.items() if n is not None}


def _walkthrough_learn(
    families: list[str],
    alerts: list[dict[str, Any]],
    case_dir: Path | None = None,
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
        for t in _playbook_triggers(fam, limit=2, case_dir=case_dir):
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
    case_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """The deterministic Mode 1 walkthrough.

    Four steps in examiner order: triage the alerts, map who/where, read the
    signal clusters, then the concrete starting points. Each step carries
    grounded actions (a needle + family) so the examiner can act without
    thinking about query syntax. Ranking is by real counts, never invented.
    """
    steps: list[dict[str, Any]] = []
    tech_notes, pb_triggers = _walkthrough_learn(families, alerts, case_dir)
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
        for s in [x for x in needle_scan if not x.get("ubiquitous")][:8]
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


def _index_census(case_dir: Path) -> dict[str, Any]:
    """Hosts/users/time range straight from the N3 index (ES aggregations).

    Fallback for when the threat-needle scan found no rows: the briefing must
    still show what the evidence contains. Never raises; returns {} when the
    index/aggregation path is unavailable (CSV-only cases keep prior behavior).
    """
    try:
        from nexus.langgraph.case_index import es_aggregate

        census: dict[str, Any] = {"hosts": [], "entities": {}, "time_range": {}}
        for field, etype in (("host", "hosts"), ("user", "users")):
            result = es_aggregate(
                case_dir, "", field=field, top=0, match_all=True, with_spans=True,
            )
            spans = (result or {}).get("top") or []
            if not spans:
                continue
            census["entities"][etype] = [
                {
                    "value": str(s.get("value")),
                    "hits": int(s.get("count") or 0),
                    "families": [],
                }
                for s in spans if s.get("value")
            ]
            if field == "host":
                census["hosts"] = [
                    str(s.get("value")) for s in spans if s.get("value")
                ]
                starts = [s.get("first_seen") for s in spans if s.get("first_seen")]
                ends = [s.get("last_seen") for s in spans if s.get("last_seen")]
                if starts and ends:
                    census["time_range"] = {"start": min(starts), "end": max(ends)}
        return census
    except Exception as exc:  # noqa: BLE001 — census is best-effort
        log.debug("index census unavailable: %s", exc)
        return {}


def _typed_entities(case_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """The case's typed entities and observables, in the briefing's shape (never raises)."""
    try:
        from nexus.langgraph.typed_entities import ENTITY_FIELDS, OBSERVABLE_KINDS, case_entities

        typed = case_entities(Path(case_dir).name)
    except Exception as exc:  # noqa: BLE001 - the briefing must render without the index
        log.debug("typed entities unavailable: %s", exc)
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for kind in [k for k, _ in ENTITY_FIELDS] + list(OBSERVABLE_KINDS):
        items = typed.get(kind) or []
        if items:
            out[kind] = [{"value": i["value"], "hits": i["count"], "families": i["families"],
                          "source_file": i["source_file"], "source_family": (i["families"] or [""])[0]}
                         for i in items]
    return out


def _lead_record(lead: dict[str, Any]) -> dict[str, Any]:
    """A lead as a row to interpret: its family, its own rule title and detail, and its stored rows' text."""
    rows = [r for r in lead.get("rows") or [] if isinstance(r, dict)]
    fields = next((r["fields"] for r in rows if isinstance(r.get("fields"), dict)), {})
    text = " ".join([str(lead.get("subject") or ""), str(lead.get("detail") or "")]
                    + [str(r.get(k) or "") for r in rows[:3] for k in ("rule_title", "details", "detail")])
    return {"family": str(lead.get("family") or ""), "text": text, "fields": fields}


def alerts_from_leads(case_dir: Path, leads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every crit/high lead as an alert, keyed by its audit id, crit before high, then by time.

    Each alert keeps the references of the rows it stands on (``doc_ids``, ``locs``, through
    ``leads.lead_row_refs``). The alert interpretation (what it means, what to check next) is read from
    the first of those rows, fetched from the index; when the index does not return it (a case with no
    index), from the lead's own record: its rule title, detail and stored rows.
    """
    from nexus.analysis.leads import lead_row_refs, lead_rows_query

    alerts: list[dict[str, Any]] = []
    records: dict[int, dict[str, Any]] = {}
    for lead in leads:
        extra = lead.get("extra") or {}
        if not extra.get("crit_high"):
            continue
        audit_ids = [str(a) for a in lead.get("audit_ids") or [] if a]
        doc_ids, locs = lead_row_refs(lead)
        alert = {
            "key": audit_ids[0] if audit_ids else str(lead.get("subject") or ""),
            "audit_ids": audit_ids,
            "family": str(lead.get("family") or ""),
            "kind": str(lead.get("kind") or ""),
            "engine": str(extra.get("engine") or ""),
            "level": str(extra.get("level") or "high").lower(),
            "title": str(lead.get("subject") or "")[:160],
            "detail": str(lead.get("detail") or "")[:300],
            "count": int(extra.get("count") or 0),
            "time": str(extra.get("first") or "")[:40],
            "host": str((extra.get("hosts") or [""])[0] or "")[:60],
            "doc_ids": doc_ids,
            "locs": [f"{f}:{n}" for f, n in locs],
        }
        records[id(alert)] = _lead_record(lead)
        alerts.append(alert)
    alerts.sort(key=lambda a: (_ALERT_LEVEL_RANK.get(a["level"], 2), a["time"]))
    if not alerts:
        return alerts
    rows: dict[int, dict[str, Any]] = {}
    first_ids = [a["doc_ids"][0] for a in alerts if a["doc_ids"]]
    first_locs = [tuple(a["locs"][0].rpartition(":")[::2]) for a in alerts if not a["doc_ids"] and a["locs"]]
    query = lead_rows_query(first_ids, first_locs)
    if query is not None:
        try:
            from nexus.langgraph.typed_entities import iter_sources

            docs = list(iter_sources(Path(case_dir).name, query,
                                     ["family", "file", "line", "text", "fields", "host", "ts"]))
            by_id = {d["_id"]: d for d in docs}
            by_loc = {(str(d.get("file") or ""), str(d.get("line") or "")): d for d in docs}
            for alert in alerts:
                row = (by_id.get(alert["doc_ids"][0]) if alert["doc_ids"] else
                       by_loc.get(tuple(alert["locs"][0].rpartition(":")[::2])) if alert["locs"] else None)
                if row:
                    alert["file"], alert["line"] = str(row.get("file") or ""), str(row.get("line") or "")
                    rows[id(alert)] = row
        except Exception as exc:  # noqa: BLE001 - the lead's own record still interprets it
            log.debug("alert rows unavailable from the index: %s", exc)
    try:
        from nexus.langgraph.interpret import interpret_hits

        inputs = [rows.get(id(a)) or records[id(a)] for a in alerts]
        for alert, interp in zip(alerts, interpret_hits(case_dir, inputs), strict=False):
            alert["interpret"] = interp
    except Exception as exc:  # noqa: BLE001 - the interpretation is a reading aid
        log.debug("alert interpretation failed: %s", exc)
    return alerts


def case_briefing(case_dir: Path) -> dict[str, Any]:
    """Deterministic case briefing.

    Returns:
        inventory   — per-family {files, rows}
        ledger      — parser run status (ok/skip/fail + per-tool entries)
        hosts       — hosts seen in hits
        time_range  — {start, end} best-effort from hit timestamps
        alerts      — high/critical severity rows (hayabusa/zircolite/…)
        needle_scan — [{needle, hits, source}] sorted by hit count desc
        entities    — every extracted entity per type with family coverage
        intake      — question / subjects / hypothesis / suspicion echo
    """
    from nexus.langgraph.query_pack import attach_hit_fields, n4_hits

    case_dir = Path(case_dir)
    inventory = _family_inventory(case_dir)
    families = sorted(inventory)

    needle_map = _scan_needles(case_dir, families)
    terms = list(needle_map)
    hits: list[dict[str, Any]] = []
    backend = ""
    scan_stats: dict[str, Any] = {}
    if terms and families:
        try:
            hits, backend = n4_hits(case_dir, terms, (None, None), stats=scan_stats)
        except Exception as exc:  # noqa: BLE001
            log.debug("briefing scan failed: %s", exc)
            hits, backend = [], ""
    # Detection/event-ID probe: playbook event ids are TYPED facts (the
    # vocabulary gate keeps bare numbers out of the keyword scan). This probe
    # keeps the alert surface and EventId field-facts independent of the
    # keyword vocabulary - a row is found by its event id, and match-site
    # classification records it as a fact, never as signal.
    if families:
        try:
            from nexus.knowledge.attack_needles import attack_packs_for
            from nexus.knowledge.needle_terms import split_terms
            from nexus.knowledge.sigma_needles import sigma_packs_for
            from nexus.langgraph.query_pack import playbook_event_ids_for_families

            fact_terms: list[str] = []
            with contextlib.suppress(Exception):
                fact_terms.extend(playbook_event_ids_for_families(families))
            for packs in (
                attack_packs_for(families, set(), limit=None),
                sigma_packs_for(families, limit=None),
            ):
                for pack in packs:
                    _, context = split_terms(pack.get("needles") or [])
                    fact_terms.extend(context["event_ids"])
            fact_terms = list(dict.fromkeys(t for t in fact_terms if t))
        except Exception:  # noqa: BLE001
            fact_terms = []
        if fact_terms:
            try:
                probe_hits, _probe = n4_hits(
                    case_dir, fact_terms, (None, None), priority_terms=fact_terms
                )
                seen_hits = {
                    (str(h.get("family")), str(h.get("file")), str(h.get("line")))
                    for h in hits
                }
                for hit in probe_hits:
                    key = (
                        str(hit.get("family")),
                        str(hit.get("file")),
                        str(hit.get("line")),
                    )
                    if key not in seen_hits:
                        seen_hits.add(key)
                        hits.append(hit)
            except Exception as exc:  # noqa: BLE001
                log.debug("event-id probe failed: %s", exc)
                scan_stats["event_id_probe_failed"] = True
    # Per-needle counts below cover the full scan window. If files cannot be
    # read, CSV recovery is needed, or an ES clause fails, counts are lower
    # bounds and the UI marks those chips honestly.
    from nexus.langgraph.query_pack import _incomplete_reasons

    incomplete_reasons = _incomplete_reasons(scan_stats)
    if scan_stats.get("event_id_probe_failed"):
        incomplete_reasons.append("event-ID fact probe failed")
    scan_stats["incomplete_reasons"] = incomplete_reasons
    scan_stats["truncated"] = bool(incomplete_reasons)
    scan_stats["truncated_reasons"] = incomplete_reasons
    scan_truncated = bool(incomplete_reasons)
    hits = attach_hit_fields(case_dir, hits)

    # --- needle -> hit count (from matched terms recorded per hit) ---
    counts: dict[str, int] = {t: 0 for t in needle_map}
    for h in hits:
        # terms_list is the structured copy; the comma string is display-only
        # (a needle containing a comma must not split into phantom terms).
        matched_terms = h.get("terms_list")
        if not isinstance(matched_terms, list):
            matched_terms = str(h.get("terms") or "").split(",")
        for t in matched_terms:
            t = str(t).strip().lower()
            if t in counts:
                counts[t] += 1
    # The scan retains every matching row. Where Elasticsearch is available,
    # exact per-term counts are independently verified against the index.
    index_counts = _exact_needle_counts(case_dir, list(counts), scan_stats)
    if index_counts is not None:
        counts = index_counts
    counts_exact = index_counts is not None or not incomplete_reasons
    scan_stats["counts_exact"] = counts_exact
    needle_scan = [
        {"needle": n, "hits": c, "source": needle_map[n], "exact": counts_exact}
        for n, c in counts.items()
        if c > 0
    ]
    needle_scan.sort(key=lambda r: -r["hits"])

    # --- F1: ubiquity demotion - a term matching a large share of the case is
    # background noise, not a signal cluster. Env-tunable share, minimum floor.
    total_rows = sum(int(v.get("rows") or 0) for v in inventory.values())
    try:
        ubiquity_pct = float(os.environ.get("NEXUS_NEEDLE_UBIQUITY_PCT", "20"))
    except ValueError:
        ubiquity_pct = 20.0
    ubiquity_floor = (
        max(25, int(total_rows * ubiquity_pct / 100.0)) if total_rows else 0
    )
    for entry in needle_scan:
        entry["ubiquitous"] = bool(
            ubiquity_floor and int(entry.get("hits") or 0) >= ubiquity_floor
        )
    # Signal terms first (by hits), background terms last.
    needle_scan.sort(
        key=lambda r: (bool(r.get("ubiquitous")), -int(r.get("hits") or 0))
    )

    # --- Insider Threat Matrix coverage (pack hits; absence = negative evidence)
    itm_coverage: list[dict[str, Any]] = []
    try:
        from nexus.knowledge.itm_needles import itm_packs_for

        for pack in itm_packs_for(set(families), limit=None):
            pack_terms = [
                str(t).strip().lower() for t in (pack.get("needles") or [])
            ]
            pack_strong = [
                str(t).strip().lower() for t in (pack.get("strong") or [])
            ]
            itm_coverage.append({
                "itm": str(pack.get("itm") or ""),
                "name": str(pack.get("name") or ""),
                "hits": int(sum(counts.get(t, 0) for t in pack_terms)),
                "strong_hits": int(sum(counts.get(t, 0) for t in pack_strong)),
                "caveat": str(pack.get("caveat") or "")[:200],
            })
        itm_coverage.sort(key=lambda r: -r["hits"])
    except Exception:  # noqa: BLE001 — coverage panel is best-effort
        itm_coverage = []

    # --- field facts (id/label columns) — pivots, never signal ---
    # Match-site awareness: a keyword that lands in an EventId/RecordNumber/
    # Provider/Level cell says the evidence contains the value, not that
    # behaviour is suspicious. Counted during the exhaustive scan so a
    # downstream page cannot crowd fact-only rows out; fall back to the hit
    # list for backends that do not populate the counters.
    stat_fact_counts = dict((scan_stats or {}).get("fact_counts") or {})
    stat_fact_fields = (scan_stats or {}).get("fact_fields") or {}
    fact_counts: dict[str, int] = {}
    fact_fields: dict[str, dict[str, int]] = {}
    fact_classes: dict[str, str] = {}
    if stat_fact_counts:
        fact_counts = stat_fact_counts
        fact_fields = {
            str(t): {str(f): int(n) for f, n in (fields or {}).items()}
            for t, fields in stat_fact_fields.items()
        }
    else:
        for h in hits:
            for s in (h.get("fact_sites") or []):
                term = str(s.get("term") or "").strip().lower()
                if not term:
                    continue
                fact_counts[term] = fact_counts.get(term, 0) + 1
                field = str(s.get("field") or "")
                fact_fields.setdefault(term, {})
                fact_fields[term][field] = fact_fields[term].get(field, 0) + 1
                fact_classes.setdefault(term, str(s.get("class") or ""))
    needle_facts = [
        {
            "needle": term,
            "hits": n,
            "field": max(fact_fields.get(term, {}), key=fact_fields[term].get)
            if fact_fields.get(term) else "",
            "class": fact_classes.get(term, ""),
        }
        for term, n in sorted(fact_counts.items(), key=lambda kv: -kv[1])
    ]

    # --- alerts: every crit/high lead, the one set every mode answers (Part 12 FM-3) ---
    # They were the severity rows among the rows a keyword happened to match, so a critical detection whose
    # text named no needle never reached the alert surface; the leads read every detection.
    from nexus.langgraph.evidence_rows import row_time

    try:
        from nexus.analysis.leads import build_leads

        built_leads = build_leads(case_dir)
        leads_error = ""
    except Exception as exc:  # noqa: BLE001 - the briefing must render regardless
        built_leads, leads_error = [], str(exc)[:200]
    alerts = alerts_from_leads(case_dir, [lead.to_dict() for lead in built_leads])

    # --- typed entities, hosts and time range: the whole index by field meaning (Part 12 FM-7) ---
    # They came from the rows a keyword happened to match, typed by pattern: hosts, accounts and the
    # time range followed the needle list, not the evidence.
    entities = _typed_entities(case_dir) if families else {}
    paths_summary: dict[str, Any] = {"distinct": 0, "families": [], "examples": []}
    census = _index_census(case_dir) if families else {}
    hosts = list(census.get("hosts") or [])
    time_range = dict(census.get("time_range") or {"start": "", "end": ""})
    census_source = "index"
    if not hosts and not time_range.get("start") and hits:
        # A case with no Elasticsearch index: the scanned rows' own host and time fields (typed at index
        # time, never read from their text), labelled as the rows they come from.
        hosts = sorted({str(h.get("host") or "") for h in hits if h.get("host")})
        times = [t for t in (row_time(h) for h in hits) if t]
        time_range = {"start": min(times) if times else "", "end": max(times) if times else ""}
        census_source = "needle_hits"

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
        needle_scan=needle_scan,
        hosts=hosts,
        families=families,
        case_dir=case_dir,
    )

    # Mode 2 verdict surface: the LLM interpretation, TI context, and staged
    # DRAFT findings land in the briefing when they exist (Mode 1 cases simply
    # skip these — no fake "not run" noise).
    mode_interpretation = ""
    ti_context = ""
    findings_summary: dict[str, Any] = {"count": 0, "drafts": 0, "top": []}
    analysis_dir = case_dir / "analysis"
    interp_path = analysis_dir / "interpretation.md"
    if interp_path.is_file():
        try:
            mode_interpretation = interp_path.read_text(encoding="utf-8", errors="replace")[:8000]
        except OSError:
            mode_interpretation = ""
    ti_path = analysis_dir / "ti_context.md"
    if ti_path.is_file():
        try:
            ti_context = ti_path.read_text(encoding="utf-8", errors="replace")[:4000]
        except OSError:
            ti_context = ""
    try:
        findings_path = case_dir / "findings.json"
        if findings_path.is_file():
            loaded = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                rows = [f for f in loaded if isinstance(f, dict)]
                findings_summary = {
                    "count": len(rows),
                    "drafts": sum(
                        1 for f in rows if str(f.get("status") or "").upper() == "DRAFT"
                    ),
                    "top": [
                        {
                            "id": str(f.get("id") or ""),
                            "title": str(f.get("title") or "")[:200],
                            "severity": str(f.get("severity") or ""),
                            "confidence": str(f.get("confidence") or ""),
                        }
                        for f in rows[:12]
                    ],
                }
    except (OSError, ValueError):
        pass

    out: dict[str, Any] = {
        "inventory": inventory,
        "families": families,
        "total_files": sum(v["files"] for v in inventory.values()),
        "total_rows": sum(v["rows"] for v in inventory.values()),
        "ledger": _parser_ledger(case_dir),
        "coverage": _coverage(case_dir),
        "hosts": hosts,
        "time_range": time_range,
        "alerts": alerts,
        "alert_count": len(alerts),
        "needle_scan": needle_scan,
        "needle_facts": needle_facts,
        "itm_coverage": itm_coverage,
        "ubiquity_floor": ubiquity_floor,
        "ubiquity_pct": ubiquity_pct,
        "scanned_needles": len(terms),
        "entities": entities,
        "paths_summary": paths_summary,
        "intake": intake,
        "walkthrough": walkthrough,
        "backend": backend,
        "hits_examined": len(hits),
        "scan_truncated": scan_truncated,
        "scan_stats": scan_stats,
        "census_source": census_source,
        "mode_interpretation": mode_interpretation,
        "ti_context": ti_context,
        "findings_summary": findings_summary,
    }

    # WO-3 (report-only): the row-reconciliation line rides the briefing so a
    # source-vs-index mismatch is visible without opening the report.
    try:
        from nexus.analysis.reconciliation import load_or_reconcile, summary_line

        out["reconciliation"] = {
            "summary": summary_line(load_or_reconcile(case_dir)),
            "report_only": True,
        }
    except Exception:  # noqa: BLE001 - the briefing must render with or without it
        out["reconciliation"] = {}

    # WO-K3: anomaly leads. Deterministic, written to analysis/leads.jsonl, and
    # surfaced here next to the needles so a briefing carries the questions worth
    # asking - rarity, an unexpected parent, a first sighting, a volume burst -
    # not only the rows a keyword happened to match. A lead is not a finding and
    # stages nothing.
    out["leads"] = [lead.to_dict() for lead in built_leads[:60]]
    by_kind: dict[str, int] = {}
    for lead in built_leads:
        by_kind[lead.kind] = by_kind.get(lead.kind, 0) + 1
    out["lead_counts"] = {"total": len(built_leads), "by_kind": by_kind}
    if leads_error:
        out["lead_counts"]["error"] = leads_error

    # WO-K7: absence honesty. "No findings" collapses three different situations
    # into one sentence; the briefing carries the honest form instead - which
    # sources ran with counts, which are disabled for this ablation, and which
    # families were not examined.
    try:
        from nexus.analysis.absence import absence_statement

        families = sorted(out.get("families") or sorted((out.get("inventory") or {}).keys()))
        out["absence"] = absence_statement(case_dir, families=families)
    except Exception as exc:  # noqa: BLE001 - the briefing must render regardless
        out["absence"] = {"statement": "", "error": str(exc)[:200]}

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
    because "checked, absent" is negative evidence, not noise — and a needle
    that could not actually be queried is marked ``scanned=no`` so it can
    never masquerade as "checked, absent".
    """
    import csv

    try:
        analysis_dir = case_dir / "analysis"
        analysis_dir.mkdir(parents=True, exist_ok=True)
        md_path = analysis_dir / "briefing.md"
        md_path.write_text(briefing_to_markdown(brief), encoding="utf-8")

        failed_terms = {
            str(t).lower() for t in (brief.get("scan_stats") or {}).get("terms_failed") or []
        }
        # The full scan retains every matching row. A term whose query failed
        # is written as not scanned rather than as a zero-hit absence.
        stats = brief.get("scan_stats") or {}
        exact = "yes" if stats.get("counts_exact") else "no"
        count_failed = [str(t) for t in stats.get("count_failed") or []]
        csv_path = analysis_dir / "signal_map.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["needle", "hits", "source", "scanned", "exact"])
            for needle, count in sorted(needle_counts.items(), key=lambda kv: -kv[1]):
                low = str(needle).lower()
                scanned = "no" if low in failed_terms else "yes"
                w.writerow([needle, count, needle_map.get(needle, ""), scanned, exact])
            for needle in count_failed:
                w.writerow([needle, 0, needle_map.get(needle, "playbook"), "no", exact])

        # Match-site facts (EventId/RecordNumber/label cells): recorded apart
        # from the signal map so a bare value is never read as behaviour.
        facts_path = analysis_dir / "field_facts.csv"
        with facts_path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["needle", "rows", "field", "class"])
            for fact in brief.get("needle_facts") or []:
                w.writerow([
                    fact.get("needle"), fact.get("hits"),
                    fact.get("field"), fact.get("class"),
                ])
        return {
            "briefing_md": str(md_path),
            "signal_map_csv": str(csv_path),
            "field_facts_csv": str(facts_path),
        }
    except Exception:  # noqa: BLE001
        return {}


def _coverage(case_dir: Path) -> dict[str, Any]:
    """WO-B4: what the lane has not processed, so the briefing can say so."""
    try:
        from nexus.langgraph.lane_gate import coverage_snapshot

        return coverage_snapshot(case_dir)
    except Exception:  # noqa: BLE001 - the briefing must render without a gate
        return {}


def briefing_to_markdown(brief: dict[str, Any]) -> str:
    """Render the briefing as markdown for the report/CLI surfaces."""
    lines: list[str] = ["# Case Briefing", ""]
    inv = brief.get("inventory") or {}
    lines.append(f"Evidence: {brief.get('total_files', 0)} files, "
                 f"{brief.get('total_rows', 0)} rows across {len(inv)} families")
    for fam, e in sorted(inv.items()):
        lines.append(f"- `{fam}`: {e['files']} files, {e['rows']} rows")
    led = brief.get("ledger") or {}
    lines.append(f"\nParser lane: {led.get('ok', 0)} OK / {led.get('skip', 0)} SKIP / "
                 f"{led.get('fail', 0)} FAIL")
    rec_line = (brief.get("reconciliation") or {}).get("summary")
    if rec_line:
        lines.append(f"- {rec_line}")
    if brief.get("hosts"):
        lines.append(f"Hosts: {', '.join(brief['hosts'][:10])}")
    tr = brief.get("time_range") or {}
    if tr.get("start"):
        lines.append(f"Time range: {tr['start']} → {tr['end']}")
    # Mode 2: the LLM interpretation (verdict + findings + gaps + TI) leads the
    # briefing when present; otherwise show findings/TI sections directly.
    interp = (brief.get("mode_interpretation") or "").strip()
    if interp:
        lines.append("")
        lines.append(interp)
    else:
        fs = brief.get("findings_summary") or {}
        if fs.get("count"):
            lines.append(f"\n## Findings ({fs.get('count')} staged, {fs.get('drafts')} DRAFT)")
            for f in fs.get("top") or []:
                lines.append(
                    f"- `{f.get('id')}` [{f.get('severity')}/{f.get('confidence')}] "
                    f"{f.get('title')}"
                )
        ti = (brief.get("ti_context") or "").strip()
        if ti:
            lines.append("")
            lines.append(ti)
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
        for a in alerts:
            lines.append(f"- [{a['level'].upper()}] {a['title']} — {a['host']} {a['time']}")
            learn = (a.get("interpret") or {}).get("learn") or {}
            if learn.get("headline"):
                lines.append(f"  - why: {learn['headline']}")
            for w in (learn.get("why_matters") or [])[:1]:
                lines.append(f"  - {w}")
    scan = brief.get("needle_scan") or []
    if scan:
        signal_rows = [s for s in scan if not s.get("ubiquitous")]
        lines.append(f"\n## Signal map ({len(signal_rows)} needles with signal hits)")
        for s in signal_rows:
            lines.append(f"- `{s['needle']}` — {s['hits']} hits ({s['source']})")
    facts = brief.get("needle_facts") or []
    if facts:
        lines.append(f"\n## Field facts (not signal) — {len(facts)} term(s)")
        lines.append(
            "Keyword matches on id/label columns (EventId, RecordNumber, "
            "Provider, Level, ...). They show the value exists in the evidence "
            "- useful as pivots, never as suspicious signal or findings."
        )
        for f in facts:
            field = f" in `{f['field']}`" if f.get("field") else ""
            lines.append(
                f"- `{f['needle']}` - {f['hits']} row(s){field} "
                f"({f.get('class') or 'fact'})"
            )
    floor = int(brief.get("ubiquity_floor") or 0)
    background = [s for s in scan if s.get("ubiquitous")]
    if background:
        lines.append(
            f"\n## Background terms (ubiquitous, >={floor} hits) - not signal"
        )
        lines.append(
            "These match a large share of the case; they are ranked last and "
            "never staged as findings."
        )
        for s in background:
            lines.append(f"- `{s['needle']}` - {s['hits']} hits ({s['source']})")
    itm_cov = brief.get("itm_coverage") or []
    if itm_cov:
        lines.append(
            f"\n## Insider Threat Matrix coverage ({len(itm_cov)} relevant pack(s))"
        )
        for row in itm_cov:
            strong = (
                f", {row['strong_hits']} strong" if row.get("strong_hits") else ""
            )
            lines.append(
                f"- `{row.get('itm')}` {row.get('name')} - {row.get('hits')} hit(s){strong}"
            )
    scan_stats = brief.get("scan_stats") or {}
    if str(brief.get("backend") or "").startswith("csv"):
        reason = str(scan_stats.get("fallback_reason") or "NEXUS_ES_URL unset")
        lines.append(
            f"\n> Backend: **CSV pack** (Elasticsearch not used — {reason}). "
            "Mode 2/3 analysis requires ES; restart ES and rebuild the index."
        )
    failed_terms = scan_stats.get("terms_failed") or []
    pending_families = (brief.get("coverage") or {}).get("pending") or []
    if pending_families:
        lines.append(
            f"\n> PENDING EVIDENCE: {len(pending_families)} item(s) the lane has "
            f"not processed ({', '.join(str(p) for p in pending_families[:10])}). "
            "No absence claim may be made about these."
        )
    if failed_terms:
        lines.append(
            f"\n> WARNING: {len(failed_terms)} needle(s) could NOT be queried "
            f"({', '.join(failed_terms[:10])}) — their 0-hit rows in "
            "`signal_map.csv` are marked `scanned=no` and are NOT evidence of absence."
        )
    elif scan_stats and scan_stats.get("terms_requested"):
        files_line = ""
        if scan_stats.get("files_total"):
            files_line = (
                f" · files {scan_stats.get('files_scanned', 0)}/"
                f"{scan_stats.get('files_total', 0)}"
            )
        lines.append(
            f"\nScan coverage: {scan_stats.get('terms_queried', 0)}/"
            f"{scan_stats.get('terms_requested', 0)} needles queried"
            f"{files_line}"
            f" ({scan_stats.get('chunk_queries', 0)} ES chunk queries)."
        )
    trunc_reasons = scan_stats.get("truncated_reasons") or []
    if trunc_reasons:
        lines.append(
            f"\n> WARNING: hit counts are LOWER BOUNDS — scan truncated by: "
            f"{'; '.join(trunc_reasons)}. Explore may find more rows."
        )
    if brief.get("census_source") == "index" and not scan:
        lines.append(
            "\n> No playbook needle hits in this evidence. The host/user/time "
            "map below comes from the index census (deterministic), not from "
            "the needle scan — the evidence is present even when no threat "
            "needle matched."
        )
    ent = brief.get("entities") or {}
    if ent:
        lines.append("\n## Top entities")
        for etype, elist in sorted(ent.items()):
            vals = ", ".join(
                e["value"]
                + (f" ({e['source_file']})" if e.get("source_file") else "")
                for e in elist
            )
            lines.append(f"- **{etype}**: {vals}")
    paths = brief.get("paths_summary") or {}
    if paths.get("distinct"):
        fams = ", ".join(paths.get("families") or []) or "the case"
        examples = ", ".join(paths.get("examples") or [])
        lines.append(
            f"- **host filesystem paths** (content, NOT evidence files): "
            f"{paths['distinct']} distinct across {fams}"
            + (f" — e.g. {examples}" if examples else "")
        )
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


def _directions_json(text: str) -> dict[str, Any] | None:
    """Extract the directions JSON object from a model reply."""
    import json

    raw = (text or "").strip()
    if not raw:
        return None
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(raw[start:end + 1])
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _normalize_directions(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate + vocabulary-gate the model's direction rows."""
    from nexus.knowledge.needle_terms import filter_scannable

    out = []
    for d in (parsed.get("directions") or [])[:6]:
        if not isinstance(d, dict):
            continue
        # F6: LLM directions are auto-generated vocabulary - keep event IDs /
        # container names out of the proposed needles.
        kept_needles = filter_scannable(
            [str(n) for n in (d.get("needles") or [])[:8]]
        )
        title = str(d.get("title") or "")[:160]
        why = str(d.get("why") or "")[:400]
        family = str(d.get("family") or "")[:40]
        if not any((title.strip(), why.strip(), kept_needles, family.strip())):
            continue
        out.append({
            "title": title,
            "why": why,
            "needles": [n[:80] for n in kept_needles],
            "family": family,
        })
    return out


def llm_directions(
    case_dir: Path,
    brief: dict[str, Any],
    model: Any = None,
) -> list[dict[str, Any]]:
    """Optional LLM layer over the deterministic briefing.

    WP 10.53: directions get the read-only tool loop (schema discovery, run
    record, sample rows, RAG on demand) before falling back to the original
    one-shot directions prompt. Returns a list grounded in the briefing's real
    numbers. Empty list when no model is configured.
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
            for t in ("process", "executable", "user", "ipv4", "domain")
            if ents.get(t)
        ) or "none"),
        f"Intake: question={intake.get('question', '(none)')} "
        f"subjects={intake.get('subjects', '(none)')} "
        f"hypothesis={intake.get('hypothesis', '(none)')}",
    ]

    # WP 10.53: prefer the bounded tool loop; fall back to the original
    # one-shot directions prompt if the loop produces nothing parseable.
    # Only a real case directory has schema/ledger tools worth binding; tests
    # and bare temp dirs use the original deterministic/one-shot path.
    _case_path = Path(case_dir) if case_dir is not None else None
    _real_case = bool(
        _case_path is not None
        and ((_case_path / "CASE.yaml").is_file() or (_case_path / "analysis").is_dir())
    )
    if _real_case:
        try:
            from nexus.audit import AuditWriter
            from nexus.langgraph.context_loop import load_loop_budget, run_context_loop

            case_path = Path(case_dir)
            audit = AuditWriter("nexus", audit_dir=case_path / "audit")
            loop_system = (
                "You are a senior DFIR examiner writing investigation directions "
                "for a peer. You may call the read-only tools to inspect the real "
                "schema (es_mappings), what actually ran (run_record), sample rows "
                "(sample_rows) and methodology (rag_search). Ground every "
                "direction in real case data. Return your FINAL answer through "
                'the tool protocol answer envelope: {"answer":"<a JSON string '
                'containing {\\"directions\\":[{\\"title\\":\\"...\\",'
                '\\"why\\":\\"...\\",\\"needles\\":[\\"...\\"],'
                '\\"family\\":\\"...\\"}]}>"}. Max 6 directions.'
            )
            loop_result = run_context_loop(
                case_dir=case_path,
                case_id=case_path.name,
                question="\n".join(user_parts),
                model=model,
                system_prompt=loop_system,
                task="mode1-directions",
                budget=load_loop_budget(),
                audit=audit,
            )
            parsed_loop = _directions_json(str(loop_result.get("reply") or ""))
            loop_directions = _normalize_directions(parsed_loop or {})
            if loop_directions:
                return loop_directions
        except Exception as exc:  # noqa: BLE001
            log.debug("tool-loop briefing directions failed: %s", exc)

    try:
        resp = model.invoke([
            {"role": "system", "content": _DIRECTIONS_SYSTEM},
            {"role": "user", "content": "\n".join(user_parts)},
        ])
        text = getattr(resp, "content", str(resp))
        parsed = _directions_json(text)
        if not parsed:
            return []
        return _normalize_directions(parsed)
    except Exception as exc:  # noqa: BLE001
        log.debug("LLM briefing directions failed: %s", exc)
        return []

