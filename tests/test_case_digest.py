"""GATE-A regression tests — context budget, Case Digest, reconciliation,
n4_sample, and the run-options plumbing."""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph import prompt_budget
from nexus.langgraph.case_digest import (
    _classify,
    build_case_digest,
    reconciliation_checklist,
    render_digest_markdown,
    write_case_digest,
)


def test_the_ledger_shows_every_job():
    """D216: the first 20 of 92 rows were listed; the memory jobs came last and Mode 1 recorded the
    memory image as unprocessed from the triage discovery's SKIP, the first row shown."""
    entries = [{"tool": "(discovery)", "status": "SKIP",
                "reason": "No recognized evidence shape under ...\\rd01-memory.img"}]
    entries += [{"tool": "recmd", "status": "OK"} for _ in range(30)]
    entries += [{"tool": "memprocfs", "status": "OK"}] + [{"tool": "vol", "status": "OK"} for _ in range(30)]
    md = render_digest_markdown({"case_id": "CASE-X", "ledger": {"ok": 61, "skip": 1, "fail": 0,
                                                                  "entries": entries}})
    assert "- OK: memprocfs, recmd x30, vol x30" in md
    assert "- SKIP: (discovery) — No recognized evidence shape" in md


# ── prompt_budget ────────────────────────────────────────────────────────

def test_budget_from_window_and_ratio(monkeypatch):
    monkeypatch.setenv("NEXUS_LLM_CONTEXT_WINDOW", "1000000")
    monkeypatch.setenv("NEXUS_CONTEXT_FILL_RATIO", "0.7")
    assert prompt_budget.context_window() == 1_000_000
    assert prompt_budget.budget_chars() == int(1_000_000 * 0.7 * 4)


def test_budget_defaults_without_env(monkeypatch):
    monkeypatch.delenv("NEXUS_LLM_CONTEXT_WINDOW", raising=False)
    monkeypatch.delenv("NEXUS_CONTEXT_FILL_RATIO", raising=False)
    assert prompt_budget.context_window() == 1_000_000
    assert prompt_budget.fill_ratio() == 0.7


def test_budget_bad_env_falls_back(monkeypatch):
    monkeypatch.setenv("NEXUS_LLM_CONTEXT_WINDOW", "not-a-number")
    monkeypatch.setenv("NEXUS_CONTEXT_FILL_RATIO", "nope")
    assert prompt_budget.context_window() == 1_000_000
    assert prompt_budget.fill_ratio() == 0.7


def test_pack_sections_priority_and_report():
    sections = [
        (1, "second", "B" * 500),
        (0, "first", "A" * 500),
    ]
    packed, report = prompt_budget.pack_sections(sections, chars=1000)
    assert packed.startswith("A")  # priority 0 first regardless of list order
    assert len(packed) <= 1000 + 2  # join separators
    assert report["sections"]["first"]["chars"] > 0
    assert report["used_chars"] <= 1000


def test_pack_sections_giant_first_section_does_not_starve_second():
    # A huge priority-0 section must not eat the whole budget in pass 1.
    sections = [
        (0, "digest", "D" * 100_000),
        (1, "pack", "P" * 100_000),
    ]
    packed, report = prompt_budget.pack_sections(sections, chars=10_000)
    assert report["sections"]["pack"]["chars"] > 0
    assert "P" in packed
    assert report["used_chars"] <= 10_000


def test_pack_sections_truncation_flag():
    packed, report = prompt_budget.pack_sections(
        [(0, "only", "x" * 5000)], chars=1000
    )
    assert report["sections"]["only"]["truncated"] is True
    assert len(packed) == 1000


def test_retry_budget_halves(monkeypatch):
    monkeypatch.setenv("NEXUS_CONTEXT_RETRY_RATIO", "0.5")
    assert prompt_budget.retry_budget_chars(10_000) == 5_000


def test_persist_context_writes_file(tmp_path):
    packed, report = prompt_budget.pack_sections([(0, "digest", "facts")], chars=1000)
    path = prompt_budget.persist_context(
        tmp_path, "mode2-interpret", packed, report, meta={"case_id": "CASE-1"}
    )
    assert path is not None and path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "LLM context" in text
    assert "facts" in text
    assert "CASE-1" in text


def test_estimate_tokens_nonzero():
    assert prompt_budget.estimate_tokens("") == 0
    assert prompt_budget.estimate_tokens("abcd") >= 1


# ── case_digest ──────────────────────────────────────────────────────────

def _fake_brief() -> dict:
    return {
        "inventory": {"hayabusa": {"files": 1, "rows": 120}, "zeek": {"files": 1, "rows": 40}},
        "families": ["hayabusa", "zeek"],
        "ledger": {"ok": 2, "skip": 0, "fail": 0, "entries": [
            {"tool": "EvtxECmd", "status": "OK", "family": "hayabusa", "reason": ""},
        ]},
        "hosts": ["ws01"],
        "time_range": {"start": "2024-01-01T00:00:00", "end": "2024-01-02T00:00:00"},
        "alerts": [
            {"key": "nexus-a-20260101-001", "audit_ids": ["nexus-a-20260101-001"], "level": "high",
             "family": "hayabusa", "title": "Mimikatz detected", "host": "ws01", "time": "2024-01-01T10:00:00"},
        ],
        "entities": {"processes": [{"value": "m.exe", "hits": 5}]},
        "intake": {"question": "What did m.exe do?"},
        "hits_examined": 160,
        "backend": "elasticsearch",
    }


def test_classify_scope(tmp_path):
    classes = _classify(["hayabusa", "zeek", "splunk", "memory_dump"])
    assert "hayabusa" in classes["host"]
    assert "zeek" in classes["network"]
    assert "splunk" in classes["siem"]
    assert "memory_dump" in classes["memory"]


def test_the_digest_carries_no_keyword_needle_counts_or_negative_evidence(tmp_path, monkeypatch):
    """Part 12 FM-3: substring counts of keywords (T22: `ual` 11,020 hits from "virtual") are not facts
    about the case, and a word with no hits is not negative evidence. The examiner's signal_map.csv stays
    on disk; the digest no longer reads it."""
    monkeypatch.setattr("nexus.langgraph.briefing.case_briefing", lambda case_dir: _fake_brief())
    monkeypatch.setattr("nexus.langgraph.case_index.es_aggregate", lambda *a, **k: None)
    analysis = tmp_path / "analysis"
    analysis.mkdir(parents=True)
    (analysis / "signal_map.csv").write_text(
        "needle,hits,source,scanned,exact\nual,11020,intake,yes,yes\nhashdump,0,playbook,yes,yes\n",
        encoding="utf-8",
    )
    digest = build_case_digest(tmp_path)
    md = render_digest_markdown(digest)
    assert "signal_map" not in digest
    for text in ("Signal map", "Negative evidence", "ual(", "hashdump", "EVERY item above"):
        assert text not in md, text


def test_the_ledger_counts_a_repeated_message_once():
    """Part 12 FM-12: T22's digest printed one Volatility WARN eight times."""
    warn = {"tool": "vol", "status": "WARN",
            "reason": "process-list walk returned nothing while psscan saw 134 process(es)"}
    md = render_digest_markdown({"case_id": "CASE-X", "ledger": {"ok": 0, "skip": 0, "fail": 0,
                                                                  "entries": [warn] * 8}})
    assert md.count("process-list walk returned nothing") == 1
    assert "- WARN: vol x8 — process-list walk" in md


def test_build_digest_scopes_absent_classes(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "nexus.langgraph.briefing.case_briefing", lambda case_dir: _fake_brief()
    )
    monkeypatch.setattr(
        "nexus.langgraph.case_index.es_aggregate", lambda *a, **k: None
    )
    digest = build_case_digest(tmp_path)
    assert digest["backend"] == "elasticsearch"
    absent = digest["scope"]["explicitly_absent"]
    assert any("memory" in a for a in absent)
    assert any("disk" in a for a in absent)
    assert not any("network flows" in a for a in absent)  # zeek present


def test_render_and_write_digest(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "nexus.langgraph.briefing.case_briefing", lambda case_dir: _fake_brief()
    )
    monkeypatch.setattr(
        "nexus.langgraph.case_index.es_aggregate", lambda *a, **k: None
    )
    digest = build_case_digest(tmp_path)
    md = render_digest_markdown(digest)
    assert "Case Digest" in md
    assert "NOT in evidence" in md
    assert "[audit_id nexus-a-20260101-001]" in md
    assert "a finding that cites its audit_id, or a disposition naming that audit_id" in md
    paths = write_case_digest(tmp_path, digest)
    assert Path(paths["json"]).is_file()
    assert Path(paths["md"]).is_file()
    loaded = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert loaded["case_id"] == digest["case_id"]


_ALERTS = [
    {"key": "nexus-a-20260101-001", "audit_ids": ["nexus-a-20260101-001"], "level": "high",
     "title": "Mimikatz detected", "host": "ws01"},
    {"key": "nexus-a-20260101-002", "audit_ids": ["nexus-a-20260101-002"], "level": "critical",
     "title": "Ransomware note", "host": "ws01"},
]


def test_reconciliation_answers_alerts_by_audit_id_not_wording():
    """Part 12 FM-9: an alert is addressed by a finding that cites its rows, not by a title its text repeats."""
    findings = [
        {"title": "Mimikatz detected on ws01", "interpretation": "credential theft", "audit_ids": []},
        {"title": "Unrelated wording", "audit_ids": ["nexus-a-20260101-002"]},
    ]
    result = reconciliation_checklist({"alerts": _ALERTS}, findings)
    assert [i["key"] for i in result["addressed"]] == ["nexus-a-20260101-002"]
    assert [i["key"] for i in result["unaddressed"]] == ["nexus-a-20260101-001"]
    assert result["alerts_total"] == 2 and "needles_with_hits" not in result


def test_reconciliation_takes_a_disposition_by_its_audit_id():
    dispositions = [{"item": "nexus-a-20260101-001", "status": "benign", "reason": "test tool", "audit_ids": []}]
    result = reconciliation_checklist({"alerts": _ALERTS}, [], dispositions)
    assert [i["key"] for i in result["dispositioned"]] == ["nexus-a-20260101-001"]
    assert [i["key"] for i in result["unaddressed"]] == ["nexus-a-20260101-002"]


def test_pack_sections_duplicate_names_not_double_counted():
    """Two sections with the same name must not be silently emitted twice
    (that would double content AND the budget accounting)."""
    from nexus.langgraph.prompt_budget import pack_sections

    packed, report = pack_sections([
        (0, "case_digest", "DIGEST-CONTENT"),
        (0, "case_digest", "DIGEST-CONTENT"),
    ], chars=10_000)
    assert packed.count("DIGEST-CONTENT") == 2  # both kept, namespaced
    assert set(report["sections"]) == {"case_digest", "case_digest#2"}


def test_case_window_reads_run_options(tmp_path, monkeypatch):
    from nexus.langgraph.prompt_budget import case_window, context_window

    monkeypatch.setenv("NEXUS_LLM_CONTEXT_WINDOW", "500000")
    assert case_window(tmp_path) == 500_000  # no options file → env default
    (tmp_path / "analysis").mkdir(parents=True)
    (tmp_path / "analysis" / "mode1_run_options.json").write_text(
        json.dumps({"context_window": 128000}), encoding="utf-8"
    )
    assert case_window(tmp_path) == 128_000  # case's own window wins
    assert context_window() == 500_000       # env untouched


def test_build_digest_accepts_cached_brief(tmp_path, monkeypatch):
    """The portal passes its cached briefing — the digest must not re-scan."""
    called = {"n": 0}

    def _boom(case_dir):
        called["n"] += 1
        return _fake_brief()

    monkeypatch.setattr("nexus.langgraph.briefing.case_briefing", _boom)
    monkeypatch.setattr(
        "nexus.langgraph.case_index.es_aggregate", lambda *a, **k: None
    )
    digest = build_case_digest(tmp_path, brief=_fake_brief())
    assert called["n"] == 0
    assert digest["case_id"] == tmp_path.name


# ── n4_sample ────────────────────────────────────────────────────────────

def test_n4_sample_spreads_over_timeline(monkeypatch, tmp_path):
    from nexus.langgraph import query_pack

    hits = [
        {"family": "hayabusa", "ts": f"2024-01-01T00:{i:02d}:00", "host": "ws01",
         "text": f"row {i}"}
        for i in range(30)
    ]
    monkeypatch.setattr(query_pack, "n4_hits", lambda *a, **k: (hits, "csv"))
    monkeypatch.setattr(query_pack, "load_case_intake", lambda d: {})
    monkeypatch.setattr(query_pack, "collect_query_terms", lambda intake: ["x"])
    result = query_pack.n4_sample(tmp_path, family="hayabusa", n=6)
    assert result["matched"] == 30
    assert result["sampled"] == 6
    assert result["spread_every"] == 5
    # Spread: first and last hits are present (not a single burst)
    assert result["hits"][0]["text"] == "row 0"
    assert result["hits"][-1]["text"] == "row 25"


def test_n4_sample_family_filter(monkeypatch, tmp_path):
    from nexus.langgraph import query_pack

    hits = [
        {"family": "hayabusa", "text": "a"},
        {"family": "zeek", "text": "b"},
        {"family": "zeek", "text": "c"},
    ]
    monkeypatch.setattr(query_pack, "n4_hits", lambda *a, **k: (hits, "csv"))
    monkeypatch.setattr(query_pack, "load_case_intake", lambda d: {})
    monkeypatch.setattr(query_pack, "collect_query_terms", lambda intake: ["x"])
    result = query_pack.n4_sample(tmp_path, family="zeek", n=5)
    assert result["matched"] == 2
    assert all(h["family"] == "zeek" for h in result["hits"])


def test_n4_sample_envelope_fields_and_event_alias(monkeypatch, tmp_path):
    """CSV-shaped hits (no attached fields) must match on envelope keys, and
    `event` must alias `event_id` — the planner is told to request both."""
    from nexus.langgraph import query_pack

    hits = [
        {"family": "hayabusa", "text": "row1", "host": "WS01", "event_id": "4624",
         "user": "alice"},
        {"family": "hayabusa", "text": "row2", "host": "WS02", "event_id": "4688"},
    ]
    monkeypatch.setattr(query_pack, "n4_hits", lambda *a, **k: (hits, "csv"))
    monkeypatch.setattr(query_pack, "load_case_intake", lambda d: {})
    monkeypatch.setattr(query_pack, "collect_query_terms", lambda intake: ["x"])

    by_host = query_pack.n4_sample(tmp_path, family="hayabusa", field="host",
                                   value="WS01")
    assert by_host["matched"] == 1

    by_event = query_pack.n4_sample(tmp_path, family="hayabusa", field="event",
                                    value="4688")
    assert by_event["matched"] == 1

    by_user = query_pack.n4_sample(tmp_path, family="hayabusa", field="user")
    assert by_user["matched"] == 1  # presence filter


def test_backbone_allowlist_has_es_sample():
    """4k.5.5: the Mode 2/3 sample tool is the ES-native one."""
    from nexus.langgraph.backbone import MODE2_TOOL_ALLOWLIST, tool_contracts_block

    assert MODE2_TOOL_ALLOWLIST.get("es_sample") == "evidence"
    # WP 10.53: the model-facing contract uses the ``sample_rows`` alias, and
    # the canonical tool name stays registered/audited underneath.
    assert "sample_rows" in tool_contracts_block(2)
    assert "es_search" in tool_contracts_block(2)


def test_backbone_call_binding_exists():
    import inspect

    from nexus.langgraph import backbone

    src = inspect.getsource(backbone.backbone_call)
    # Canonical names still dispatch to the ES-native core; the alias resolver
    # maps model-facing names (sample_rows) onto the same path.
    assert 'canonical in ("es_fields", "es_search", "es_aggregate", "es_sample")' in src
    assert "canonical = _resolve_tool(name)" in src


# ── interpretation reconciliation ────────────────────────────────────────

def test_interpretation_file_includes_reconciliation(tmp_path):
    import asyncio

    from nexus.langgraph.interpretation import write_interpretation_summary

    out = asyncio.run(write_interpretation_summary(
        tmp_path,
        findings=[{"title": "F1", "interpretation": "i", "confidence": "HIGH"}],
        reconciliation={
            "addressed": [{"kind": "alert", "key": "a1", "value": "[HIGH] F1 (ws01)"}],
            "unaddressed": [{"kind": "alert", "key": "a2", "value": "[CRITICAL] Ransomware note (ws01)"}],
            "alerts_total": 2,
        },
        model=None,
    ))
    assert out is not None
    text = Path(out).read_text(encoding="utf-8")
    assert "Reconciliation" in text
    assert "Ransomware note" in text
    assert "1 addressed / 0 dispositioned / 1 unaddressed** of 2 crit/high alerts" in text
