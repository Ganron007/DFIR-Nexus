"""Entity/needle hygiene: machine paths and schema labels must not leak.

Live report (2026-09-23): a Mode 1 scan surfaced `domain_user`,
`STUDY\\Github`, `CADRE-Platform\\DFIR-Nexus` — the DOMAIN\\user regex matched
every segment of the local repo path, and the scan vocabulary accepted
path-like tokens / entity-type labels as needles.
"""

from __future__ import annotations

import pytest

REPO_TEXT = r"copy C:\STUDY\Github\CADRE-Platform\DFIR-Nexus\Evidence-files\01-windows to D:\out"


def test_langgraph_entities_ignore_path_segments():
    from nexus.langgraph.entities import extract_entities

    hits = [{
        "family": "hayabusa",
        "file": "a.csv",
        "line": 1,
        "text": REPO_TEXT + r" and CORP\fredr logged on",
    }]
    ents = extract_entities(hits)
    values = [e["value"] for e in ents.get("domain_user", [])]
    assert r"CORP\fredr" in values
    assert not any(v.startswith(("STUDY", "CADRE", "Evidence-files", "evtx")) for v in values)
    assert not any("Github" in v for v in values)


def test_analysis_entities_ignore_path_segments():
    from nexus.analysis.entities import extract_entities

    out = extract_entities([REPO_TEXT + r" user CORP\fredr"])
    assert r"CORP\fredr" in out["users"]
    assert all("STUDY" not in u and "CADRE" not in u and "Nexus" not in u for u in out["users"])


def test_entity_inventory_ignores_path_valued_fields():
    from nexus.langgraph.entity_inventory import build_entity_inventory

    inv = build_entity_inventory(
        "CASE-HYGIENE",
        hits=[{
            "family": "evtxecmd",
            "file": "a.csv",
            "line": 1,
            "text": "row",
            "fields": {"UserName": r"C:\STUDY\Github\CADRE-Platform\DFIR-Nexus\out"},
        }],
    )
    assert all("STUDY" not in u for u in (inv.get("users") or {}))


def test_is_needle_like_filters_paths_labels_and_numbers():
    from nexus.langgraph.query_pack import is_needle_like

    assert not is_needle_like("STUDY\\Github")
    assert not is_needle_like("CADRE-Platform\\DFIR-Nexus")
    assert not is_needle_like("domain_user")
    assert not is_needle_like("21")       # stray short number
    assert not is_needle_like("123")
    assert not is_needle_like("C:\\Windows\\Temp")
    assert is_needle_like("4624")         # event IDs are first-class needles
    assert is_needle_like("1102")
    assert is_needle_like("powershell")
    assert is_needle_like("sdelete")
    assert is_needle_like("10.0.0.5")


def test_scan_needles_drops_paths_and_type_labels(tmp_path):
    from nexus.langgraph import briefing
    from nexus.langgraph.case_intake import persist_case_intake

    case = tmp_path / "CASE-SCAN"
    case.mkdir()
    persist_case_intake(case, {
        "query_extra": "\n".join([
            "domain_user",
            r"STUDY\Github",
            r"CADRE-Platform\DFIR-Nexus",
            "sdelete",
        ]),
    })

    needles = briefing._scan_needles(case, ["hayabusa"], [])

    assert "sdelete" in needles
    assert "domain_user" not in needles
    assert all("\\" not in k for k in needles)
    assert all("/" not in k for k in needles)


@pytest.mark.parametrize("token", ["STUDY\\Github", "CADRE-Platform\\DFIR-Nexus", "domain_user"])
def test_live_leak_tokens_are_filtered(token):
    from nexus.langgraph.query_pack import is_needle_like

    assert not is_needle_like(token.lower())
