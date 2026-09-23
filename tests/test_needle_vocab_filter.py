"""F6: needle vocabulary gate (numbers/container names out of the scan)
+ external (ATT&CK-grounded) needle packs."""

from __future__ import annotations


def test_split_terms_routes_numbers_and_container_names():
    from nexus.knowledge.needle_terms import (
        filter_scannable,
        is_scannable_term,
        split_terms,
    )

    scan, context = split_terms([
        "cipher /w", "1102", "security.evtx", "4625", "net use", "SYSTEM.evtx",
        "mimikatz",
    ])
    assert scan == ["cipher /w", "net use", "mimikatz"]
    assert context["event_ids"] == ["1102", "4625"]
    assert context["artifacts"] == ["security.evtx", "SYSTEM.evtx"]

    assert not is_scannable_term("325")
    assert not is_scannable_term("System.evtx")
    assert is_scannable_term("vssadmin delete shadows")
    assert filter_scannable(["41", "sdelete"]) == ["sdelete"]


def test_playbook_terms_filtered_and_event_ids_preserved():
    from nexus.langgraph.query_pack import _playbook_event_ids, _playbook_terms

    terms = _playbook_terms(["log_tampering"])
    assert "1102" not in terms and "104" not in terms
    assert "security.evtx" not in terms and "system.evtx" not in terms
    assert "wevtutil" in [t.lower() for t in terms]

    event_ids = _playbook_event_ids(["log_tampering"])
    assert "1102" in event_ids and "104" in event_ids


def test_attack_and_sigma_terms_filtered():
    from nexus.knowledge.attack_needles import attack_needles_for
    from nexus.knowledge.sigma_needles import sigma_needles_for

    attack = attack_needles_for(families={"evtxecmd", "hayabusa"}, limit=8, cap=200)
    assert attack, "expected attack needles for these families"
    assert all(not str(t).strip().isdigit() for t in attack), [
        t for t in attack if str(t).strip().isdigit()
    ]

    sigma = sigma_needles_for({"evtxecmd", "hayabusa"}, limit=5, cap=200)
    assert all(not str(t).strip().isdigit() for t in sigma), [
        t for t in sigma if str(t).strip().isdigit()
    ]


def test_external_pack_valid_and_scannable():
    from nexus.knowledge.external_needles import (
        external_needles_for,
        external_packs_for,
        external_strong_for,
    )
    from nexus.knowledge.loader import get_attack_registry

    ids = {t["id"] for t in get_attack_registry()["techniques"]}
    packs = get_attack_registry and external_packs_for(
        {"prefetch", "evtxecmd", "hayabusa", "browser"}, limit=10
    )
    assert packs, "no external packs matched those families"
    for pack in packs:
        assert str(pack.get("attack") or "").upper() in ids, pack.get("attack")
        assert pack.get("needles") and pack.get("caveat")

    needles = external_needles_for({"prefetch", "evtxecmd"})
    assert "psexec.exe" in [n.lower() for n in needles]

    strong = external_strong_for({"prefetch", "evtxecmd"})
    assert "psexesvc" in [s.lower() for s in strong]
    assert external_needles_for(set()) == []


def test_briefing_and_endpoint_carry_external():
    import tempfile
    from pathlib import Path

    from nexus.langgraph.briefing import _scan_needles

    mapped = _scan_needles(Path(tempfile.mkdtemp()), ["prefetch", "evtxecmd"])
    labels = set(mapped.values())
    assert "external" in labels or "external-strong" in labels, labels
    # The vocabulary gate holds end to end: no bare numbers become needles.
    assert not [k for k in mapped if str(k).strip().isdigit()]

    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    client = TestClient(Starlette(routes=create_dashboard()))
    data = client.get("/portal/api/playbook/needles?families=evtxecmd").json()
    sources = {s.get("source") for s in (data.get("suggestions") or [])}
    assert "external" in sources, sources
