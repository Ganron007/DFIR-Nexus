"""WP 9.7 — DET dictionary tests.

Detection dictionaries (ICS/OT, cloud, kernel/rootkit, maldev-evasion) load
from `data/knowledge/det/` and annotate hit interpretation with extra
`look_for` + `caveats`.
"""
from __future__ import annotations


def test_det_dictionaries_load():
    from nexus.knowledge.loader import get_det

    entries = get_det()
    assert len(entries) >= 20, f"expected the DET corpus, found {len(entries)}"
    for e in entries:
        assert e.get("id"), e
        assert e.get("name"), e
        assert e.get("look_for"), e
        assert e.get("caveats"), e
        assert e.get("platform"), e


def test_det_platforms_present():
    from nexus.knowledge.loader import get_det

    platforms = {str(e.get("platform")) for e in get_det()}
    for want in ("ics_ot", "cloud", "windows_kernel", "windows_maldev"):
        assert want in platforms, f"missing DET platform {want}"


def test_det_for_matches_platforms():
    from nexus.knowledge.loader import det_for

    ics = det_for(keywords={"modbus"})
    assert ics and any(x["platform"] == "ics_ot" for x in ics)

    cloud = det_for(techniques={"T1078.004"})
    assert cloud and cloud[0]["platform"] == "cloud"

    kernel = det_for(techniques={"T1014"})
    assert kernel and any(x["platform"] == "windows_kernel" for x in kernel)

    # no match → empty
    assert det_for(families={"zzz"}, keywords={"nonexistent"}) == []


def test_interpret_hit_surfaces_det():
    from nexus.langgraph.interpret import interpret_hit

    out = interpret_hit(None, {
        "family": "cloudtrail",
        "terms": "CreateAccessKey",
        "text": "eventName=CreateAccessKey user=bob T1098.001",
    })
    assert out.get("det"), "expected DET annotations on a cloud hit"
    assert "det" in out["sources"]
    assert any(d.get("platform") == "cloud" for d in out["det"])
