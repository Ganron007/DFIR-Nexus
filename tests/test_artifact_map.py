"""YAML artifact map drives presence — not a hardcoded first-user planner."""

from pathlib import Path

from nexus.langgraph.artifact_map import (
    completeness_table,
    discover_windows_artifacts,
    glob_location,
    user_profile_dirs,
)
from nexus.langgraph.case_intake import extra_playbook_names, persist_case_intake
from nexus.langgraph.tool_lane import plan_windows_triage


def _win_root(tmp_path: Path) -> Path:
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    return root


def test_user_profile_dirs_skips_default_public(tmp_path: Path):
    root = _win_root(tmp_path)
    (root / "Users" / "alice").mkdir(parents=True)
    (root / "Users" / "Public").mkdir(parents=True)
    (root / "Users" / "Default").mkdir(parents=True)
    names = [p.name for p in user_profile_dirs(root)]
    assert names == ["alice"]


def test_glob_prefetch_dir_counts_as_present(tmp_path: Path):
    root = _win_root(tmp_path)
    (root / "Windows" / "Prefetch").mkdir(parents=True)
    hits = glob_location(root, r"C:\Windows\Prefetch\*.pf")
    assert hits
    assert hits[0].name == "Prefetch"


def test_discover_prefetch_present_schedules_pecmd(tmp_path: Path):
    root = _win_root(tmp_path)
    (root / "Windows" / "Prefetch").mkdir(parents=True)
    arts = discover_windows_artifacts(root)
    prefetch = next(a for a in arts if a.slug == "prefetch")
    assert prefetch.present
    jobs = plan_windows_triage(str(root), tmp_path / "ex")
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    assert "pecmd" in pending
    table = completeness_table(arts, pending)
    row = next(r for r in table if r["artifact"] == "Prefetch")
    assert row["status"] == "SCHEDULED"


def test_playbook_hints_from_hypothesis():
    names = extra_playbook_names({
        "hypothesis": "insider-threat USB staging",
        "playbooks": "unusual_logon",
    })
    assert "unusual_logon" in names
    assert "usb_activity" in names
    assert "data_staging" in names


def test_persist_case_intake(tmp_path: Path):
    case_dir = tmp_path / "INC-1"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: INC-1\nname: t\n", encoding="utf-8")
    written = persist_case_intake(case_dir, {
        "timezone": "UTC",
        "question": "What staged?",
        "hypothesis": "insider",
    })
    assert written["timezone"] == "UTC"
    assert "data_staging" in written["playbooks"]
    text = (case_dir / "CASE.yaml").read_text(encoding="utf-8")
    assert "intake:" in text
    assert "timezone: UTC" in text


def test_prefetch_related_tools_is_pecmd():
    from nexus.knowledge.loader import get_artifact

    prefetch = get_artifact("prefetch")
    assert prefetch is not None
    tools = [t.lower() for t in prefetch.get("related_tools") or []]
    assert "pecmd" in tools


def test_browser_history_includes_sqlecmd():
    from nexus.knowledge.loader import get_artifact

    browser = get_artifact("browser_history")
    assert browser is not None
    tools = [t.lower() for t in browser.get("related_tools") or []]
    assert "sqlecmd" in tools


def test_auth_log_is_not_windows_evtx():
    from nexus.knowledge.loader import get_artifact

    auth = get_artifact("auth_log", platform="linux")
    assert auth is not None
    tools = [t.lower() for t in auth.get("related_tools") or []]
    assert "evtxecmd" not in tools
    assert "hayabusa" not in tools


def test_user_activity_mru_present_with_ntuser(tmp_path: Path):
    root = _win_root(tmp_path)
    nt = root / "Users" / "alice" / "NTUSER.DAT"
    nt.parent.mkdir(parents=True)
    nt.write_bytes(b"hive")
    cfg = root / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "SOFTWARE").write_bytes(b"hive")
    arts = discover_windows_artifacts(root)
    mru = next(a for a in arts if a.slug == "user_activity_mru")
    assert mru.present
    assert any(t.lower() == "recmd" for t in mru.related_tools)
    jobs = plan_windows_triage(str(root), tmp_path / "ex")
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    table = completeness_table(arts, pending)
    row = next(r for r in table if r["artifact"] == "User Activity MRU")
    if "recmd" in pending:
        assert row["status"] == "SCHEDULED"
    else:
        assert any(j.tool == "recmd" and j.status == "SKIP" for j in jobs)


def test_usn_schedules_mftecmd_when_j_present(tmp_path: Path):
    root = _win_root(tmp_path)
    j = root / "$Extend" / "$J"
    j.parent.mkdir(parents=True)
    j.write_bytes(b"usn" * 2000)  # usable $J, not a 0-byte Samba stub
    jobs = plan_windows_triage(str(root), tmp_path / "ex")
    usn = [
        j for j in jobs
        if j.tool == "mftecmd" and j.status == "PENDING" and "usn.csv" in " ".join(j.argv)
    ]
    assert len(usn) == 1
    arts = discover_windows_artifacts(root)
    usn_art = next(a for a in arts if a.slug == "usn_journal")
    assert usn_art.present


def test_windows_catalog_has_knowledge_cards():
    from nexus.knowledge.loader import list_tools
    from nexus.tools.windows import _WIN_CATALOG

    def norm(s: str) -> str:
        n = s.lower().replace(" ", "").replace("-", "").replace("_", "")
        n = n.replace(".pl", "").replace(".exe", "").replace(".py", "").replace("64", "")
        return n

    names = {norm(str(t.get("name") or "")) for t in list_tools()}
    missing = []
    for key, info in _WIN_CATALOG.items():
        if norm(key) not in names and norm(info["name"]) not in names:
            missing.append(key)
    assert missing == []
