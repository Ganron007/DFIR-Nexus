"""Hive routing fixes found by the debug matrix (2026-09-29, CASE-4BA41128).

Two real gaps on the DEFAULT hive:
- RECmd: every machine/user batch returns zero rows on DEFAULT, and a dirty
  hive without transaction logs aborts unless `--nl true` is passed. The hive
  produced no output and the lane (correctly) failed it.
- RegRipper: `_regripper_profile("DEFAULT")` mapped to a `default` profile that
  does not ship with RegRipper, so `rip -f default` died with a Perl module
  error and 42 bytes of output.

Both are pinned here so they cannot return silently.
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph import tool_lane as tl


def test_regripper_reads_every_user_hive_recmd_reads_with_its_profile(monkeypatch, tmp_path):
    """TA-6 (T03-OPT, 2026-10-30): a drive tree whose only hives are a user's. The RegRipper step never collected
    NTUSER.DAT ("no hives found for RegRipper" on T03), and its private profile table labelled UsrClass hives so
    that they ran `all`; both steps now read `_user_hives` and the profile comes from `_regripper_profile`."""
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    user = root / "Users" / "fredr"
    (user / "AppData/Local/Microsoft/Windows").mkdir(parents=True)
    (user / "NTUSER.DAT").write_bytes(b"")
    (user / "AppData/Local/Microsoft/Windows/UsrClass.dat").write_bytes(b"")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    for profile in ("ntuser", "usrclass", "all"):
        (plugins / profile).write_text("x", encoding="utf-8")
    monkeypatch.setenv("NEXUS_LANE_OPT_IN", "regripper")
    monkeypatch.setattr(tl, "_windows_tool_available", lambda name: True)
    monkeypatch.setattr(tl, "_windows_tool_path", lambda name: f"{name}.exe")
    monkeypatch.setattr(tl, "_regripper_plugins_dir", lambda: plugins)

    jobs = tl.plan_windows_triage(str(root), tmp_path / "ex")

    regripper = sorted((Path(j.argv[2]).name, j.argv[4]) for j in jobs if j.tool == "regripper")
    assert regripper == [("NTUSER.DAT", "ntuser"), ("UsrClass.dat", "usrclass")]
    recmd = sorted(Path(j.argv[j.argv.index("-f") + 1]).name for j in jobs if j.tool == "recmd" and "-f" in j.argv)
    assert recmd == ["NTUSER.DAT", "UsrClass.dat"]


def test_recmd_batch_for_default_prefers_dfirbatch(monkeypatch, tmp_path):
    sentinel = tmp_path / "DFIRBatch.reb"
    sentinel.write_text("x", encoding="utf-8")
    monkeypatch.setattr(tl, "_find_recmd_dfir_batch", lambda: sentinel)
    monkeypatch.setattr(tl, "_find_recmd_batch", lambda: tmp_path / "kroll.reb")
    monkeypatch.setattr(tl, "_find_recmd_user_batch", lambda: tmp_path / "user.reb")
    assert tl._recmd_batch_for(Path("DEFAULT")) == sentinel


def test_recmd_batch_for_still_uses_user_batch_for_ntuser(monkeypatch, tmp_path):
    sentinel = tmp_path / "user.reb"
    monkeypatch.setattr(tl, "_find_recmd_dfir_batch", lambda: tmp_path / "dfir.reb")
    monkeypatch.setattr(tl, "_find_recmd_batch", lambda: tmp_path / "kroll.reb")
    monkeypatch.setattr(tl, "_find_recmd_user_batch", lambda: sentinel)
    assert tl._recmd_batch_for(Path("NTUSER.DAT")) == sentinel


def test_regripper_profile_uses_a_shipped_profile(monkeypatch, tmp_path):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    for name in ("software", "all", "ntuser"):
        (plugins / name).write_text("plugins", encoding="utf-8")
    monkeypatch.setattr(tl, "_regripper_plugins_dir", lambda: plugins)
    assert tl._regripper_profile("SOFTWARE") == "software"
    assert tl._regripper_profile("NTUSER-fredr.DAT") == "ntuser"


def test_regripper_profile_falls_back_to_all_when_missing(monkeypatch, tmp_path):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "all").write_text("plugins", encoding="utf-8")
    monkeypatch.setattr(tl, "_regripper_plugins_dir", lambda: plugins)
    # No `default` profile ships; the fixture has none either.
    assert tl._regripper_profile("DEFAULT") == "all"
    assert tl._regripper_profile("SECURITY") == "all"
