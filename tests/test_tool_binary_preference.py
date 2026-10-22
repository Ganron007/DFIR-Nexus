"""The lane runs the current Zimmerman parsers, and never a copy from KAPE's bundle (D104).

Regression guard for 3348fbd: `_find_binary` used to order candidates by extension then alphabetical order, so
`Tools/windows/kape/...` beat `Tools/windows/zimmerman/...` purely on the letter "k" - every Zimmerman parser we
executed was four years old (old MFTECmd cannot read `$LogFile`; old SQLECmd chokes on newer `.smap` maps).

Operator decision 2026-10-13 (D104): the KAPE bundle is no longer a fallback. A tool the current toolset lacks is a
SKIP. kape.exe and gkape.exe are the collector and stay resolvable.

`_prefer_binary` is a pure function, so these tests use synthetic paths - no tools tree required.
"""
from __future__ import annotations

from pathlib import Path

from nexus.tools.windows import _prefer_binary

NET10 = Path("repo/Tools/windows/extra/evtxecmd-2026.10.0/zimmerman/net10/EvtxECmd.exe")
NET9 = Path("repo/Tools/windows/zimmerman/net9/AmcacheParser.exe")
ZIMMERMAN = Path("repo/Tools/windows/zimmerman/legacy/AmcacheParser.exe")
EXTRA = Path("repo/Tools/windows/extra/regripper/rip.exe")
SYSINTERNALS = Path("repo/Tools/windows/sysinternals/sigcheck64.exe")
KAPE = Path("repo/Tools/windows/kape/Modules/bin/AmcacheParser.exe")
KAPE_LAUNCHER = Path("repo/Tools/windows/kape/kape.exe")
UNKNOWN = Path("D:/custom/tools/AmcacheParser.exe")


def test_net9_wins_over_zimmerman_copies_in_both_discovery_orders():
    assert _prefer_binary([ZIMMERMAN, NET9]) == NET9
    assert _prefer_binary([NET9, ZIMMERMAN]) == NET9


def test_net10_release_wins_over_net9_and_legacy_copies():
    assert _prefer_binary([NET9, ZIMMERMAN, NET10]) == NET10
    assert _prefer_binary([NET10, NET9, ZIMMERMAN]) == NET10


def test_toolset_rank_order():
    assert _prefer_binary([SYSINTERNALS, EXTRA, ZIMMERMAN, NET9, NET10]) == NET10
    assert _prefer_binary([SYSINTERNALS, EXTRA, ZIMMERMAN]) == ZIMMERMAN
    assert _prefer_binary([SYSINTERNALS, EXTRA]) == EXTRA
    assert _prefer_binary([SYSINTERNALS]) == SYSINTERNALS


def test_kape_bundle_copies_are_never_selected():
    # A bundle copy is not a candidate at all: alone it resolves to nothing, so the tool is a SKIP.
    assert _prefer_binary([KAPE]) is None
    assert _prefer_binary([KAPE, NET9]) == NET9
    assert _prefer_binary([KAPE, SYSINTERNALS]) == SYSINTERNALS


def test_kape_launcher_stays_resolvable():
    assert _prefer_binary([KAPE_LAUNCHER]) == KAPE_LAUNCHER


def test_unknown_path_wins_only_alone():
    assert _prefer_binary([UNKNOWN, NET9]) == NET9
    assert _prefer_binary([UNKNOWN]) == UNKNOWN


def test_empty_input_returns_none():
    assert _prefer_binary([]) is None
