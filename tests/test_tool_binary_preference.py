"""The lane must run the current Zimmerman parsers, not KAPE's 2022 bundle.

Regression guard for 3348fbd: `_find_binary` used to order candidates by
extension then alphabetical order, so `Tools/windows/kape/...` beat
`Tools/windows/zimmerman/...` purely on the letter "k" - every Zimmerman
parser we executed was four years old (old MFTECmd cannot read `$LogFile`;
old SQLECmd chokes on newer `.smap` maps and produced no browser output).

`_prefer_binary` is a pure function, so these tests use synthetic paths - no
tools tree required.
"""
from __future__ import annotations

from pathlib import Path

from nexus.tools.windows import _prefer_binary

NET9 = Path("repo/Tools/windows/zimmerman/net9/AmcacheParser.exe")
ZIMMERMAN = Path("repo/Tools/windows/zimmerman/legacy/AmcacheParser.exe")
EXTRA = Path("repo/Tools/windows/extra/regripper/rip.exe")
SYSINTERNALS = Path("repo/Tools/windows/sysinternals/sigcheck64.exe")
KAPE = Path("repo/Tools/windows/kape/Modules/bin/AmcacheParser.exe")
UNKNOWN = Path("D:/custom/tools/AmcacheParser.exe")


def test_net9_wins_over_kape_in_both_discovery_orders():
    assert _prefer_binary([KAPE, NET9]) == NET9
    assert _prefer_binary([NET9, KAPE]) == NET9


def test_toolset_rank_order():
    assert _prefer_binary([KAPE, SYSINTERNALS, EXTRA, ZIMMERMAN, NET9]) == NET9
    assert _prefer_binary([KAPE, SYSINTERNALS, EXTRA, ZIMMERMAN]) == ZIMMERMAN
    assert _prefer_binary([KAPE, SYSINTERNALS, EXTRA]) == EXTRA
    assert _prefer_binary([KAPE, SYSINTERNALS]) == SYSINTERNALS
    # The KAPE bundle is the oldest known toolset, but it still outranks a
    # path no toolset marker recognises.
    assert _prefer_binary([KAPE, UNKNOWN]) == KAPE


def test_unknown_path_wins_only_alone():
    assert _prefer_binary([UNKNOWN, NET9]) == NET9
    assert _prefer_binary([UNKNOWN]) == UNKNOWN


def test_empty_input_returns_none():
    assert _prefer_binary([]) is None
