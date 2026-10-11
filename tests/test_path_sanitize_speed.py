"""The machine-path sanitiser is faster and gives the same output (WO-TA item 10, 2026-10-11).

The reference below is the sanitiser as it was before the speed change, reproduced from git HEAD. The
product function must agree with it on crafted and random texts. The real-row check (40,000 rows of the
case's committed run) was run as a scratch script with 0 mismatches; these tests keep the rule in place.
"""

from __future__ import annotations

import random
import re
from pathlib import Path

import pytest

from nexus.langgraph import path_sanitize as ps


def _reference(text: str, roots: list[tuple[str, str]]) -> str:
    """The original body of sanitize_machine_paths: every root tested for every text."""
    if not text:
        return text
    if not any(ch in text for ch in ("\\", "/", ":")):
        return text
    if not roots:
        return text
    out = text
    low = out.lower()
    for prefix, label in roots:
        replaced = False
        for variant, vlow in ps._prefix_variants(prefix):
            if variant in out or vlow in low:
                out = re.sub(re.escape(variant), label, out, flags=re.IGNORECASE)
                replaced = True
        if replaced:
            low = out.lower()
    out = ps._ANALYST_STAGING_RE.sub(ps._LABEL_STAGING, out)
    out = ps._ANALYST_CACHE_RE.sub(ps._LABEL_HOME, out)
    out = ps._NEXUS_HOME_RE.sub(ps._LABEL_HOME, out)
    out = ps._NEXUS_CASE_RE.sub(ps._LABEL_CASE, out)
    return out


ROOTS = [
    (r"C:\Work\DFIR-Nexus", "<repo>"),
    (r"C:\Work\DFIR-Nexus\cases\CASE-1", "<case>"),
    ("/home/analyst", "<home>"),
    (r"D:\Evidence", "<evidence>"),
]

CRAFTED = [
    "",
    "no path characters at all",
    r"C:\Work\DFIR-Nexus\cases\CASE-1\extractions\x.csv",
    r"c:\work\dfir-nexus\cases\case-1\x.csv",
    "C:/Work/DFIR-Nexus/cases/CASE-1/x.csv",
    r"see D:\Evidence\disk.E01 and C:\Work\DFIR-Nexus",
    "file:///home/analyst/.nexus/cases/CASE-9/evidence.json",
    "/home/analyst/nexus-es-mapping/run.csv",
    "/home/someone/.cache/volatility3/symbols",
    "/home/someone/.nexus/cases/CASE-7/x",
    r"\.nexus\cases\CASE-3\x",
    r".nexuſ\cases\CASE-3\x",  # long s folds to s under ignore-case: the reason the literal is ".nex"
    "/HOME/ANALYST/NEXUS-ES-MAPPING",
    "2026-10-11T09:00:00Z 4104 Get-Item C:\\Users\\x",
]


@pytest.mark.parametrize("text", CRAFTED)
def test_crafted_texts_match_the_reference(text):
    assert ps.sanitize_machine_paths(text, roots=ROOTS) == _reference(text, ROOTS)


def test_random_texts_match_the_reference():
    rng = random.Random(20261011)
    pieces = [
        r"C:\Work\DFIR-Nexus", r"C:\Work\DFIR-Nexus\cases\CASE-1", "/home/analyst", r"D:\Evidence",
        "/home/", ".nexus", "cases", "nexus-es-mapping", ".cache", "ſ", "S", "\\", "/", ":", "x", " ",
        "AbC", "file://", "CASE-1", "\\\\", "//",
    ]
    for _ in range(3000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 12)))
        assert ps.sanitize_machine_paths(text, roots=ROOTS) == _reference(text, ROOTS), text


def test_no_roots_leaves_the_text_alone():
    assert ps.sanitize_machine_paths(r"C:\Work\DFIR-Nexus\x", roots=[]) == r"C:\Work\DFIR-Nexus\x"


def test_the_root_probe_is_reused_for_one_roots_list_and_rebuilt_when_it_changes():
    roots = list(ROOTS)
    first = ps._root_probe_for(roots)
    assert ps._root_probe_for(roots) is first
    roots.append((r"E:\Other", "<other>"))
    assert ps._root_probe_for(roots) is not first
