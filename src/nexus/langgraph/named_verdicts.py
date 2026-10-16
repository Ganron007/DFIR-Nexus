"""The baseline checks a claim's own words credit, and whether the calls it cites returned them (D258).

D238 checks the events a claim names against the calls it cites. What a claim says a check answered was not
checked. On CASE-C5B04D31 (fresh Mode 2 run ``M2-20261016T210141-b9e203``, 2026-10-16) a work order wrote
"check_file on STUN.exe path ... and check_lolbin on standard system binaries confirm STUN.exe is a legitimate
Windows component (Windows Defender Update service)", citing one memory YARA search. No ``check_file`` call on
STUN.exe had run; the one that ran 16 minutes later answered UNKNOWN (no Windows build ships the file, yet it
sits in the Windows directory). Later seats read the statement as "check_file EXPECTED", and two candidates
called the implant a legitimate Defender component.

A check is named by its tool name: the examiner checks of the loop's toolkit (``context_loop._TOOL_ARGS``). A
verdict is named by its value as the checks return it (``triage.analysis.Verdict``). Nothing is typed here.
A statement that names a check cites a call of that check, and a verdict named in the same sentence is one a
cited call of that check returned; when the sentence names a value one of those calls was asked about, the
calls on that value answer. A check named in a sentence of absence ("check_file was not run") is not asserted.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from nexus.langgraph.named_events import _CLAUSE_END, _NOT_FOUND

#: Words that make the rest of their sentence say a check was not run or not known to answer. D238's list less
#: "expected", which is a verdict here.
_NEGATION = re.compile(r"\b(?:no|not|without|never|none|nothing|neither|nor|cannot|can't|unable|would|could|"
                       r"might|if|whether)\b", re.I)


#: The same sentence, after the check, saying it did not run ("check_file was not run on STUN.exe").
_NOT_RUN = re.compile(r"\b(?:not|never)\s+(?:been\s+)?(?:run|ran|called|executed|performed|checked)\b", re.I)


def _negated(text: str, start: int, end: int) -> bool:
    before = _CLAUSE_END.split(text[:start])[-1]
    after = _CLAUSE_END.split(text[end:], maxsplit=1)[0]
    return bool(_NEGATION.search(before) or _NOT_FOUND.search(after) or _NOT_RUN.search(after))


@lru_cache(maxsize=1)
def verdict_tools() -> tuple[str, ...]:
    """The loop's examiner checks that answer with a baseline verdict, longest name first."""
    from nexus.langgraph.context_loop import _TOOL_ARGS

    tools = [t for t in _TOOL_ARGS if t.startswith("check_") or t == "analyze_filename_triage"]
    return tuple(sorted(tools, key=len, reverse=True))


@lru_cache(maxsize=1)
def _patterns() -> tuple[re.Pattern[str], re.Pattern[str]]:
    from nexus.triage.analysis import Verdict

    tool = re.compile(r"(?<![\w])(" + "|".join(map(re.escape, verdict_tools())) + r")(?![\w])", re.I)
    # As the checks print them, so "unknown" in prose is not a verdict. Longest first: EXPECTED_LOLBIN.
    values = sorted((v.value for v in Verdict), key=len, reverse=True)
    verdict = re.compile(r"(?<![\w])(" + "|".join(map(re.escape, values)) + r")(?![\w])")
    return tool, verdict


#: (check, verdicts the sentence names, the sentence): a check a text credits.
Mention = tuple[str, tuple[str, ...], str]


def named_verdicts(text: Any) -> list[Mention]:
    """The checks the text credits, each with the verdicts its sentence names, in order."""
    text = str(text or "")
    if not text.strip():
        return []
    tool, verdict = _patterns()
    found: list[Mention] = []
    for m in tool.finditer(text):
        if _negated(text, m.start(), m.end()):
            continue
        start = len(text[:m.start()]) - len(_CLAUSE_END.split(text[:m.start()])[-1])
        sentence = text[start:m.end() + len(_CLAUSE_END.split(text[m.end():], maxsplit=1)[0])]
        named = tuple(dict.fromkeys(v.group(1) for v in verdict.finditer(sentence)))
        found.append((m.group(1).lower(), named, sentence))
    return found


def _asked_about(call: dict[str, Any], sentence: str) -> bool:
    """The sentence names a value the call was asked about (a path also by its file name)."""
    low = sentence.lower()
    for value in (call.get("params") or {}).values():
        value = str(value or "").strip().lower()
        if len(value) < 3:
            continue
        name = re.split(r"[\\/]", value)[-1]
        if value in low or (len(name) >= 3 and name in low):
            return True
    return False


def verdict_grounding(text: Any, calls: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """``{"grounded": [...], "ungrounded": [...]}``: for each check the text credits, whether a cited call of
    that check returned what the text says. ``calls`` are the claim's own (``evidence_rows.cited_calls``)."""
    grounded: list[str] = []
    ungrounded: list[str] = []
    for tool, verdicts, sentence in named_verdicts(text):
        own = [c for c in calls.values() if str(c.get("tool") or "") == tool]
        label = f"{tool} {'/'.join(verdicts)}".strip()
        if not own:
            ungrounded.append(f"{label} (it cites no {tool} call)")
            continue
        answering = [c for c in own if _asked_about(c, sentence)] or own
        returned = {str(c.get("verdict") or "") for c in answering}
        if verdicts and not returned & set(verdicts):
            got = ", ".join(sorted(v or "no verdict" for v in returned))
            ungrounded.append(f"{label} (the cited {tool} call returned {got})")
        else:
            grounded.append(label)
    return {"grounded": list(dict.fromkeys(grounded)), "ungrounded": list(dict.fromkeys(ungrounded))}
