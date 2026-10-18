r"""JSON a model writes, read with the one repair its forensic text needs.

Models write Windows paths into JSON strings with single backslashes: the JSON text
``"C:\Windows\System32"`` instead of ``"C:\\Windows\\System32"``. ``\W`` is not a JSON escape, so
the whole reply fails to parse. On 2026-10-14 a 10,160-character Mode 1 plan failed at
``"C:\Windows\System32\WindowsPowerShell\..."`` and the run read it as "no plan". Doubling every
backslash that does not begin a valid JSON escape keeps the text the model meant, character for
character. Valid escapes (``\n``, ``\"``, ``\\``, ``\uXXXX`` and the rest) are left as they are,
and nothing else is changed: a reply that is broken in any other way still fails to parse.
"""
from __future__ import annotations

import json
import re
from typing import Any

#: A valid escape is consumed whole, so an escaped backslash is never split; a lone backslash
#: anywhere else is the invalid one.
_ESCAPE = re.compile(r'\\(["\\/bfnrt]|u[0-9a-fA-F]{4})|\\')


def repair_invalid_escapes(text: str) -> str:
    """Double each backslash that does not start a valid JSON escape."""
    return _ESCAPE.sub(lambda m: m.group(0) if m.group(1) else "\\\\", text)


#: A one-letter escape written between two name characters, the backslash itself unescaped.
_NAME_ESCAPE = re.compile(r"(?<=[\w:$.)\]])\\([bfnrt])(?=\w)")
_DRIVE = re.compile(r"[A-Za-z]:")


def repair_path_escapes(text: str) -> str:
    """Double a backslash that separates the parts of a Windows name but reads as a JSON escape (D215).

    A path segment that begins with t, f, r, b or n makes a valid escape out of its separator, so the
    reply parses and the name is cut by a control character: `c:\\terraform` read as a tab,
    `helpers\\functions` as a form feed, `shieldbase\\rd01$` as a carriage return (CASE-C5B04D31's
    DRAFTs 017 and 041). Between two name characters a tab, form feed, carriage return or backspace
    is never what a model means. `\\n` is read as a separator only inside a name that is already a
    path (a drive or an earlier backslash), so a newline in prose stays a newline.
    """
    def fix(match: re.Match[str]) -> str:
        if match.group(1) != "n":
            return "\\\\" + match.group(1)
        start = max(text.rfind(c, 0, match.start()) for c in ' "\'\n\t') + 1
        token = text[start:match.start()]
        return "\\\\n" if ("\\" in token or _DRIVE.search(token)) else match.group(0)

    return _NAME_ESCAPE.sub(fix, text)


def json_error_note(text: str) -> str:
    """Where a reply stops being JSON: the decoder's message and the text around it, for a corrective retry.

    A retry that said only "could not be read" got the same mistake back: on sample S03 (2026-10-18) Muse Spark
    closed a nested query clause one brace short in its notes, and again in its retry, and the Mode 1 loop stopped
    after one round. The retry now shows the place. "" when the reply parses.
    """
    text = (text or "").strip()
    start = min((i for i in (text.find("{"), text.find("[")) if i != -1), default=-1)
    blob = text[start:] if start != -1 else text
    try:
        loads_model_json(blob)
    except json.JSONDecodeError as exc:
        before, after = blob[max(0, exc.pos - 100):exc.pos], blob[exc.pos:exc.pos + 40]
        return f"{exc.msg} at character {exc.pos}: ...{before}<<HERE>>{after}..."
    except ValueError as exc:
        return str(exc)[:200]
    return ""


def loads_model_json(text: str) -> Any:
    """``json.loads`` of a reply whose path separators are repaired, retried once with invalid
    escapes repaired when that is the error."""
    text = repair_path_escapes(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        if "escape" not in str(exc):
            raise
    return json.loads(repair_invalid_escapes(text))
