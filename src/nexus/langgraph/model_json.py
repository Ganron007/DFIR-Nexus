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


def loads_model_json(text: str) -> Any:
    """``json.loads``, retried once with invalid escapes repaired when that is the error."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        if "escape" not in str(exc):
            raise
    return json.loads(repair_invalid_escapes(text))
