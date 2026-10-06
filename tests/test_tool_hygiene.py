"""The audit tools' hygiene checker must be able to FAIL.

Workbook defect class: a check that passes for reasons unrelated to what it claims. Five
were found by inspection in this work order; this file pins the tool built to catch the
next one, and proves it can fail - because a checker that cannot fail is itself the
defect, which is how this very tool passed its first self-test while returning 0 for a
file containing a bare `assert`.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TOOL = REPO / "devtools" / "knowledge" / "audit_tool_hygiene.py"

#: a truthiness test whose branch carries a diagnostic
GOOD = '''"""a guard with a reason."""


def main() -> int:
    rows = []
    if not rows:
        print("no rows")
        return 1
    return 0
'''

#: a bare truthiness assertion: it cannot say WHICH fact failed
BAD = '''"""a bare truthiness assertion."""


def main() -> int:
    rows = []
    assert rows
    return 0
'''


def _run_tool_against(source: str) -> tuple[int, str]:
    """Run the hygiene tool with its TOOLS list pointed at a one-file source.

    The probe file is COPIED next to the patched tool rather than its path being
    injected into the source, because a Windows temp path contains backslashes that an
    injected string literal would treat as escapes.
    """
    original = TOOL.read_text(encoding="utf-8")
    patched = re.sub(r"TOOLS = \[.*?\]\n", 'TOOLS = ["_hygiene_probe.py"]\n',
                    original, count=1, flags=re.S)
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "_hygiene_probe.py"
        src.write_text(source, encoding="utf-8")
        tool = Path(tmp) / "tool.py"
        tool.write_text(patched, encoding="utf-8")
        r = subprocess.run([sys.executable, str(tool)], cwd=str(tmp),
                           capture_output=True, text=True)
    return r.returncode, (r.stdout or "")


def test_the_hygiene_tool_passes_a_guard_with_a_reason():
    rc, _ = _run_tool_against(GOOD)
    assert rc == 0, "a guard with a diagnostic should pass"


def test_the_hygiene_tool_fails_a_bare_truthiness_assertion():
    rc, _ = _run_tool_against(BAD)
    assert rc == 1, "a bare `assert x` must be reported - it names no fact"


def test_the_hygiene_tool_reports_zero_on_the_audit_tools():
    """Against the shipped tools: no bare truthiness assertion."""
    r = subprocess.run([sys.executable, str(TOOL)], cwd=str(REPO),
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-400:]
    assert "bare assertions (cannot say which fact failed): 0" in r.stdout
