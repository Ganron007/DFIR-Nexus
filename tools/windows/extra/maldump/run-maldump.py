"""maldump lane wrapper (WO-TA item 5).

Runs maldump 0.5.0 (pip `maldump==0.5.0`) as `python -m maldump`, with the same
arguments. maldump checks `IsUserAnAdmin()` and exits without reading the
quarantine when the session is not elevated. This wrapper reports that as a
failure (exit 2) rather than an empty success, so the lane never records an
unread quarantine as clear.

    run-maldump.py <root_dir> -m -d <output directory>

Output: `quarantine.csv` (metadata) in the output directory. Quarantined samples
are not extracted here (`-q`); extracting samples is an examiner decision.
"""
from __future__ import annotations

import ctypes
import runpy
import sys


def _is_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def main(argv: list[str]) -> int:
    if not _is_admin():
        print("maldump needs an elevated (Administrator) session; quarantine not read.",
              file=sys.stderr)
        return 2
    sys.argv = ["maldump", *argv]
    try:
        runpy.run_module("maldump", run_name="__main__", alter_sys=True)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else (0 if code is None else 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
