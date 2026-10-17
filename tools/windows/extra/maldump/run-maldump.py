"""maldump lane wrapper (WO-TA item 5).

Runs maldump 0.5.0 (pip `maldump==0.5.0`) as `python -m maldump`, with the same
arguments. maldump checks `IsUserAnAdmin()` and exits without reading the
quarantine when the session is not elevated. This wrapper reports that as a
failure (exit 2) rather than an empty success, so the lane never records an
unread quarantine as clear.

    run-maldump.py <root_dir> -m -d <output directory>

Output: `quarantine.csv` (metadata) in the output directory. Quarantined samples
are not extracted here (`-q`); extracting samples is an examiner decision.

maldump turns each quarantine time into the local time of the host that runs it
(`datetime.fromtimestamp`, parsers/windef_parser.py:37) and writes it with no
offset, so on a lane host at +05:30 Defender's 00:41:57Z quarantine read 06:11:57
and was indexed as UTC (D259). maldump therefore runs in its own process whose
zone is UTC (`TZ=UTC0`, read by the Windows C runtime and by POSIX alike), and
`quarantine.csv` holds UTC. The zone has to be set before that process starts:
the C runtime reads it once.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys


def _is_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def utc_env() -> dict[str, str]:
    """This environment, in UTC: the one maldump runs in."""
    return {**os.environ, "TZ": "UTC0"}


def main(argv: list[str]) -> int:
    if not _is_admin():
        print("maldump needs an elevated (Administrator) session; quarantine not read.",
              file=sys.stderr)
        return 2
    return subprocess.run([sys.executable, "-m", "maldump", *argv], env=utc_env()).returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
