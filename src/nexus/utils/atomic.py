"""Replacing a file or folder in one step: the one definition every writer uses (D485, 2026-10-29).

`os.replace` is atomic, but Windows refuses it (WinError 5, access denied; 32, sharing violation) while another
process holds the destination or the source open without delete sharing, and real-time antivirus opens every file
just written to scan it. Measured on the operator's host with Defender's on-access scan on: 12 of 3,000
back-to-back replaces of one file failed this way with no other writer in the process, and every hold cleared
within 11 ms (`scratch/agent/replace_race.py`, `replace_retry.py`). Before this, each of 35 writers called
`os.replace` itself: an approval's mirror write failed after its record was committed, so every later approval
of that case was refused as tampering (`tests/test_case_locks.py`), and a Mode 3 seat failed on its egress token
file (D293), the one writer that already retried.

A `PermissionError` is retried with growing waits, about 1.6 s in all, and the last one is raised: a holder that
does not let go is still a failure the caller sees. Windows reports another process's hold as a `PermissionError`;
on POSIX the same error is a real permission problem and costs only the bounded wait before it is raised. pip
replaces its files the same way (`pip/_internal/utils/filesystem.py`, `replace`, 1 s).
"""
from __future__ import annotations

import os
import time
from pathlib import Path

#: The waits between attempts, in seconds: nine attempts over about 1.6 s.
REPLACE_WAITS = (0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.4, 0.8)


def replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> Path:
    """Move *src* onto *dst* in one step (replacing a file there), riding out another process's brief hold."""
    for wait in REPLACE_WAITS:
        try:
            os.replace(src, dst)
            return Path(dst)
        except PermissionError:
            time.sleep(wait)
    os.replace(src, dst)
    return Path(dst)
