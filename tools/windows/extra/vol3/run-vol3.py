"""Volatility 3 lane wrapper (WO-TA item 6; operator decision 2026-10-11: run on Windows, not SIFT).

Runs the pinned volatility3 2.28.0 wheel (PyPI, sha256 68ea2257d25d2ab6160bb29203ce9bf3e91a8a852a420cb819ebb4c4115eaa68,
licence VSL 1.0) from its own venv, Tools/windows/memory/vol3-2.28.0-venv. Every argument is passed to the
``vol`` entry point unchanged, so the lane's argv (``-f <image> -r jsonl <plugin>``) means what it means on the
SIFT host. The memory image is read in place. The wrapper's own environment is not the venv's: PYTHONPATH,
which the lane's executor sets to this folder, is removed for the child so only the venv's packages load.
Exit status is the status of ``vol``.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

VENV_VOL = Path(__file__).resolve().parents[2] / "memory" / "vol3-2.28.0-venv" / "Scripts" / "vol.exe"


def main() -> int:
    if not VENV_VOL.is_file():
        print(f"vol3: the pinned venv is missing ({VENV_VOL}); see Tools/windows/memory/vol3-2.28.0-requirements.txt",
              file=sys.stderr)
        return 3
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return subprocess.call([str(VENV_VOL), *sys.argv[1:]], env=env)


if __name__ == "__main__":
    raise SystemExit(main())
