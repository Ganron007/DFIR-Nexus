"""WMI-Parser lane wrapper (WO-TA item 5).

Runs WMI-Parser v0.0.3 (AndrewRathbun/WMI-Parser, `Wmi-Parser.exe` beside this
file) on a WMI repository file, `OBJECTS.DATA`.

WMI-Parser targets .NET 6. This host has .NET 9 and 10 but not 6. The .NET host
can run an app on a newer installed major version when `DOTNET_ROLL_FORWARD=Major`
is set. This wrapper sets it for the child process only, so no machine setting
changes and no binary is edited.

    run-wmi-parser.py -i <OBJECTS.DATA> -o <output directory>

Output: `wmi-parser.tsv` in the output directory, and the same rows as
`wmi-parser.csv`. The case indexer reads .csv (not .tsv), so the CSV copy is what
reaches the index; the TSV is kept as the tool wrote it. The exit code of the
parser is passed through, so a failed parse stays a failed job.
"""
from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path


def _output_dir(argv: list[str]) -> Path | None:
    for flag in ("-o", "--output"):
        if flag in argv:
            idx = argv.index(flag)
            if idx + 1 < len(argv):
                return Path(argv[idx + 1])
    return None


def main(argv: list[str]) -> int:
    exe = Path(__file__).resolve().parent / "Wmi-Parser.exe"
    if not exe.is_file():
        print(f"Wmi-Parser.exe not found beside {Path(__file__).name}", file=sys.stderr)
        return 2
    env = dict(os.environ)
    env["DOTNET_ROLL_FORWARD"] = "Major"
    proc = subprocess.run([str(exe), *argv], env=env, check=False)
    out = _output_dir(argv)
    tsv = out / "wmi-parser.tsv" if out else None
    if proc.returncode == 0 and tsv is not None and tsv.is_file():
        with tsv.open(encoding="utf-8", errors="replace", newline="") as src, \
                (out / "wmi-parser.csv").open("w", encoding="utf-8", newline="") as dst:
            writer = csv.writer(dst)
            for row in csv.reader(src, delimiter="\t"):
                writer.writerow(row)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
