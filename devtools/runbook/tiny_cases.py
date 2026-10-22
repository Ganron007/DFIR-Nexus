"""Create the tiny cases (TIER1-WORK-ORDERS Part 11, TP2): one case per staged tiny case, its evidence registered,
the operator's standard question as its only intake, and its case id written back to the public manifest.

    python devtools/runbook/tiny_cases.py [--only T01,T02] [--dry-run]

A case that already has a case_id in the manifest is left alone. Each top-level entry of the case's staged folder is
registered as one evidence item (the ``C`` folder of a drive-tree case, the ``capture``/``logs`` folders of a loose
one). Nothing else is set: the intake holds only what the examiner sets (rule 10.1).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "Docs" / "internal" / "eval" / "tiny-cases.yaml"
QUESTION = "Compromise suspected."


def nexus(*args: str) -> str:
    proc = subprocess.run([sys.executable, "-m", "nexus", *args], cwd=REPO, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise SystemExit(f"nexus {' '.join(args)} failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", default="")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    for tid, entry in manifest["cases"].items():
        if (only and tid not in only) or entry.get("case_id"):
            continue
        folder = Path(entry["folder"])
        items = sorted(folder.iterdir())
        if args.dry_run:
            print(f"{tid}: would create 'Tiny {tid}' and register {[p.name for p in items]}")
            continue
        out = nexus("case", "init", f"Tiny {tid}")
        m = re.search(r"\(ID: (CASE-[A-Za-z0-9-]+)\)", out)
        if not m:
            raise SystemExit(f"{tid}: no case id in: {out}")
        cid = m.group(1)
        for item in items:
            nexus("evidence", "register", str(item), "--case", cid)
        nexus("case", "intake", "--case", cid, "--question", QUESTION, "--set-by", "agent")
        entry["case_id"] = cid
        MANIFEST.write_text(yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True), encoding="utf-8",
                            newline="\n")
        print(f"{tid}: {cid}, {len(items)} evidence items registered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
