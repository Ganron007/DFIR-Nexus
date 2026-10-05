"""WO-KR2b (design time, one-off): pin the analytics' authored queries.

The behavioural analytics were authored in Mode 1 query syntax (`dsl:`). KR2
converted them and then deleted the `dsl:` keys. Its converter was **not
idempotent**: it read `dsl`, wrote `es`, and deleted `dsl`, so a second run read an
empty `dsl`, compiled `match_all`, and overwrote the correct query. **26 of the 36
analytics now match every row in a case** - a stored query that asserts nothing,
which is the KR2b defect class.

The authored `dsl:` survives in git. This script recovers it into a pinned
design-time source (`analytics_source.yaml`) so the conversion is reproducible
without depending on git history, and so a reviewer can read what each analytic
was authored to say.

Source commit: the revision **before** KR2 deleted the keys (`81c0cc1^`).

Usage::

    python devtools/knowledge/pin_analytics_source.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
TARGET = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "behavioral_analytics.yaml"
OUT = Path(__file__).resolve().parent / "analytics_source.yaml"
#: The revision before KR2 removed `dsl:` from the analytics.
SOURCE_REV = "81c0cc1^"

HEADER = """\
# WO-KR2b - the behavioural analytics' AUTHORED queries, pinned.
#
# Recovered from the revision before KR2 deleted the `dsl:` keys, so the stored
# `es:` can be regenerated reproducibly and a reviewer can read what each analytic
# was authored to say. Design time only: nothing in src/nexus reads this file.
#
# Regenerate with: python devtools/knowledge/pin_analytics_source.py
"""


def main() -> int:
    rel = TARGET.relative_to(REPO).as_posix()
    proc = subprocess.run(
        ["git", "show", f"{SOURCE_REV}:{rel}"],
        cwd=str(REPO), capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        print(f"git show failed: {proc.stderr.strip()}", file=sys.stderr)
        return 2
    before = yaml.safe_load(proc.stdout) or {}
    authored: dict[str, str] = {}
    for pack in before.get("packs") or []:
        ident = str(pack.get("id") or "").strip()
        dsl = str(pack.get("dsl") or "").strip()
        if ident and dsl:
            authored[ident] = dsl

    # Keep the analytics that exist now, so a removed one is visible as missing.
    current = yaml.safe_load(TARGET.read_text(encoding="utf-8")) or {}
    ids = [str(a.get("id")) for a in (current.get("packs") or []) if a.get("id")]

    body = {"source_rev": SOURCE_REV, "source_path": rel, "queries": {}}
    missing: list[str] = []
    for ident in ids:
        if ident in authored:
            body["queries"][ident] = authored[ident]
        else:
            missing.append(ident)

    OUT.write_text(
        HEADER + yaml.safe_dump(body, sort_keys=False, allow_unicode=True, width=1000),
        encoding="utf-8",
    )
    print(f"pinned {len(body['queries'])} authored queries -> {OUT.name}")
    if missing:
        print(f"no authored query for {len(missing)} analytic(s): {missing}")
        print("  (these were authored directly as `es:`; the converter keeps them)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
