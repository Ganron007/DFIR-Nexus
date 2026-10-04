"""Distill a KB selection into a schema-valid, cited skill DRAFT (WP 9.2, design-time).

Examples:
    python devtools/knowledge/distill_skill.py --folder "DFIR-Report" --name dfir_intrusion_flow
    python devtools/knowledge/distill_skill.py --folder "13Cubed" --llm --out Docs/internal/skill-drafts
    python devtools/knowledge/distill_skill.py --from-yaml draft.yaml --install   # promote after review

Exit 0 when the draft passes every gate, 1 otherwise. Drafts are written to a
review dir by default; --install writes to the shipped skills dir (needs gates
to pass; add --force to overwrite).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "src"))


def main() -> int:
    ap = argparse.ArgumentParser(prog="distill_skill", description=__doc__)
    ap.add_argument("--folder", default=None, help="KB folder/category to distill")
    ap.add_argument("--from-yaml", default=None, help="use an existing skill draft instead")
    ap.add_argument("--name", default=None, help="output skill id (default: draft id)")
    ap.add_argument("--out", default=None, help="review dir (default Docs/internal/skill-drafts)")
    ap.add_argument("--llm", action="store_true", help="use the configured LLM to refine")
    ap.add_argument("--install", action="store_true", help="write into the shipped skills dir if gates pass")
    ap.add_argument("--force", action="store_true", help="overwrite an existing shipped skill")
    ap.add_argument("--kb", default=None, help="path to kb.py (default G:\\doc_extract\\kb\\kb.py)")
    args = ap.parse_args()

    from devtools.knowledge.distill import distill

    try:
        report = distill(
            folder=args.folder,
            from_yaml=args.from_yaml,
            name=args.name,
            out_dir=args.out,
            use_llm=args.llm,
            kb_py=args.kb,
            install=args.install,
            force=args.force,
        )
        print(json.dumps(report, indent=2))
        return 0 if not report["gate"] else 1
    except Exception as exc:  # noqa: BLE001
        print(f"distill failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
