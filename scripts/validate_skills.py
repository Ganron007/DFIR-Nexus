"""Validate the skill layer against known-answer cases (WP 9.6).

Usage:
    python scripts\\validate_skills.py --case <casedir> --key <answer_key.yaml> [--json]
    python scripts\\validate_skills.py --corpus <dir> [--json]

`--corpus` runs every immediate subdirectory that contains an
`answer_key.yaml` and aggregates recall/precision across cases.

Answer key:
    case: my-case
    expected:
      families: [hayabusa, evtx]
      techniques: [T1003.001]
      artifacts: ["lsass.dmp"]
      entities: [{type: ipv4, value: "10.0.0.5"}]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def _print_report(rep: dict) -> None:
    print(f"case: {rep['case']}  recall={rep['recall']:.2f} precision={rep['precision']:.2f} "
          f"f1={rep['f1']:.2f}  (needles={rep['needles_searched']}, hits={rep['hits']})")
    for d in rep["dimensions"]:
        if not d["expected"]:
            continue
        print(f"  {d['dimension']:<11} r={d['recall']:.2f} p={d['precision']:.2f} "
              f"missing={d['missing'] or '-'} extra={d['extra'] or '-'}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--case", default=None, help="case directory")
    ap.add_argument("--key", default=None, help="answer_key.yaml (default <case>/answer_key.yaml)")
    ap.add_argument("--corpus", default=None, help="dir of case subdirs each with answer_key.yaml")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    from nexus.validation.harness import run_validation

    reports: list[dict] = []
    if args.corpus:
        root = Path(args.corpus)
        for case_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            key = case_dir / "answer_key.yaml"
            if key.is_file():
                reports.append(run_validation(case_dir, key))
    elif args.case:
        case_dir = Path(args.case)
        key = Path(args.key) if args.key else case_dir / "answer_key.yaml"
        reports.append(run_validation(case_dir, key))
    else:
        print("provide --case or --corpus", file=sys.stderr)
        return 2

    if not reports:
        print("no cases with an answer_key.yaml found", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))
        return 0

    for rep in reports:
        _print_report(rep)
    if len(reports) > 1:
        n = len(reports)
        print(f"\naggregate: recall={sum(r['recall'] for r in reports)/n:.2f} "
              f"precision={sum(r['precision'] for r in reports)/n:.2f} "
              f"f1={sum(r['f1'] for r in reports)/n:.2f} across {n} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
