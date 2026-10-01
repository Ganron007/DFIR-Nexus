#!/usr/bin/env python
"""Accuracy scorer (WO-A1 / WP 10.3, D20 = B).

Read-only. It scores cases that already exist; producing them is GATE-H's job.
Nothing is ever written inside a case directory - the only writes are the two
internal report files, and the script refuses to run if either would land in a
case folder.

    python scripts/accuracy_run.py CASE-A CASE-B            # EVTX-to-MITRE key
    python scripts/accuracy_run.py --kind self-describing --evidence-root DIR CASE

Output: Docs/internal/accuracy.json + Docs/internal/ACCURACY.md. **Internal**
until GATE 10-A is signed - never Docs/ACCURACY.md.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from nexus.validation.answer_keys import (  # noqa: E402
    AnswerKey,
    evtx_to_mitre_key,
    self_describing_key,
)
from nexus.validation.harness import findings_dimension  # noqa: E402

DEFAULT_KEY_ROOT = (
    REPO
    / "Evidence-files"
    / "01-windows"
    / "evtx"
    / "yamato-hayabusa-sample-evtx"
    / "EVTX-to-MITRE-Attack"
)
DEFAULT_JSON = REPO / "Docs" / "internal" / "accuracy.json"
DEFAULT_MD = REPO / "Docs" / "internal" / "ACCURACY.md"
MODES = (1, 2, 3)


def _cases_root() -> Path:
    try:
        from nexus.config import settings

        return Path(settings.cases_root)
    except Exception:  # noqa: BLE001 - a scorer must not die on config
        return REPO / "cases"


def resolve_case(case_id: str, cases_root: Path) -> Path | None:
    """Find a case directory by id, one level of nesting at most."""
    direct = cases_root / case_id
    if direct.is_dir():
        return direct
    for parent in sorted(p for p in cases_root.iterdir() if p.is_dir()):
        nested = parent / case_id
        if nested.is_dir():
            return nested
    return None


def _git_head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def score_cases(key: AnswerKey, cases: list[tuple[str, Path]], dimension: str) -> dict:
    """Per-case and per-mode dimensions, plus the mode roll-up."""
    per_case = []
    by_mode: dict[str, dict] = {}
    for case_id, case_dir in cases:
        modes_present: list[int] = []
        rows = {}
        for mode in MODES:
            scored = findings_dimension(case_dir, key, dimension=dimension, mode=mode)
            if scored["findings_scored"]:
                modes_present.append(mode)
            rows[f"mode{mode}"] = scored
        rows["all"] = findings_dimension(case_dir, key, dimension=dimension, mode="all")
        per_case.append(
            {
                "case_id": case_id,
                "case_dir": str(case_dir),
                "modes_present": modes_present,
                "dimensions": rows,
            }
        )
        for mode in MODES:
            if mode not in modes_present:
                continue
            bucket = by_mode.setdefault(
                f"mode{mode}",
                {"expected": set(), "found": set(), "cases": 0, "findings": 0},
            )
            scored = rows[f"mode{mode}"]
            bucket["expected"] |= set(scored["expected"])
            bucket["found"] |= set(scored["found"])
            bucket["cases"] += 1
            bucket["findings"] += int(scored["findings_scored"])

    rollup = {}
    for name, bucket in by_mode.items():
        expected, found = bucket["expected"], bucket["found"]
        hit = expected & found
        recall = len(hit) / len(expected) if expected else 1.0
        precision = len(hit) / len(found) if found else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        rollup[name] = {
            "cases": bucket["cases"],
            "findings_scored": bucket["findings"],
            "expected": sorted(expected),
            "found": sorted(found),
            "true_positives": sorted(hit),
            "missed": sorted(expected - found),
            "extra": sorted(found - expected),
            "recall": round(recall, 4),
            "precision": round(precision, 4),
            "f1": round(f1, 4),
        }
    return {"dimension": dimension, "per_case": per_case, "by_mode": rollup}


def render_markdown(report: dict) -> str:
    key: dict = report["answer_key"]
    lines = [
        "# Accuracy - what the modes actually found",
        "",
        "> **Internal.** D20 = B: these numbers stay in `Docs/internal/` until "
        "GATE 10-A is signed. They are a measurement of cases that already "
        "exist, not a claim about the product.",
        "",
        f"- Generated: {report['generated_at']}",
        f"- HEAD: `{report['head']}`",
        f"- Dimension: `{report['dimension']}`",
        f"- Key: `{key['kind']}` at `{key['root']}`",
        f"- Key contents: {key['counts']['entries']} scorable item(s), "
        f"{key['counts']['techniques']} technique label(s), "
        f"{key['counts']['entities']} entit(ies), "
        f"**{key['counts']['excluded']} excluded**",
        f"- Cases scored: {len(report['per_case'])}",
        "",
        "## Method",
        "",
        "1. The key is built from evidence (see `nexus.validation.answer_keys`).",
        "2. For each case, each finding staged (DRAFT or APPROVED) is attributed",
        "   to its producing mode - the finding's own `provenance.mode` when it",
        "   has one, otherwise the case's stored mode.",
        "3. Precision = found ∩ expected / found. Recall = found ∩ expected /",
        "   expected. F1 is their harmonic mean. Sub-techniques stay distinct",
        "   from their parents.",
        "4. Nothing is written into a case directory; the scorer reads only.",
        "",
        "## Per mode",
        "",
        "| Mode | Cases | Findings | Expected | Recall | Precision | F1 |",
        "|---|---|---|---|---|---|---|",
    ]
    for name in sorted(report["by_mode"]):
        row = report["by_mode"][name]
        lines.append(
            f"| {name} | {row['cases']} | {row['findings_scored']} | "
            f"{len(row['expected'])} | {_pct(row['recall'])} | "
            f"{_pct(row['precision'])} | {_pct(row['f1'])} |"
        )
    if not report["by_mode"]:
        lines.append("| - | 0 | 0 | 0 | - | - | - |")

    lines += ["", "## Missed and extra", ""]
    for name in sorted(report["by_mode"]):
        row = report["by_mode"][name]
        lines.append(f"### {name}")
        lines.append("")
        lines.append(f"- missed: {', '.join(row['missed']) or 'none'}")
        lines.append(f"- extra: {', '.join(row['extra']) or 'none'}")
        lines.append("")

    lines += ["## Key exclusions (reported, never dropped)", ""]
    if key["excluded"]:
        lines += ["| File | Reason |", "|---|---|"]
        for item in key["excluded"][:50]:
            lines.append(f"| `{item['file']}` | {item['reason']} |")
        if len(key["excluded"]) > 50:
            lines.append(f"| … {len(key['excluded']) - 50} more | see accuracy.json |")
    else:
        lines.append("None - every file in the key was scored.")
    lines += ["", "## Cases", ""]
    for case in report["per_case"]:
        lines.append(
            f"- `{case['case_id']}` — modes staged: "
            f"{', '.join(str(m) for m in case['modes_present']) or 'none'}"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_ids", nargs="+", help="case ids to score")
    parser.add_argument(
        "--kind",
        choices=("evtx-to-mitre", "self-describing"),
        default="evtx-to-mitre",
    )
    parser.add_argument("--key-root", default=str(DEFAULT_KEY_ROOT))
    parser.add_argument(
        "--evidence-root", default=str(DEFAULT_KEY_ROOT.parent),
        help="evidence root for --kind self-describing",
    )
    parser.add_argument("--dimension", default="techniques", choices=("techniques", "entities"))
    parser.add_argument("--cases-root", default=None)
    parser.add_argument("--json-out", default=str(DEFAULT_JSON))
    parser.add_argument("--md-out", default=str(DEFAULT_MD))
    args = parser.parse_args(argv)

    if args.kind == "evtx-to-mitre":
        key = evtx_to_mitre_key(args.key_root)
    else:
        key = self_describing_key(args.evidence_root)

    cases_root = Path(args.cases_root) if args.cases_root else _cases_root()
    cases: list[tuple[str, Path]] = []
    missing: list[str] = []
    for case_id in args.case_ids:
        case_dir = resolve_case(case_id, cases_root)
        if case_dir is None:
            missing.append(case_id)
        else:
            cases.append((case_id, case_dir))
    if missing:
        print(f"case(s) not found under {cases_root}: {', '.join(missing)}", file=sys.stderr)

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "head": _git_head(),
        "dimension": args.dimension,
        "answer_key": key.to_dict(),
        "cases_root": str(cases_root),
        "missing_cases": missing,
    }
    report.update(score_cases(key, cases, args.dimension))

    json_out, md_out = Path(args.json_out), Path(args.md_out)
    # read-only promise, enforced: never write inside a case directory
    for out in (json_out, md_out):
        for _case_id, case_dir in cases:
            if case_dir in out.parents or out == case_dir:
                print(
                    f"refusing to write {out}: it is inside case directory {case_dir}",
                    file=sys.stderr,
                )
                return 2
    json_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    md_out.write_text(render_markdown(report), encoding="utf-8")

    print(f"key: {key.kind} — {len(key.entries)} item(s), {len(key.excluded)} excluded")
    if not report["by_mode"]:
        print("no case produced a scorable finding for this dimension")
    for name in sorted(report["by_mode"]):
        row = report["by_mode"][name]
        print(
            f"{name}: recall {row['recall']:.3f} precision {row['precision']:.3f} "
            f"f1 {row['f1']:.3f} "
            f"(cases {row['cases']}, findings {row['findings_scored']}, "
            f"expected {len(row['expected'])}, missed {len(row['missed'])})"
        )
    print(f"wrote {json_out.relative_to(REPO)} and {md_out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())