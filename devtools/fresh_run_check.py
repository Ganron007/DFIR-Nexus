"""D230: does an independent run's traced prompt hold anything from earlier runs or reviews?

An `independent` run must see the evidence only. This reads the model-call trace of one run
(`devtools/trace_prompts.py` writes it) and looks for text that cannot come from the evidence: the
ids of findings already on the case, the ids of other runs, the titles those runs gave their
findings, and the lines of the examiner's review. Shared evidence text (a row both a finding and a
tool result quote) is not a marker, so overlap of evidence is never reported.

    python devtools/fresh_run_check.py --case CASE-ID --trace <model_calls-RUN.jsonl> --run-id RUN

Exit 0 when the prompts are clean, 1 when an earlier result reached them, 2 on bad input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_RUN_ID = re.compile(r"\b(?:M[123]-\d{8}T\d{6}-[0-9a-f]{6}|RUN-\d{8}T\d{6,}Z-[a-z]+-[0-9a-f]{8})\b")
_TITLE_WORDS = 5
_REVIEW_WORDS = 8


def _case_dir(case: str) -> Path:
    path = Path(case)
    if path.is_dir():
        return path
    from nexus.config import settings

    return Path(settings.cases_root) / case


def earlier_markers(case_dir: Path, run_id: str) -> dict[str, str]:
    """Text an independent run cannot have from the evidence, mapped to where it comes from."""
    markers: dict[str, str] = {}
    findings_file = case_dir / "findings.json"
    findings = json.loads(findings_file.read_text(encoding="utf-8")) if findings_file.is_file() else []
    for finding in findings:
        if not isinstance(finding, dict) or str(finding.get("run_id") or "") == run_id:
            continue
        fid = str(finding.get("id") or "")
        if fid:
            markers[fid] = f"finding id {fid}"
        title = " ".join(str(finding.get("title") or "").split())
        if len(title.split()) >= _TITLE_WORDS:
            markers[title.lower()] = f"title of {fid}"
        other_run = str(finding.get("run_id") or "")
        if other_run:
            markers[other_run] = f"run id {other_run}"
    for sub in ("mode2_runs", "mode3_runs"):
        for record in (case_dir / "analysis" / sub).glob("*.json"):
            if record.stem != run_id and _RUN_ID.fullmatch(record.stem):
                markers[record.stem] = f"run id {record.stem}"
    for run_dir in (case_dir / "runs").glob("RUN-*"):
        if run_dir.name != run_id and "interpret" in run_dir.name:
            markers[run_dir.name] = f"run id {run_dir.name}"
    review = case_dir / "analysis" / "examiner_review.md"
    if review.is_file():
        for line in review.read_text(encoding="utf-8").splitlines():
            text = " ".join(line.strip(" #*-|>").split())
            if len(text.split()) >= _REVIEW_WORDS:
                markers[text.lower()] = "examiner review"
    return markers


def scan(trace: Path, markers: dict[str, str]) -> list[dict[str, object]]:
    """Every traced call whose messages hold a marker, with the markers found."""
    keyed = {marker.lower(): src for marker, src in markers.items()}
    hits: list[dict[str, object]] = []
    with trace.open(encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            # Whitespace normalised as the markers are, so a re-wrapped line still matches.
            low = " ".join(" ".join(str(m.get("content") or "") for m in record.get("messages") or []
                                    if isinstance(m, dict)).split()).lower()
            found = sorted({src for marker, src in keyed.items() if marker in low})
            if found:
                hits.append({"call": record.get("seq") or n, "markers": found})
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--case", required=True)
    parser.add_argument("--trace", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    case_dir, trace = _case_dir(args.case), Path(args.trace)
    if not case_dir.is_dir() or not trace.is_file():
        print(f"no case folder {case_dir} or no trace {trace}", file=sys.stderr)
        return 2
    markers = earlier_markers(case_dir, args.run_id)
    hits = scan(trace, markers)
    print(f"{args.run_id}: {len(markers)} earlier markers, {len(hits)} traced call(s) holding one")
    for hit in hits[:20]:
        print(f"  call {hit['call']}: {', '.join(map(str, hit['markers']))[:300]}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
