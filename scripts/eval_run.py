#!/usr/bin/env python
"""WO-K1 — the K1 runner and scorer (WP 15.1 + 15.11).

Creates one case per mode on the same evidence (sibling cases, D5 = A),
registers the evidence, runs the lane and the mode with **no examiner input
beyond a neutral question**, and scores the run against the operator's manifest.

    python scripts/eval_run.py --set-dir DIR --manifest PATH --modes 1,2,3
    python scripts/eval_run.py --score-only --manifest PATH --cases ID1,ID2

Metrics per mode:

* techniques — precision, recall, F1
* entities   — precision, recall, F1
* **false-positive rate** — DRAFTs whose cited rows come only from benign files
* **time to the first true lead**, from the finding timestamps
* wall time, and model tokens when the run record carries them

Three WO-K1 rules are enforced structurally, not by intention:

1. **The manifest is read only here.** It is never passed to a prompt, a tool, a
   child process argument or the child environment; `leak_guard()` then scans the
   case for its path and the run fails if it appears.
2. **Nothing upstream of the case.** `discover_evidence` refuses to register the
   labelling directories — a `labels/` folder inside the case is the answer
   key walking into the evidence.
3. **`--score-only` never runs a mode**, so re-scoring cannot perturb a result.

Results are written to ``Docs/internal/ACCURACY.md`` (§ "K-runs") and
``Docs/internal/accuracy.json``; ``--label`` names the run (K-run 0 = baseline).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from nexus.validation.answer_keys import AnswerKey  # noqa: E402
from nexus.validation.harness import (  # noqa: E402
    case_findings,
    findings_dimension,
)

NEUTRAL_QUESTION = "Investigate this host for compromise"
MODES = (1, 2, 3)
DEFAULT_JSON = REPO / "Docs" / "internal" / "accuracy.json"
DEFAULT_MD = REPO / "Docs" / "internal" / "ACCURACY.md"
FINDING_STATUSES = ("DRAFT", "APPROVED")

#: Directory names that hold ground truth. Never registered into a case: the
#: labels are the answer, and the case is what the model reads.
TRUTH_DIRS = frozenset({
    "label", "labels", "ground-truth", "ground_truth", "groundtruth",
    "truth", "answer_keys", "answer-keys", "attacks",  # AIT-LDS: attacks.log
})
#: AIT-LDS names its attacker log directory this way; it names the schedule.
TRUTH_FILES = frozenset({
    "attacks.log",
    # The manifest and the step->technique table are the answer. If the stage
    # root (rather than its evidence/ child) is ever handed to --set-dir, these
    # would otherwise be registered into the case and become readable.
    "manifest.json",
    "mapping.json",
    "stage_events.json",
})


# ---------------------------------------------------------------------------
# paths / discovery
# ---------------------------------------------------------------------------

def cases_root() -> Path:
    try:
        from nexus.config import settings

        return Path(settings.cases_root)
    except Exception:  # noqa: BLE001 — a scorer must not die on config
        return REPO / "cases"


def discover_evidence(set_dir: Path) -> tuple[list[Path], list[Path]]:
    """``(evidence files, skipped truth files)`` under *set_dir*.

    Truth directories and files are skipped **and reported** rather than quietly
    dropped: registering them would put the answer inside the case.
    """
    evidence: list[Path] = []
    skipped: list[Path] = []
    for path in sorted(p for p in set_dir.rglob("*") if p.is_file()):
        parts = {part.lower() for part in path.relative_to(set_dir).parts[:-1]}
        if parts & TRUTH_DIRS or path.name.lower() in TRUTH_FILES:
            skipped.append(path)
            continue
        evidence.append(path)
    return evidence, skipped


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# the leak guard
# ---------------------------------------------------------------------------

def leak_guard(case_dir: Path, manifest_path: Path) -> list[str]:
    """Occurrences of the manifest path inside the case. Non-empty = fail.

    Scans what a run persists — the packed prompts (``analysis/llm_context/``),
    the audit log, the run records and the staged findings — because those are
    exactly the surfaces a prompt or tool call would leave the path in.
    """
    needles = {str(manifest_path), manifest_path.name}
    hits: list[str] = []
    for path in case_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".md", ".json", ".jsonl", ".txt", ".yaml", ".yml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for needle in needles:
            if needle and needle in text:
                hits.append(f"{path.relative_to(case_dir)} contains {needle!r}")
                break
    return hits


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------

def read_audit(case_dir: Path) -> dict[str, dict]:
    """``audit_id -> entry`` from every audit jsonl in the case."""
    out: dict[str, dict] = {}
    audit_dir = case_dir / "audit"
    if not audit_dir.is_dir():
        return out
    for path in sorted(audit_dir.glob("*.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                key = str(entry.get("audit_id") or "")
                if key:
                    out[key] = entry
    return out


def _finding_audit_ids(finding: dict) -> list[str]:
    ids: list[str] = []
    for key in ("audit_ids", "audit_id"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            ids.append(value.strip())
        elif isinstance(value, list):
            ids.extend(str(v).strip() for v in value if str(v).strip())
    for artifact in finding.get("artifacts") or []:
        if isinstance(artifact, dict):
            value = str(artifact.get("audit_id") or "").strip()
            if value:
                ids.append(value)
    return list(dict.fromkeys(ids))


def _cited_hashes(finding: dict, audit: dict[str, dict]) -> tuple[set[str], bool]:
    """``(hashes, resolved)`` for a finding's cited rows.

    ``resolved`` is False when any cited audit id is missing or carries no input
    hash — an unresolvable citation must not be read as "benign only".
    """
    hashes: set[str] = set()
    resolved = False
    for audit_id in _finding_audit_ids(finding):
        entry = audit.get(audit_id)
        if entry is None:
            return set(), False
        got = entry.get("input_sha256s") or []
        if not isinstance(got, list):
            return set(), False
        clean = {str(h).strip().lower() for h in got if str(h).strip()}
        if not clean:
            return set(), False
        hashes |= clean
        resolved = True
    return hashes, resolved


def _finding_ts(finding: dict) -> str:
    for key in ("staged_at", "created_at", "approved_at", "timestamp", "ts"):
        value = str(finding.get(key) or "").strip()
        if value:
            return value
    return ""


def false_positives(case_dir: Path, key: AnswerKey) -> dict:
    """DRAFTs whose cited rows come only from files the manifest marks benign."""
    benign = key.benign_hashes()
    findings = case_findings(case_dir)
    audit = read_audit(case_dir)
    drafts = [f for f in findings
              if str(f.get("status") or "DRAFT").upper() in FINDING_STATUSES]
    fp: list[str] = []
    unresolved = 0
    for finding in drafts:
        hashes, resolved = _cited_hashes(finding, audit)
        if not resolved:
            # No resolvable citation, or no input hash. Cannot attribute it to
            # benign evidence, so it is not counted as a false positive.
            unresolved += 1
            continue
        if benign and hashes and hashes <= benign:
            fp.append(str(finding.get("id") or finding.get("title") or "?"))
    total = len(drafts)
    return {
        "findings": total,
        "benign_only": len(fp),
        "benign_only_ids": fp,
        "unattributable": unresolved,
        "rate": round(len(fp) / total, 4) if total else 0.0,
        "benign_files_declared": len(benign),
    }


def score_case(case_dir: Path, key: AnswerKey, started_at: float | None = None) -> dict:
    """Every per-mode metric for one case."""
    scoped = key.restrict_to(case_dir)
    dimensions = {
        name: findings_dimension(case_dir, scoped, dimension=name)
        for name in ("techniques", "entities")
    }

    expectations = scoped.techniques()
    # A set with no expectation has no recall to report. The harness scores an
    # empty expectation as recall 1.0, which on a benign-only set would read as
    # a perfect result - the opposite of what it means. Say "not applicable".
    if not expectations:
        for dim in dimensions.values():
            dim["recall"] = None
            dim["recall_reason"] = "no expectation for this set (benign-only or unlabelled)"
    findings = [
        f for f in case_findings(case_dir)
        if str(f.get("status") or "DRAFT").upper() in FINDING_STATUSES
    ]
    true_leads: list[tuple[str, dict]] = []
    for finding in findings:
        got = {str(t).upper() for t in (finding.get("technique_ids") or [])}
        if got & expectations:
            true_leads.append((_finding_ts(finding), finding))
    true_leads = [pair for pair in true_leads if pair[0]]
    first_lead_s: float | None = None
    if true_leads and started_at is not None:
        earliest = min(ts for ts, _ in true_leads)
        try:
            when = datetime.fromisoformat(earliest.replace("Z", "+00:00"))
            first_lead_s = round(when.timestamp() - started_at, 1)
        except ValueError:
            first_lead_s = None

    return {
        "case_id": case_dir.name,
        "case_dir": str(case_dir),
        "findings": len(findings),
        "findings_scored": dimensions["techniques"].get("findings_scored", 0),
        "dimensions": dimensions,
        "false_positive": false_positives(case_dir, scoped),
        "true_leads": len(true_leads),
        "time_to_first_true_lead_s": first_lead_s,
        "key_scope": {
            "matched": scoped.matched,
            "unlabelled": len(scoped.unlabelled),
            "ignored": len(scoped.ignored),
            "expected_techniques": len(scoped.techniques()),
            "benign_declared": len(scoped.benign_hashes()),
        },
    }


# ---------------------------------------------------------------------------
# running a mode
# ---------------------------------------------------------------------------

def _run(cmd: list[str], *, timeout: int) -> tuple[int, str, float]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, cwd=str(REPO), capture_output=True, text=True, timeout=timeout,
        )
        rc, out = proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        rc, out = -9, f"timed out after {timeout}s"
    return rc, out[-4000:], round(time.monotonic() - started, 1)


def run_mode(mode: int, case_id: str, question: str, timeout: int) -> dict:
    """Run one mode on an existing case. No examiner input beyond *question*."""
    py = sys.executable
    if mode == 1:
        # Mode 1 = the LLM mode: lane + interpret -> DRAFTs.
        rc, out, secs = _run(
            [py, "-m", "nexus", "pipeline", "--from-case", case_id, "--mode", "coverage"],
            timeout=timeout,
        )
        return {"mode": 1, "rc": rc, "wall_s": secs, "tail": out}

    if mode == 2:
        rc, out, secs = _run(
            [py, "-m", "nexus", "mode2", "run", "-q", question, "--case", case_id],
            timeout=timeout,
        )
        staged = {"rc": None}
        if rc == 0:
            src, sout, ssecs = _run(
                [py, "-m", "nexus", "mode2", "stage", "--case", case_id],
                timeout=min(timeout, 900),
            )
            staged = {"rc": src, "wall_s": ssecs, "tail": sout}
        return {"mode": 2, "rc": rc, "wall_s": secs, "tail": out, "stage": staged}

    rc, out, secs = _run(
        [py, "-m", "nexus", "mode3", "run", "-q", question, "--case", case_id, "--json"],
        timeout=timeout,
    )
    staged = {"rc": None}
    if rc == 0:
        src, sout, ssecs = _run(
            [py, "-m", "nexus", "mode3", "stage", "--case", case_id],
            timeout=min(timeout, 900),
        )
        staged = {"rc": src, "wall_s": ssecs, "tail": sout}
    return {"mode": 3, "rc": rc, "wall_s": secs, "tail": out, "stage": staged}


# ---------------------------------------------------------------------------
# the run record
# ---------------------------------------------------------------------------

def _git_head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(REPO),
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _knowledge_versions() -> dict:
    """The knowledge layer versions the run used, so a K-run is reproducible."""
    out: dict = {}
    try:
        from nexus.knowledge.loader import get_skills
        from nexus.knowledge.skills import skill_version

        out["skills"] = {
            str(s.get("skill")): skill_version(s) for s in get_skills() if s.get("skill")
        }
    except Exception as exc:  # noqa: BLE001
        out["skills_error"] = str(exc)[:200]
    for name, rel in (
        ("needles_sigma", "src/nexus/data/knowledge/needles/sigma_needles.yaml"),
        ("needles_evtx", "src/nexus/data/knowledge/needles/evtx_attack_samples.yaml"),
        ("attack_needles", "src/nexus/data/knowledge/attack/attack_needles.yaml"),
    ):
        path = REPO / rel
        if path.is_file():
            out[f"{name}_sha256"] = sha256_file(path)[:16]
    return out


K_RUN_LEGEND = (
    "False-positive = DRAFTs whose cited rows resolve **only** to files the "
    "manifest marks `role: benign`. A finding whose citations cannot be "
    "resolved to input hashes is *not* counted as benign-only (it would "
    "otherwise read as a clean run). Recall is `n/a` on a set with no "
    "expectation, because an empty expectation scores as recall 1.0."
)


def _render_run_md(report: dict) -> str:
    """One K-run as a `### <label>` block (no `## K-runs` header - the caller owns that)."""
    lines = [
        f"### {report['label']}",
        "",
        f"- When: {report['at']}",
        f"- HEAD: `{report['head']}`",
        f"- Question: {report['question']!r} (the only examiner input)",
        f"- Manifest: `{report['manifest']}` (read only by the scorer)",
        f"- Evidence files: {len(report['evidence'])} registered; "
        f"{len(report['truth_skipped'])} truth file(s) skipped",
        "",
    ]
    if report["truth_leak_checks"]:
        lines.append("- manifest-leak guard:")
        for check in report["truth_leak_checks"]:
            state = "CLEAN" if not check["hits"] else f"LEAK - {check['hits'][:3]}"
            lines.append(f"  - `{check['case_id']}`: {state}")
        lines.append("")
    lines += [
        "| Mode | rc | Findings | Techniques P | R | F1 | Entities F1 | "
        "Benign-only FP | First true lead | Wall s |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for case in report["cases"]:
        tech = case.get("dimensions", {}).get("techniques", {})
        ent = case.get("dimensions", {}).get("entities", {})
        fp = case.get("false_positive", {})
        lead = case.get("time_to_first_true_lead_s")
        lead_txt = "n/a" if lead is None else f"{lead}s"

        def _num(value: str | float | None) -> str:
            return "n/a" if value is None else format(value, ".3f")

        lines.append(
            f"| {case['mode']} | {case['run'].get('rc')} | {case.get('findings', 0)} | "
            f"{_num(tech.get('precision'))} | {_num(tech.get('recall'))} | "
            f"{_num(tech.get('f1'))} | {_num(ent.get('f1'))} | "
            f"{fp.get('benign_only', 0)}/{fp.get('findings', 0)} | "
            f"{lead_txt} | {case['run'].get('wall_s')} |"
        )
    lines.append("")
    return "\n".join(lines)


def _k_runs_section(runs: list[dict]) -> str:
    """The whole `## K-runs` section, regenerated from every run record.

    Regenerated rather than appended-to: K1 re-runs the baseline after each of
    K2-K7, so appending would eventually duplicate the legend and replacing the
    header alone would silently erase the earlier runs.
    """
    body = "\n".join(_render_run_md(run) for run in runs)
    return f"## K-runs\n\n{K_RUN_LEGEND}\n\n{body}\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set-dir", default="", help="evidence directory for K1")
    parser.add_argument("--manifest", required=True, help="operator manifest (read only here)")
    parser.add_argument("--modes", default="1,2,3")
    parser.add_argument("--label", default="", help="K-run name, e.g. 'K-run 0 baseline'")
    parser.add_argument("--question", default=NEUTRAL_QUESTION)
    parser.add_argument("--cases", default="", help="--score-only: case ids to score")
    parser.add_argument("--score-only", action="store_true")
    parser.add_argument("--no-run", action="store_true", help="create + register only")
    parser.add_argument("--timeout", type=int, default=5400, help="per-mode seconds")
    parser.add_argument("--json-out", default=str(DEFAULT_JSON))
    parser.add_argument("--md-out", default=str(DEFAULT_MD))
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        print(f"manifest not found: {manifest_path}", file=sys.stderr)
        return 2
    key = AnswerKey.from_manifest(manifest_path)  # the ONLY reader of the manifest

    modes = [int(m) for m in args.modes.split(",") if m.strip()]
    report: dict = {
        "label": args.label or datetime.now(UTC).strftime("K-run %Y-%m-%dT%H:%MZ"),
        "at": datetime.now(UTC).isoformat(),
        "head": _git_head(),
        "question": args.question,
        "manifest": str(manifest_path),
        "knowledge": _knowledge_versions(),
        "cases": [],
        "evidence": [],
        "truth_skipped": [],
        "truth_leak_checks": [],
        "key_counts": key.to_dict()["counts"],
    }

    evidence: list[Path] = []
    if args.set_dir:
        evidence, skipped = discover_evidence(Path(args.set_dir))
        report["evidence"] = [str(p) for p in evidence]
        report["truth_skipped"] = [str(p) for p in skipped]
        print(f"evidence: {len(evidence)} file(s); skipped {len(skipped)} truth file(s)")
        if skipped:
            print("  (truth files are never registered - they are the answer)")

    if not args.score_only:
        if not evidence:
            print("--set-dir is required unless --score-only", file=sys.stderr)
            return 2
        case_ids = {}
        for mode in modes:
            case_id = f"CASE-K1-M{mode}-{datetime.now(UTC).strftime('%H%M%S')}"
            rc, out, _ = _run(
                [sys.executable, "-m", "nexus", "case", "init",
                 f"K1 {report['label']} mode {mode}", "--case-id", case_id],
                timeout=300,
            )
            if rc != 0:
                print(f"case init failed for mode {mode}: {out[-300:]}", file=sys.stderr)
                return 1
            case_ids[mode] = case_id
            for path in evidence:
                _run(
                    [sys.executable, "-m", "nexus", "evidence", "register", str(path),
                     "--case", case_id, "-d", f"K1 {path.name}"],
                    timeout=1800,
                )
            print(f"mode {mode}: case {case_id} ready ({len(evidence)} evidence file(s))")
        report["case_ids"] = case_ids
    else:
        if not args.cases:
            print("--score-only needs --cases", file=sys.stderr)
            return 2
        given = [c.strip() for c in args.cases.split(",") if c.strip()]
        report["case_ids"] = {int(m): c for m, c in zip(modes, given, strict=False)}

    for mode in modes:
        case_id = report["case_ids"][mode]
        case_dir = cases_root() / case_id
        if not case_dir.is_dir():
            print(f"case dir missing: {case_dir}", file=sys.stderr)
            return 1

        hits = leak_guard(case_dir, manifest_path)
        report["truth_leak_checks"].append({"case_id": case_id, "hits": hits})

        started = time.time()
        run = {"rc": "skipped", "wall_s": 0.0}
        if not args.score_only and not args.no_run:
            run = run_mode(mode, case_id, args.question, args.timeout)
            print(f"mode {mode}: rc={run['rc']} wall={run['wall_s']}s")

        scored = score_case(case_dir, key, started_at=started)
        scored["mode"] = mode
        scored["run"] = run
        report["cases"].append(scored)
        if hits:
            print(f"LEAK in {case_id}: {hits[:3]}", file=sys.stderr)

    report["leak_ok"] = all(not c["hits"] for c in report["truth_leak_checks"])

    json_out, md_out = Path(args.json_out), Path(args.md_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if json_out.is_file():
        try:
            existing = json.loads(json_out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}
    runs = existing.get("k_runs") if isinstance(existing.get("k_runs"), list) else []
    runs.append(report)
    existing["k_runs"] = runs
    json_out.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")

    md = md_out.read_text(encoding="utf-8") if md_out.is_file() else ""
    # Replace everything from `## K-runs` to the end with the regenerated
    # section, so the section stays last and earlier runs survive.
    marker = "## K-runs"
    if marker in md:
        md = md[: md.index(marker)].rstrip()
    md_out.write_text((md + "\n\n" + _k_runs_section(runs)).lstrip("\n"), encoding="utf-8")

    print(f"\n{report['label']}: leak guard {'CLEAN' if report['leak_ok'] else 'FAILED'}")
    for case in report["cases"]:
        tech = case["dimensions"]["techniques"]
        print(
            f"  mode {case['mode']}: techniques P={tech['precision']:.3f} "
            f"R={tech['recall']:.3f} F1={tech['f1']:.3f}, "
            f"benign-only FP={case['false_positive']['benign_only']}/{case['false_positive']['findings']}"
        )
    print(f"wrote {json_out.name} and {md_out.name}")
    return 0 if report["leak_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
