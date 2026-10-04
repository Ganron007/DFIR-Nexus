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
import os
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
        ("needles_generated", "src/nexus/data/knowledge/needles/generated_needles.yaml"),
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
    ]
    if report.get("void"):
        # A void run must never be read as a result. The section is regenerated
        # from the JSON records, so this has to be rendered - a hand-edit to the
        # Markdown would be wiped on the next run.
        lines += [
            "> **VOID — do not read as a result.** "
            + str(report.get("void_reason") or "marked void by the operator"),
            "",
        ]
    if report.get("aborted"):
        lines += [
            f"> **SWEEP ABORTED — {report['aborted']}**",
            ">",
            "> Cases completed before the abort are recorded below; the rest never ran.",
            "",
        ]
    lines += [
        f"- When: {report['at']}",
        f"- HEAD: `{report['head']}`",
        f"- Question: {report['question']!r} (the only examiner input)",
        f"- Modes: {report.get('modes')} · repeats: {report.get('repeats', 1)}",
        "",
    ]
    for target in report.get("targets", []):
        counts = target.get("key_counts", {})
        lines.append(
            f"- `{target['name']}`: {target['evidence']} evidence file(s), "
            f"{counts.get('techniques', 0)} expected technique(s), "
            f"{target['truth_skipped']} truth file(s) skipped — "
            f"manifest `{Path(target['manifest']).name}` (read only by the scorer)"
        )
    lines.append("")
    if report["truth_leak_checks"]:
        lines.append("- manifest-leak guard:")
        for check in report["truth_leak_checks"]:
            state = "CLEAN" if not check["hits"] else f"LEAK - {check['hits'][:3]}"
            lines.append(f"  - `{check['case_id']}`: {state}")
        lines.append("")
    lines += [
        "| Case | Rep | Mode | rc | Run status | Findings | Techniques P | R | F1 | "
        "Entities F1 | Benign-only FP | First true lead | Wall s |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
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
            f"| {case.get('target', '-')} | {case.get('repeat', 1)} | {case['mode']} | "
            f"{case['run'].get('rc')} | {'INCOMPLETE' if case.get('incomplete') else case.get('run_status') or '-'} | "
            f"{case.get('findings', 0)} | "
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


def _load_targets(set_dir: str, manifest: str, case_set: str) -> list[dict]:
    """The cases to run: one, or a set, each with its own evidence and manifest.

    A manifest is per-case (a set of files has its own ground truth), so the key
    is loaded per target rather than once - and only ever here.
    """
    if case_set:
        path = Path(case_set)
        if not path.is_file():
            raise SystemExit(f"case set not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        cases = data.get("cases") if isinstance(data, dict) else data
        if not isinstance(cases, list) or not cases:
            raise SystemExit(f"{path}: expected {{'cases': [...]}}")
        out: list[dict] = []
        for i, item in enumerate(cases, 1):
            if not isinstance(item, dict):
                raise SystemExit(f"{path}: case {i} is not an object")
            name = str(item.get("name") or f"case{i}")
            root = path.parent
            set_dir_i = str(item.get("set_dir") or "")
            manifest_i = str(item.get("manifest") or "")
            if set_dir_i and not Path(set_dir_i).is_absolute():
                set_dir_i = str(root / set_dir_i)
            if manifest_i and not Path(manifest_i).is_absolute():
                manifest_i = str(root / manifest_i)
            out.append({"name": name, "set_dir": set_dir_i, "manifest": manifest_i})
        return out

    if not manifest or not str(manifest):
        raise SystemExit("--manifest is required (or use --case-set)")
    return [{"name": "case", "set_dir": set_dir, "manifest": str(manifest)}]


def latest_run_status(case_dir: Path) -> str:
    """The status of the case's newest pipeline run ("", "running", "completed").

    A case can be scored while its run is still in flight - measured
    2026-10-03: `CASE-K1-ta0002-m1-r1-215904` was scored with status `running`
    and contributed 5 partial findings, which reads as a product result. A
    partial run is not a measurement.
    """
    runs = case_dir / "runs"
    if not runs.is_dir():
        return ""
    newest = ""
    newest_name = ""
    for child in runs.iterdir():
        if child.is_dir() and child.name > newest_name:
            manifest = child / "manifest.json"
            if manifest.is_file():
                newest_name = child.name
                try:
                    newest = str(json.loads(
                        manifest.read_text(encoding="utf-8")
                    ).get("status") or "")
                except (OSError, ValueError):
                    newest = ""
    return newest


def es_unreachable() -> str:
    """Why ES is unusable, or "" when it is up.

    Interpret refuses without ES (by design, no salvage), so every case run
    without it produces zero findings. A sweep that scores those zeros reports a
    product failure that did not happen. This is the preflight that refuses to.
    """
    url = (os.environ.get("NEXUS_ES_URL") or "").strip()
    if not url:
        try:
            from nexus.config import settings
            url = str(getattr(settings, "es_url", "") or "")
        except Exception:  # noqa: BLE001
            url = ""
    if not url:
        return "NEXUS_ES_URL is not set"
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(
            url.rstrip("/") + "/_cluster/health", timeout=8
        ) as response:
            body = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"{url} unreachable: {type(exc).__name__}: {exc}"
    status = str(body.get("status") or "")
    if status in ("red", "unavailable"):
        return f"{url} cluster status is {status!r}"
    return ""


def ablations_to_run(args_layers: str, ablate: bool) -> list[str]:
    """The layers a `--ablate` invocation should disable, one run each."""
    from nexus.analysis.layers import KNOWLEDGE_LAYERS, LEAD_SOURCES

    if args_layers.strip():
        wanted = [t.strip().lower() for t in args_layers.split(",") if t.strip()]
        known = set(LEAD_SOURCES) | set(KNOWLEDGE_LAYERS)
        unknown = [w for w in wanted if w not in known]
        if unknown:
            raise SystemExit(
                f"unknown layer(s) {', '.join(unknown)}; "
                f"known: {', '.join(sorted(known))}"
            )
        return wanted
    if ablate:
        return list(LEAD_SOURCES) + list(KNOWLEDGE_LAYERS)
    return []


def _ablation_table(runs: list[dict], baseline_label: str) -> str:
    """A per-layer delta against a named baseline run.

    The operator decides the cuts, so the table states recall and the
    false-positive number for the baseline and for each disabled layer, and the
    delta. A layer whose removal does not move recall has not earned its place.
    """
    from nexus.analysis.layers import KNOWLEDGE_LAYERS, LEAD_SOURCES

    base = None
    for run in runs:
        if baseline_label and run.get("label") == baseline_label:
            base = run
            break
    if base is None:
        for run in reversed(runs):
            if not str(run.get("label") or "").startswith("ablate:"):
                base = run
                break
    by_layer: dict[str, dict] = {}
    for run in runs:
        label = str(run.get("label") or "")
        if label.startswith("ablate:"):
            by_layer[label.split(":", 1)[1].strip()] = run

    # A baseline is required to compute a delta. With no baselines at all there
    # is nothing to compare, so no table - but a baseline with no ablations still
    # gets one, listing every layer as not run, which is the honest reading.
    if base is None:
        return ""

    def _agg(run: dict) -> tuple[float, float, int]:
        recalls = [c["dimensions"]["techniques"]["recall"]
                   for c in run.get("cases", [])
                   if c["dimensions"]["techniques"].get("recall") is not None]
        precs = [c["dimensions"]["techniques"]["precision"]
                 for c in run.get("cases", [])]
        fp = sum(c["false_positive"]["benign_only"] for c in run.get("cases", []))
        return (
            sum(recalls) / len(recalls) if recalls else 0.0,
            sum(precs) / len(precs) if precs else 0.0,
            fp,
        )

    base_r, base_p, base_fp = _agg(base)
    lines = [
        "",
        "### Ablation (WO-K8)",
        "",
        f"Baseline: **{base.get('label')}** (recall {base_r:.3f}, precision "
        f"{base_p:.3f}, benign-only FP {base_fp}).",
        "",
        "| Layer disabled | Recall | Δ recall | Precision | Δ precision | Benign-only FP |",
        "|---|---|---|---|---|---|",
    ]
    for layer in list(LEAD_SOURCES) + list(KNOWLEDGE_LAYERS):
        run = by_layer.get(layer)
        if run is None:
            lines.append(f"| {layer} | _(not run)_ | | | | |")
            continue
        recall, precision, fp = _agg(run)
        lines.append(
            f"| {layer} | {recall:.3f} | {recall - base_r:+.3f} | "
            f"{precision:.3f} | {precision - base_p:+.3f} | {fp} |"
        )
    lines.append("")
    lines.append(
        "A layer whose removal does not move recall or the false-positive number "
        "has not earned its place. **The operator decides the cuts.**"
    )
    lines.append("")
    return "\n".join(lines)


def _child_argv(args: argparse.Namespace) -> list[str]:
    """The argv for an ablated child run, rebuilt from the parsed arguments.

    Deliberately **not** a filter over raw `argv`: `--label x` and
    `--ablate-layers rules,rag` are two tokens each, so dropping only the flag
    leaves the value behind as a stray positional and every child invocation
    fails with "unrecognized arguments". Measured 2026-10-04 while auditing the
    path - the bug would only have surfaced after a ~70 h ablation sweep.
    """
    out: list[str] = []
    if args.case_set:
        out += ["--case-set", args.case_set]
    elif args.set_dir:
        out += ["--set-dir", args.set_dir]
        if args.manifest:
            out += ["--manifest", args.manifest]
    elif args.manifest:
        out += ["--manifest", args.manifest]
    if args.modes:
        out += ["--modes", str(args.modes)]
    out += ["--repeats", str(args.repeats)]
    if args.question:
        out += ["--question", args.question]
    if args.timeout:
        out += ["--timeout", str(args.timeout)]
    if args.json_out:
        out += ["--json-out", str(args.json_out)]
    if args.md_out:
        out += ["--md-out", str(args.md_out)]
    if args.score_only:
        out.append("--score-only")
    if args.no_run:
        out.append("--no-run")
    # Never propagate the ablation switches: the child is the ordinary run, and
    # the layer is removed through the environment variable instead.
    return out


def build_parser() -> argparse.ArgumentParser:
    """The CLI parser, extracted so tests can round-trip the child argv."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set-dir", default="", help="evidence directory for K1")
    parser.add_argument("--manifest", default="", help="operator manifest (read only here)")
    parser.add_argument("--case-set", default="",
                        help="JSON listing several cases: {cases:[{name,set_dir,manifest}]}")
    parser.add_argument("--ablate", action="store_true",
                        help="run the set once per layer with that layer disabled, then "
                             "write the deltas (WO-K8)")
    parser.add_argument("--ablate-layers", default="",
                        help="comma list to ablate instead of every layer")
    parser.add_argument("--baseline-label", default="",
                        help="K-run label the ablation deltas compare against")
    parser.add_argument("--void", default="",
                        help="mark this run VOID with a reason (excluded from use as a result)")
    parser.add_argument("--repeats", type=int, default=1,
                        help="run the whole set this many times (independent cases)")
    parser.add_argument("--modes", default="1,2,3")
    parser.add_argument("--label", default="", help="K-run name, e.g. 'K-run 0 baseline'")
    parser.add_argument("--question", default=NEUTRAL_QUESTION)
    parser.add_argument("--cases", default="", help="--score-only: case ids to score")
    parser.add_argument("--score-only", action="store_true")
    parser.add_argument("--no-run", action="store_true", help="create + register only")
    parser.add_argument("--timeout", type=int, default=5400, help="per-mode seconds")
    parser.add_argument("--json-out", default=str(DEFAULT_JSON))
    parser.add_argument("--md-out", default=str(DEFAULT_MD))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    modes = [int(m) for m in args.modes.split(",") if m.strip()]
    repeats = max(1, int(args.repeats))
    targets = _load_targets(args.set_dir, args.manifest, args.case_set)

    # WO-K8: an ablation is the same set run once per disabled layer. Each is a
    # full sweep, so it runs as a child of this command with the toggle set -
    # that reuses the exact measurement path rather than a parallel one.
    ablations = ablations_to_run(args.ablate_layers, args.ablate)
    if ablations:
        from nexus.analysis.layers import ENV_KNOWLEDGE_DISABLE, ENV_LEADS_DISABLE
        from nexus.analysis.layers import LEAD_SOURCES as _LS

        print(f"ablation: {len(ablations)} layer(s) x the whole set")
        for layer in ablations:
            env = dict(os.environ)
            var = ENV_LEADS_DISABLE if layer in _LS else ENV_KNOWLEDGE_DISABLE
            env[var] = layer
            argv_child = _child_argv(args) + ["--label", f"ablate:{layer}"]
            print(f"  -- ablating {layer} ({var}={layer})")
            subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), *argv_child],
                env=env, check=False,
            )
        # Then write the deltas for everything recorded so far.
        if Path(args.json_out).is_file():
            existing = json.loads(Path(args.json_out).read_text(encoding="utf-8"))
            runs = existing.get("k_runs") or []
            table = _ablation_table(runs, args.baseline_label)
            if table:
                md_path = Path(args.md_out)
                md = md_path.read_text(encoding="utf-8") if md_path.is_file() else ""
                md = md.replace("### Ablation (WO-K8)", "", 1)
                md_path.write_text(md.rstrip() + "\n" + table, encoding="utf-8")
                print(f"wrote the ablation table to {md_path.name}")
        return 0
    for target in targets:
        if not Path(target["manifest"]).is_file():
            print(f"manifest not found: {target['manifest']}", file=sys.stderr)
            return 2

    report: dict = {
        "label": args.label or datetime.now(UTC).strftime("K-run %Y-%m-%dT%H:%MZ"),
        "at": datetime.now(UTC).isoformat(),
        "head": _git_head(),
        "question": args.question,
        "modes": modes,
        "repeats": repeats,
        "knowledge": _knowledge_versions(),
        "targets": [],
        "cases": [],
        "truth_leak_checks": [],
    }
    if args.void:
        report["void"] = True
        report["void_reason"] = args.void

    # Refuse before creating anything: a case run without ES yields zero findings
    # and scores as a product miss that never happened. Measured 2026-10-03/04:
    # ES exited at 23:12 and 16 of 18 cases ran to completion reporting 0 findings.
    if not args.score_only:
        why = es_unreachable()
        if why:
            print(f"refusing to run: {why}", file=sys.stderr)
            print(
                "Interpret refuses without Elasticsearch (no salvage), so every case "
                "would score zero findings. Start ES (the lab container is `nexus-es`) "
                "and re-run. Nothing was created or scored.",
                file=sys.stderr,
            )
            return 3

    prepared: list[dict] = []
    for target in targets:
        set_dir = target["set_dir"]
        tmanifest = Path(target["manifest"])
        # The ONLY reader of a manifest. It is never passed to a prompt, a tool,
        # a child process argument or the child environment.
        tkey = AnswerKey.from_manifest(tmanifest)
        evidence: list[Path] = []
        skipped: list[Path] = []
        if set_dir:
            evidence, skipped = discover_evidence(Path(set_dir))
        entry = {
            "name": target["name"],
            "manifest": str(tmanifest),
            "set_dir": str(set_dir or ""),
            "evidence": len(evidence),
            "truth_skipped": len(skipped),
            "key_counts": tkey.to_dict()["counts"],
        }
        report["targets"].append(entry)
        print(
            f"\n=== {target['name']}: {len(evidence)} evidence file(s), "
            f"{entry['key_counts']['techniques']} expected technique(s), "
            f"{repeats} repeat(s)"
        )
        if skipped:
            print(f"  skipped {len(skipped)} truth file(s) - they are the answer")
        prepared.append({
            "target": target, "tmanifest": tmanifest, "tkey": tkey,
            "evidence": evidence,
        })

    # Repeat-major, NOT target-major: every target completes r1 before any target
    # starts r2, so a complete baseline exists as early as possible. Target-major
    # spends hours finishing one case's repeats before touching the next case -
    # which is the wrong shape when the batch may be read (or stopped) part-way.
    abort_reason = ""
    for rep in range(repeats):
        for item in prepared:
            target = item["target"]
            tmanifest = item["tmanifest"]
            tkey = item["tkey"]
            evidence = item["evidence"]
            if abort_reason:
                break
            if not args.score_only:
                # ES can die mid-sweep. Stop rather than accumulate cases that
                # measure nothing and report them as scores.
                why = es_unreachable()
                if why:
                    abort_reason = f"{why} (rep {rep + 1}, target {target['name']})"
                    print(f"\nABORTING THE SWEEP: {abort_reason}", file=sys.stderr)
                    break
            if not args.score_only:
                if not evidence:
                    print("--set-dir (or --case-set) is required unless --score-only",
                          file=sys.stderr)
                    return 2
                case_ids = {}
                stamp = datetime.now(UTC).strftime("%H%M%S")
                for mode in modes:
                    case_id = f"CASE-K1-{target['name']}-m{mode}-r{rep + 1}-{stamp}"
                    rc, out, _ = _run(
                        [sys.executable, "-m", "nexus", "case", "init",
                         f"K1 {report['label']} {target['name']} mode {mode} rep {rep + 1}",
                         "--case-id", case_id],
                        timeout=300,
                    )
                    if rc != 0:
                        print(f"case init failed: {out[-300:]}", file=sys.stderr)
                        return 1
                    case_ids[mode] = case_id
                    for path in evidence:
                        _run(
                            [sys.executable, "-m", "nexus", "evidence", "register", str(path),
                             "--case", case_id, "-d", f"K1 {path.name}"],
                            timeout=1800,
                        )
                    # K1 allows exactly one examiner input: a neutral question. It
                    # must be set as case intake, because the interpret stages read
                    # the question from the case - without it the lane parses
                    # everything and then produces a generic host-triage pass with
                    # no findings, which would score as recall 0 for no good reason.
                    _run(
                        [sys.executable, "-m", "nexus", "case", "intake",
                         "--case", case_id, "--question", args.question],
                        timeout=300,
                    )
                print(f"  rep {rep + 1}: {len(case_ids)} case(s) ready "
                      f"({len(evidence)} evidence file(s) each)")
            else:
                if not args.cases:
                    print("--score-only needs --cases", file=sys.stderr)
                    return 2
                given = [c.strip() for c in args.cases.split(",") if c.strip()]
                case_ids = {int(m): c for m, c in zip(modes, given, strict=False)}

            for mode in modes:
                case_id = case_ids[mode]
                case_dir = cases_root() / case_id
                if not case_dir.is_dir():
                    print(f"case dir missing: {case_dir}", file=sys.stderr)
                    return 1

                hits = leak_guard(case_dir, tmanifest)
                report["truth_leak_checks"].append({
                    "case_id": case_id, "target": target["name"], "hits": hits,
                })

                started = time.time()
                run = {"rc": "skipped", "wall_s": 0.0}
                if not args.score_only and not args.no_run:
                    run = run_mode(mode, case_id, args.question, args.timeout)
                    print(f"  rep {rep + 1} mode {mode}: rc={run['rc']} "
                          f"wall={run['wall_s']}s")

                scored = score_case(case_dir, tkey, started_at=started)
                status = latest_run_status(case_dir)
                scored.update({
                    "mode": mode,
                    "target": target["name"],
                    "repeat": rep + 1,
                    "run": run,
                    "run_status": status,
                    # A run that never completed is not a measurement.
                    "incomplete": bool(status) and status != "completed",
                })
                report["cases"].append(scored)
                if scored["incomplete"]:
                    print(f"  WARNING: run status {status!r} - this case is not a "
                          f"measurement (recorded as incomplete)", file=sys.stderr)
                if hits:
                    print(f"  LEAK in {case_id}: {hits[:3]}", file=sys.stderr)

    report["leak_ok"] = all(not c["hits"] for c in report["truth_leak_checks"])
    if abort_reason:
        report["aborted"] = abort_reason
        print(
            f"sweep aborted after {len(report['cases'])} case(s): {abort_reason}",
            file=sys.stderr,
        )

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
        fp = case["false_positive"]

        def _num(value: str | float | None) -> str:
            return "n/a" if value is None else format(value, ".3f")

        print(
            f"  mode {case['mode']}: techniques P={_num(tech['precision'])} "
            f"R={_num(tech['recall'])} F1={_num(tech['f1'])}, "
            f"benign-only FP={fp['benign_only']}/{fp['findings']}"
        )
    print(f"wrote {json_out.name} and {md_out.name}")
    return 0 if report["leak_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
