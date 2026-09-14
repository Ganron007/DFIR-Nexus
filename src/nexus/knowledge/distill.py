"""Skill distillation pipeline — WP 9.2.

Turns a KB selection into a schema-valid, fully-cited skill DRAFT for review.

    acquire  → ``kb export --format skill`` (KB-2) or a provided ``--from-yaml``
    refine   → deterministic cleanup (+ optional LLM pass when configured)
    gate     → ``validate_skill`` + every step query parses + citations present
    emit     → a review dir (default ``Docs/internal/skill-drafts``)

Safety: never installs into the shipped skills dir unless ``install=True`` and
every gate passes — distillation drafts, a human/agent promotes.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

from nexus.knowledge.loader import det_for, skill_sources, validate_skill
from nexus.langgraph.query_dsl import parse_query

_KB_DEFAULT = r"G:\doc_extract\kb\kb.py"
_REPO = Path(__file__).resolve().parents[3]
_DEFAULT_OUT = _REPO / "Docs" / "internal" / "skill-drafts"
_SKILLS_DIR = _REPO / "src" / "nexus" / "data" / "knowledge" / "skills"
_CITE_RE = re.compile(r"^d_[0-9a-f]{4,}:[cu]?[0-9a-f]{1,12}$")

_LLM_SYSTEM = """\
You refine an auto-generated DFIR investigation skill DRAFT into a coherent
procedure an examiner can run. You are given the draft (with a `source` list of
KB chunk citations) and short excerpts from those chunks.

Rules:
- Return ONLY JSON matching the input schema exactly: skill, title, description,
  trigger {families, keywords, techniques}, steps [{name, query, look_for, pivot,
  corroborate}], negative, confidence_rules {high, medium, low}, caveats, mitre.
- Keep EVERY `source` citation from the draft — never invent or drop citations.
- Queries are N4 search terms (space/OR separated), NOT natural language; keep
  them short and derived from the cited text.
- look_for must say what to verify in the returned rows (fields, values, context).
- Sequence steps in the order a senior examiner would work them.
- Do not add facts that are not in the excerpts; if unsure, keep the draft wording.
"""


def acquire_kb_export(folder: str, dest: Path, kb_py: str | None = None) -> Path | None:
    """Run ``kb export --format skill`` and return the produced draft path."""
    kb = Path(kb_py or _KB_DEFAULT)
    if not kb.is_file():
        return None
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(kb), "export", "--format", "skill",
           "--folder", folder, "--dest", str(dest)]
    res = subprocess.run(cmd, capture_output=True, text=True,
                         encoding="utf-8", errors="replace")
    if res.returncode != 0:
        raise RuntimeError("kb export failed: %s" % (res.stderr[-400:] or res.stdout[-400:]))
    cands = sorted(dest.glob("*.skill.yaml"))
    return cands[0] if cands else None


def load_draft(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"draft is not a mapping: {path}")
    return data


def gate(skill: dict[str, Any]) -> list[str]:
    """Hard gates — a gate-passing draft is safe to install."""
    problems: list[str] = list(validate_skill(skill))
    for i, st in enumerate(skill.get("steps") or []):
        q = str((st or {}).get("query") or "").strip()
        if not q:
            continue
        try:
            parse_query(q)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"step {i} query does not parse: {exc}")
    sources = skill_sources(skill)
    if not sources:
        problems.append("no source citations")
    for s in sources:
        cid = str(s.get("chunk_id") or "")
        if not _CITE_RE.match(cid):
            problems.append(f"malformed citation: {cid!r}")
    trig = skill.get("trigger") or {}
    if not (trig.get("families") or trig.get("keywords") or trig.get("techniques")):
        problems.append("empty trigger")
    return problems


def refine_deterministic(skill: dict[str, Any]) -> dict[str, Any]:
    """Dedupe steps, fold matching DET caveats, fill required blanks."""
    out = dict(skill)
    steps: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for st in out.get("steps") or []:
        if not isinstance(st, dict):
            continue
        q = str(st.get("query") or "").strip()
        lf = str(st.get("look_for") or "").strip()
        key = (q.lower(), lf[:60].lower())
        if key in seen:
            continue
        seen.add(key)
        step = {
            "name": str(st.get("name") or "step")[:60],
            "query": q,
            "look_for": lf,
            "pivot": str(st.get("pivot") or ""),
            "corroborate": str(st.get("corroborate") or ""),
        }
        if isinstance(st.get("source"), dict):
            step["source"] = st["source"]
        steps.append(step)
    out["steps"] = steps

    # Fold matching DET dictionary guidance (WP 9.7) into caveats.
    techniques = [str(t) for t in (out.get("mitre") or [])]
    caveats = [str(c) for c in (out.get("caveats") or [])]
    for e in (det_for(techniques=techniques) if techniques else []):
        cav = str(e.get("caveats") or "").strip()
        if cav and cav not in caveats:
            caveats.append(cav)
    out["caveats"] = caveats[:8]

    cr = out.get("confidence_rules") or {}
    if not any(str(v).strip() for v in cr.values()):
        out["confidence_rules"] = {
            "high": "artifact present on the host plus corroborating second-source evidence",
            "medium": "artifact present without independent corroboration",
            "low": "weak/unverified indicator — confirm signer/path and context (FD-004)",
        }
    if not str(out.get("negative") or "").strip():
        out["negative"] = (
            "Absence of these artifacts in the covered evidence does not prove the "
            "activity did not occur — state the evidence coverage and retention window."
        )
    return out


def refine_llm(skill: dict[str, Any], model: Any) -> dict[str, Any] | None:
    """Optional LLM refinement; None when no model / on any failure."""
    if model is None:
        return None
    excerpts = []
    for s in skill_sources(skill)[:12]:
        excerpts.append(str(s.get("citation") or s.get("chunk_id")))
    try:
        resp = model.invoke([
            {"role": "system", "content": _LLM_SYSTEM},
            {"role": "user", "content":
                "DRAFT (JSON):\n" + json.dumps(skill, ensure_ascii=False)[:12000]
                + "\n\nCitations to preserve:\n" + "\n".join(excerpts)},
        ])
        text = getattr(resp, "content", str(resp))
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            return None
        refined = json.loads(text[start:end + 1])
        if not isinstance(refined, dict):
            return None
        # Citations are authoritative — never let the model drop/mutate them.
        refined["source"] = skill.get("source")
        return refined
    except Exception:  # noqa: BLE001 — deterministic path stands
        return None


def distill(
    *,
    folder: str | None = None,
    from_yaml: str | Path | None = None,
    name: str | None = None,
    out_dir: str | Path | None = None,
    use_llm: bool = False,
    kb_py: str | None = None,
    install: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Acquire → refine → gate → emit a skill draft. Returns a summary report."""
    if not folder and not from_yaml:
        raise ValueError("provide folder= or from_yaml=")
    out_dir = Path(out_dir) if out_dir else _DEFAULT_OUT
    out_dir.mkdir(parents=True, exist_ok=True)

    tmp: Path | None = None
    if from_yaml:
        draft_path = Path(from_yaml)
    else:
        tmp = Path(tempfile.mkdtemp(prefix="distill_"))
        found = acquire_kb_export(str(folder), tmp, kb_py)
        if found is None:
            raise FileNotFoundError(
                "kb export produced no skill draft (KB missing or empty selection)")
        draft_path = found

    skill = load_draft(draft_path)
    slug = re.sub(r"[^a-z0-9_]+", "_", str(name or skill.get("skill") or "skill").lower()).strip("_")

    refined_by = "kb-draft"
    if use_llm:
        from nexus.langgraph.report_analysis import resolve_model

        llm = refine_llm(skill, resolve_model())
        if llm is not None:
            skill = llm
            refined_by = "llm"
    if refined_by != "llm":
        skill = refine_deterministic(skill)
        refined_by = "deterministic"
    else:
        skill = refine_deterministic(skill)  # dedupe + DET even after LLM

    problems = gate(skill)
    installed = False
    if install:
        if problems:
            dest = out_dir / f"{slug}.yaml"
        else:
            dest = _SKILLS_DIR / f"{slug}.yaml"
            if dest.exists() and not force:
                problems = [f"{dest} already exists — use force=True to overwrite"]
                dest = out_dir / f"{slug}.yaml"
            else:
                installed = True
    else:
        dest = out_dir / f"{slug}.yaml"

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        yaml.safe_dump(skill, sort_keys=False, allow_unicode=True, width=1000),
        encoding="utf-8",
    )

    report = {
        "skill": slug,
        "source_folder": folder,
        "draft_from": str(draft_path),
        "refined_by": refined_by,
        "steps": len(skill.get("steps") or []),
        "citations": len(skill_sources(skill)),
        "gate": problems,
        "installed": installed,
        "written": str(dest),
    }
    (out_dir / f"{slug}.distill-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report
