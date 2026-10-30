"""The tiny cases' coverage matrix (TIER1-WORK-ORDERS Part 11, 11.3): what the lane, the importers and the three
modes actually did on every tiny case, against what the product has. Reviewer-owned acceptance: run it, never edit
it to pass.

    python devtools/runbook/coverage_matrix.py [--round R1] [--md out.md] [--json out.json]

Reads the public manifest (``Docs/internal/eval/tiny-cases.yaml``, case ids written by ``tiny_cases.ps1``), the
universe (``Docs/internal/eval/tiny-coverage-universe.yaml``), each case's exact-run lane gate, its index (ES terms
aggregation on ``family``), and the run records named in ``cases/<id>/.trace/runs-<Txx>-<round>.ids``. Importers,
skills, playbooks and Mode 2/3 roles are read from the code. Prints the report; exits 1 while any required item
has no case in which it worked.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
EVAL = REPO / "Docs" / "internal" / "eval"
KNOWLEDGE = REPO / "src" / "nexus" / "data" / "knowledge"
OK_STATES = {"processed", "ok", "warn"}


def cases_root() -> Path:
    from nexus.config import settings  # noqa: PLC0415

    return Path(settings.cases_root)


def es_families(case_id: str) -> dict[str, int] | str:
    url = (os.environ.get("NEXUS_ES_URL") or "http://localhost:9200").rstrip("/")
    body = json.dumps({"size": 0, "aggs": {"f": {"terms": {"field": "family", "size": 500}}}}).encode()
    req = urllib.request.Request(f"{url}/nexus-case-{case_id.lower()}/_search", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.load(resp)
    except Exception as exc:  # noqa: BLE001
        return f"index unavailable ({type(exc).__name__})"
    return {b["key"]: b["doc_count"] for b in data["aggregations"]["f"]["buckets"]}


def run_ids(trace: Path, tid: str, rnd: str | None) -> tuple[str, dict[str, str]]:
    files = sorted(trace.glob(f"runs-{tid}-*.ids"), key=lambda p: p.stat().st_mtime)
    if rnd:
        files = [p for p in files if p.name == f"runs-{tid}-{rnd}.ids"]
    if not files:
        return "", {}
    tag = files[-1].name[len("runs-"):-len(".ids")]
    ids = {}
    for line in files[-1].read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2:
            ids[parts[0]] = parts[1]
    return tag, ids


def mode_log(trace: Path, tag: str, mode: str) -> dict:
    log = trace / f"run-{tag}-{mode}.log"
    if not log.is_file():
        return {"exit": None, "minutes": None}
    text = log.read_text(encoding="utf-8", errors="replace")
    exit_m = re.findall(r"^MODE\d_EXIT=(\d+)", text, flags=re.M)
    stamps = re.findall(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)$", text, flags=re.M)
    minutes = None
    if len(stamps) >= 2:
        from datetime import datetime  # noqa: PLC0415

        f = "%Y-%m-%dT%H:%M:%SZ"
        minutes = round((datetime.strptime(stamps[-1], f) - datetime.strptime(stamps[0], f)).total_seconds() / 60, 1)
    return {"exit": int(exit_m[-1]) if exit_m else None, "minutes": minutes}


def mode_record(folder: Path, mode: str, rid: str) -> dict:
    if mode == "mode1":
        path = folder / "runs" / rid / "manifest.json"
    else:
        path = folder / "analysis" / f"{mode}_runs" / f"{rid}.json"
    if not rid or not path.is_file():
        return {"status": "missing"}
    rec = json.loads(path.read_text(encoding="utf-8"))
    roles = set(rec.get("roles_used") or [])
    for res in rec.get("results") or []:
        if res.get("role"):
            roles.add(res["role"])
    # TA-5.2: a run records its knowledge in one section; a record written before it named Mode 2/3 skills only.
    knowledge = rec.get("knowledge") if isinstance(rec.get("knowledge"), dict) else None
    skills = (knowledge or {}).get("skills") if knowledge else rec.get("skills_used")
    return {
        "status": rec.get("status"),
        "reason": str(rec.get("error") or ""),
        "model": (rec.get("model") or {}).get("model") if isinstance(rec.get("model"), dict) else rec.get("model"),
        "skills": sorted({s.get("skill") for s in skills or [] if s.get("skill")}),
        "skills_recorded": knowledge is not None or "skills_used" in rec,
        "playbooks_recorded": knowledge is not None,
        "playbooks": sorted({p.get("playbook") for p in (knowledge or {}).get("playbooks") or [] if p.get("playbook")}),
        "analytics_ran": sum(1 for a in (knowledge or {}).get("analytics") or [] if a.get("outcome") == "ran"),
        "roles": sorted(roles),
        "candidates": len(rec.get("candidates") or []),
    }


def case_report(tid: str, entry: dict, rnd: str | None) -> dict:
    cid = entry.get("case_id")
    out: dict = {"case": tid, "case_id": cid, "group": entry.get("group")}
    if not cid:
        out.update({"gate": {"status": "no case: run tiny_cases.ps1"}, "jobs": [], "families": {}, "modes": {}})
        return out
    folder = cases_root() / cid
    gate_file = folder / "analysis" / "lane_gate.json"
    if gate_file.is_file():
        gate = json.loads(gate_file.read_text(encoding="utf-8"))
        out["gate"] = {k: gate.get(k) for k in ("status", "run_id", "processed_count", "blocked_count",
                                                 "waiting_count")}
        out["jobs"] = [{"tool": str(j.get("tool") or ""), "state": str(j.get("state") or ""),
                        "importer": str(j.get("importer") or "")}
                       for j in gate.get("jobs") or []]
    else:
        out["gate"] = {"status": "no lane run"}
        out["jobs"] = []
    out["families"] = es_families(cid)
    tag, ids = run_ids(folder / ".trace", tid, rnd)
    out["round_tag"] = tag
    out["modes"] = {}
    for mode in ("mode1", "mode2", "mode3"):
        rec = mode_record(folder, mode, ids.get(mode, ""))
        rec["run_id"] = ids.get(mode, "")
        if tag:
            rec.update(mode_log(folder / ".trace", tag, mode))
        out["modes"][mode] = rec
    return out


def ended_well(mode: str, rec: dict) -> bool:
    """A mode run that did its job. Mode 1 stops by design at the examiner's approval once it has staged DRAFTs: its
    record says ``interrupted`` with the reason "awaiting approval at await_approval (N DRAFT finding(s) staged)", and
    ``nexus pipeline --resume`` continues it after the examiner's decision. That is a finished analysis, not a failure."""
    if rec.get("exit") != 0:
        return False
    if rec.get("status") == "completed":
        return True
    return (mode == "mode1" and rec.get("status") in ("interrupted", "awaiting_approval")
            and rec.get("reason", "").startswith("awaiting approval at await_approval"))


def universe_lists() -> dict:
    from nexus.ingest.registry import _ALL_IMPORTERS, _safe_import  # noqa: PLC0415

    importers: dict[str, list[str]] = {}
    for mod, name in _ALL_IMPORTERS:
        cls = _safe_import(mod, name)
        if cls is None:
            continue
        try:
            src = cls.source_class()
        except TypeError:
            src = cls().source_class()
        importers.setdefault(str(getattr(src, "value", src)), []).append(name)
    skills = []
    for path in sorted((KNOWLEDGE / "skills").glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        skills.append(str(data.get("skill") or data.get("id") or path.stem))
    playbooks = sorted(p.stem for p in (KNOWLEDGE / "discipline" / "playbooks").glob("*.yaml"))
    try:
        from nexus.modes.multi_role import ROLES  # noqa: PLC0415

        roles = sorted(ROLES)
    except Exception:  # noqa: BLE001
        roles = []
    return {"importers": importers, "skills": skills, "playbooks": playbooks, "roles": roles}


def build(rnd: str | None) -> dict:
    manifest = yaml.safe_load((EVAL / "tiny-cases.yaml").read_text(encoding="utf-8"))
    universe = yaml.safe_load((EVAL / "tiny-coverage-universe.yaml").read_text(encoding="utf-8"))
    cases = [case_report(tid, entry, rnd) for tid, entry in manifest["cases"].items()]
    lists = universe_lists()
    lane_src = "".join(p.read_text(encoding="utf-8") for p in (REPO / "src" / "nexus" / "langgraph").glob("*lane*.py"))

    def seen(pred) -> dict[str, list[str]]:
        hits: dict[str, list[str]] = {}
        for c in cases:
            for j in c.get("jobs", []):
                key = pred(j)
                if key:
                    hits.setdefault(key[0], []).append(f"{c['case']}:{key[1]}")
        return hits

    from nexus.langgraph.lane_gate import import_source  # noqa: PLC0415
    from nexus.langgraph.tool_lane import is_lane_note  # noqa: PLC0415

    # A tool's row, by the gate's own naming: not the importer pass's (`import:<source>`, or `import` for a file no
    # importer recognised) and not one of the lane's notes about the evidence (D493).
    tool_seen = seen(lambda j: None if import_source(j["tool"]) is not None or is_lane_note(j["tool"])
                     else (j["tool"].lower(), j["state"]))
    import_seen = seen(lambda j: (src.lower(), j["state"]) if (src := import_source(j["tool"])) else None)
    # TA-5.3: the class that read each file (a gate written before it names only the source).
    class_seen = seen(lambda j: (j["importer"], j["state"]) if j.get("importer") else None)
    tools = {}
    for name, spec in universe["tools"].items():
        states = tool_seen.get(name, [])
        ok = [s for s in states if s.split(":", 1)[1] in OK_STATES]
        cls = spec["class"]
        if cls == "required":
            verdict = "OK" if ok else "GAP"
        elif cls == "policy_skip":
            verdict = "OK" if states and not ok else ("RAN" if ok else "GAP")
        else:
            verdict = "OK" if ok else cls
        tools[name] = {"class": cls, "verdict": verdict, "seen": states, "expect": spec.get("expect", []),
                       "in_code": name in lane_src}
    unlisted = sorted(set(tool_seen) - set(universe["tools"]))
    importers = {}
    for src, classes in lists["importers"].items():
        states = import_seen.get(src, [])
        ok = [s for s in states if s.split(":", 1)[1] in OK_STATES]
        expected = universe.get("importers_expected", {}).get(src)
        classes_ok = sorted(c for c in classes if any(s.split(":", 1)[1] in OK_STATES for s in class_seen.get(c, [])))
        importers[src] = {"classes": classes, "classes_seen": classes_ok, "seen": states, "expect": expected or [],
                          "verdict": "OK" if ok else ("GAP" if expected else "no tiny case")}
    used_skills: dict[str, list[str]] = {}
    used_roles: dict[str, list[str]] = {}
    playbooks_recorded = False
    used_playbooks: dict[str, list[str]] = {}
    for c in cases:
        for mode, rec in (c.get("modes") or {}).items():
            for s in rec.get("skills") or []:
                used_skills.setdefault(s, []).append(f"{c['case']}:{mode}")
            for r in rec.get("roles") or []:
                used_roles.setdefault(r, []).append(f"{c['case']}:{mode}")
            playbooks_recorded |= bool(rec.get("playbooks_recorded"))
            for p in rec.get("playbooks") or []:
                used_playbooks.setdefault(p, []).append(f"{c['case']}:{mode}")
    skills = {s: {"verdict": "OK" if s in used_skills else "GAP", "seen": used_skills.get(s, [])}
              for s in lists["skills"]}
    playbooks = {p: {"verdict": "OK" if p in used_playbooks else ("GAP" if playbooks_recorded else "not recorded"),
                     "seen": used_playbooks.get(p, [])} for p in lists["playbooks"]}
    roles = {r: {"verdict": "OK" if r in used_roles else "GAP", "seen": used_roles.get(r, [])}
             for r in lists["roles"]}
    gaps = ([f"tool {k}" for k, v in tools.items() if v["verdict"] == "GAP"]
            + [f"tool {k} not found in the lane modules" for k, v in tools.items() if not v["in_code"]]
            + [f"unlisted tool {t} (add it to the universe)" for t in unlisted]
            + [f"importer {k}" for k, v in importers.items() if v["verdict"] == "GAP"]
            + [f"skill {k}" for k, v in skills.items() if v["verdict"] == "GAP"]
            + [f"playbook {k} ({v['verdict']})" for k, v in playbooks.items() if v["verdict"] != "OK"]
            + [f"role {k}" for k, v in roles.items() if v["verdict"] == "GAP"]
            + [f"{c['case']}: gate {c['gate'].get('status')}" for c in cases if c.get("gate", {}).get("status") != "clear"]
            + [f"{c['case']}: {m} exit {r.get('exit')} status {r.get('status')} {r.get('reason', '')[:80]}".rstrip()
               for c in cases for m, r in (c.get("modes") or {}).items() if not ended_well(m, r)])
    return {"cases": cases, "tools": tools, "importers": importers, "skills": skills, "playbooks": playbooks,
            "roles": roles, "gaps": gaps}


def markdown(rep: dict) -> str:
    lines = ["# Tiny-case coverage", "", "## Cases", "",
             "| Case | Gate | Families | Mode 1 | Mode 2 | Mode 3 |", "|---|---|---|---|---|---|"]
    for c in rep["cases"]:
        fam = c.get("families")
        fam_s = ", ".join(f"{k} {v}" for k, v in sorted(fam.items())) if isinstance(fam, dict) else str(fam)
        modes = []
        for m in ("mode1", "mode2", "mode3"):
            r = (c.get("modes") or {}).get(m, {})
            modes.append(f"{r.get('status')} exit {r.get('exit')} {r.get('minutes')} min" if r else "-")
        g = c.get("gate", {})
        lines.append(f"| {c['case']} {c.get('case_id') or ''} | {g.get('status')} ({g.get('processed_count')} processed, "
                     f"{g.get('blocked_count')} blocked, {g.get('waiting_count')} waiting) | {fam_s[:300]} | "
                     + " | ".join(modes) + " |")
    for title, key in (("Lane tools", "tools"), ("Importers (by source)", "importers"), ("Skills", "skills"),
                       ("Playbooks", "playbooks"), ("Mode 2/3 roles", "roles")):
        lines += ["", f"## {title}", "", "| Item | Verdict | Where |", "|---|---|---|"]
        for name, v in rep[key].items():
            where = ", ".join(v.get("seen", [])[:8]) or ("expected: " + ", ".join(v.get("expect", []))
                                                         if v.get("expect") else "")
            extra = f" ({v['class']})" if "class" in v else ""
            if v.get("classes_seen"):
                where = f"read by {', '.join(v['classes_seen'])}; " + where
            lines.append(f"| {name}{extra} | {v['verdict']} | {where} |")
    lines += ["", f"## Gaps ({len(rep['gaps'])})", ""] + [f"- {g}" for g in rep["gaps"]]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--round", default=None)
    ap.add_argument("--md")
    ap.add_argument("--json")
    args = ap.parse_args()
    rep = build(args.round)
    text = markdown(rep)
    if args.md:
        Path(args.md).write_text(text, encoding="utf-8", newline="\n")
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=2, default=str), encoding="utf-8", newline="\n")
    print(text)
    return 1 if rep["gaps"] else 0


if __name__ == "__main__":
    sys.exit(main())
