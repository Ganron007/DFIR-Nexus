"""N8 report-layer analysis — dissect every finding cluster into a readable
analyst read, then tie the case together into an assessment.

Mode 1 uses the LLM at the reporting layer even when drafting was heuristic:
each cluster gets what/why/how/who-when + a category + verify-next + caveats,
and the case gets a sequence/scope/confidence assessment. The LLM is
constrained to the evidence rows it is shown — its output is labeled
LLM-assisted and never becomes an approved fact on its own. When no model is
configured (or a call fails), a deterministic heuristic fills category +
tactic and the report still renders.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deterministic category + tactic mapping (also the LLM's allowed vocabulary)
# ---------------------------------------------------------------------------

CATEGORIES = (
    "execution", "persistence", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "command_and_control", "collection",
    "exfiltration", "impact", "authentication", "other",
)

# technique-id → ATT&CK tactic for the IDs our detection layer commonly emits.
_TID_TACTIC = {
    "T1059": "execution", "T1204": "execution", "T1106": "execution",
    "T1053": "persistence", "T1547": "persistence", "T1543": "persistence",
    "T1574": "persistence", "T1136": "persistence",
    "T1562": "defense_evasion", "T1027": "defense_evasion",
    "T1070": "defense_evasion", "T1218": "defense_evasion",
    "T1140": "defense_evasion", "T1036": "defense_evasion",
    "T1003": "credential_access", "T1555": "credential_access",
    "T1552": "credential_access", "T1558": "credential_access",
    "T1087": "discovery", "T1082": "discovery", "T1083": "discovery",
    "T1018": "discovery", "T1057": "discovery", "T1016": "discovery",
    "T1021": "lateral_movement", "T1570": "lateral_movement",
    "T1071": "command_and_control", "T1105": "command_and_control",
    "T1571": "command_and_control", "T1572": "command_and_control",
    "T1090": "command_and_control", "T1102": "command_and_control",
    "T1005": "collection", "T1560": "collection", "T1074": "collection",
    "T1113": "collection", "T1115": "collection",
    "T1041": "exfiltration", "T1048": "exfiltration", "T1567": "exfiltration",
    "T1486": "impact", "T1490": "impact", "T1489": "impact",
    "T1529": "impact", "T1498": "impact",
    "T1078": "authentication", "T1133": "authentication",
}

# keyword → category for blobs without technique IDs.
_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "execution": (
        "t1059", "t1204", "cmd.exe", "powershell", "wscript", "cscript",
        "mshta", "rundll32", "regsvr32", "commandline", "proc exec",
        "process creation", "sysmon 1", "event id 1", "encoded command",
    ),
    "persistence": (
        "t1053", "t1547", "schtasks", "scheduled task", "run key",
        "\\run\\", "service install", "startup folder", "winlogon",
        "new service", "7045", "at.exe",
    ),
    "defense_evasion": (
        "t1562", "t1027", "t1070", "t1218", "t1036", "t1140", "defender",
        "edr", "tamper", "obfuscat", "logclear", "clear log", "wevtutil",
        "disable", "masquerad", "uninstall", "timestomp",
    ),
    "credential_access": (
        "t1003", "t1555", "t1552", "t1558", "lsass", "credential",
        "password", "mimikatz", "dpapi", "ntds", "sam dump", "sekurlsa",
        "asreproast", "kerberoast",
    ),
    "discovery": (
        "t1087", "t1082", "t1083", "t1018", "t1057", "t1016", "whoami",
        "ipconfig", "systeminfo", "netstat", "net user", "net group",
        "net localgroup", "nltest", "enum", "query user", "quser",
    ),
    "lateral_movement": (
        "t1021", "t1570", "psexec", "wmi", "winrm", "admin$", "c$",
        "remote desktop", "mstsc", "rdp", "smb", "wmic /node", "copy \\\\",
    ),
    "command_and_control": (
        "t1071", "t1105", "t1571", "t1572", "t1090", "t1102", "beacon",
        "callback", "c2", "download", "http://", "https://", "dns tunnel",
        "powershell -w hidden", "certutil -urlcache", "bitsadmin",
    ),
    "collection": (
        "t1005", "t1560", "t1074", "t1113", "t1115", "archive",
        "compress", "staging", "clipboard",
    ),
    "exfiltration": (
        "t1041", "t1048", "t1567", "exfil", "upload", "ftp", "rclone",
        "megasync",
    ),
    "impact": (
        "t1486", "t1490", "t1489", "t1529", "ransom", "encrypt",
        "vssadmin", "shadow", "bcdedit", "wipe", "wiper",
    ),
    "authentication": (
        "t1078", "t1133", "logon", "4624", "4625", "4648", "4768", "4769",
        "4776", "kerberos", "ntlm", "valid account", "brute",
    ),
}

_ANALYSIS_SYSTEM = """\
You are a DFIR reporting analyst writing for an examiner who must approve or
reject the finding. You are given ONE finding cluster's evidence rows (parsed
detection/parser output) plus the draft interpretation.

Rules:
- Facts come ONLY from the evidence shown — never invent hosts, users, times,
  paths, or events not present in the rows.
- Separate observation ("the row shows X") from inference ("consistent with Y").
- Be concrete: name the artifact field, command line, or detection title that
  carries each claim.
- Keep every field to 1-2 sentences; verify/caveats are short bullet strings.
- JSON only, no markdown, no commentary."""

_ANALYSIS_SCHEMA = """\
{"category": one of execution|persistence|defense_evasion|credential_access|
discovery|lateral_movement|command_and_control|collection|exfiltration|
impact|authentication|other,
 "what": "what happened per the evidence",
 "why": "why it matters / what it indicates for the case",
 "how": "likely mechanism — inference, marked as such",
 "who_when": "account/host/process + time window visible in the evidence",
 "verify": ["concrete next checks, artifact-specific"],
 "caveats": ["benign explanations / evidentiary limits"]}"""

_ASSESS_SYSTEM = """\
You are a DFIR lead writing the case assessment for an examiner. You are given
per-cluster analyst reads (category, severity, MITRE, time window, evidence
counts) built from real detection rows.

Rules:
- Build a probable sequence of events ONLY from the clusters provided — do not
  invent stages the evidence does not show.
- Say what is corroborated (multiple families / findings agree) versus single-
  source. Confidence must match the actual corroboration.
- Name concrete gaps and the highest-value next checks.
- JSON only: {"sequence": "...", "scope": "...", "confidence": "low|medium|high
  + one-sentence reason", "gaps": ["..."], "recommended": ["..."]}"""


def resolve_model():
    """Best-effort LLM for the reporting layer; None when unconfigured."""
    try:
        from nexus.langgraph.llm_pipeline import get_model

        return get_model()
    except Exception:  # noqa: BLE001 — no LLM → deterministic layer still runs
        return None


def _dedupe_keep(items: list[str], cap: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        k = it.strip().lower()
        if k and k not in seen:
            seen.add(k)
            out.append(it.strip())
            if len(out) >= cap:
                break
    return out


def category_for(cluster: list[dict[str, Any]], rows: list[dict[str, str]]) -> str:
    """Deterministic category: technique IDs first, then keyword scoring."""
    blob_parts: list[str] = []
    for f in cluster:
        blob_parts.append(str(f.get("title") or ""))
        blob_parts.append(str(f.get("observation") or "")[:400])
    for r in rows[:10]:
        blob_parts.append(str(r.get("detail") or "")[:400])
        blob_parts.append(str(r.get("source") or ""))
    blob = " ".join(blob_parts).lower()

    for f in cluster:
        for tid in (f.get("mitre_ids") or f.get("attack_ids")
                    or f.get("technique_ids") or []):
            base = str(tid).split(".")[0].strip().upper()
            if base in _TID_TACTIC:
                return _TID_TACTIC[base]

    scores: dict[str, int] = {c: 0 for c in CATEGORIES}
    for cat, kws in _CATEGORY_KEYWORDS.items():
        for kw in kws:
            if kw in blob:
                scores[cat] += 1
    best = max(scores, key=lambda c: scores[c])
    return best if scores[best] > 0 else "other"


def _cluster_blob(cluster: list[dict[str, Any]], rows: list[dict[str, str]],
                  *, cap_rows: int = 16) -> str:
    """Compact evidence block for the prompt — signature-collapsed rows.

    Distinct detection signatures (not raw row count) are what the LLM
    dissects — 300 rows collapse to their ~30 signatures so massive
    evidence sets still fit the context window.
    """
    from nexus.integration.evidence_table import collapse_signatures

    sig_rows = collapse_signatures(rows)
    titles = "; ".join(dict.fromkeys(str(f.get("title") or "") for f in cluster))
    sev = str(cluster[0].get("severity") or "unrated")
    tids = sorted({
        str(t)
        for f in cluster
        for t in (f.get("mitre_ids") or f.get("attack_ids")
                  or f.get("technique_ids") or [])
    })
    parts = [
        f"Finding(s): {titles}",
        f"Severity: {sev}" + (f"  MITRE: {', '.join(tids)}" if tids else ""),
        (f"Evidence: {len(rows)} rows grouped into {len(sig_rows)} distinct "
         "signatures (ONLY source of facts):"),
    ]
    for r in sig_rows[:cap_rows]:
        line = " | ".join(
            x for x in (
                str(r.get("time") or ""),
                str(r.get("source") or ""),
                str(r.get("detail") or "")[:300],
                str(r.get("loc") or ""),
            ) if x
        )
        parts.append(f"- {line[:420]}")
    if len(sig_rows) > cap_rows:
        parts.append(f"- … {len(sig_rows) - cap_rows} more signatures not shown")
    interp = next(
        (str(f.get("interpretation") or "").strip() for f in cluster
         if str(f.get("interpretation") or "").strip()),
        "",
    )
    if interp:
        parts.append(f"Prior interpretation: {interp[:600]}")
    return "\n".join(parts)


_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _real_times(rows: list[dict[str, str]]) -> list[str]:
    """Sorted real timestamps — drops '', '—', and other non-date markers."""
    return sorted(
        t for t in (str(r.get("time") or "") for r in rows)
        if _TS_RE.match(t)
    )


def _heuristic_analysis(cluster: list[dict[str, Any]],
                        rows: list[dict[str, str]]) -> dict[str, Any]:
    """No-LLM read: category from the deterministic map, pointers to evidence."""
    cat = category_for(cluster, rows)
    times = _real_times(rows)
    span = ""
    if times:
        span = f" ({times[0]} → {times[-1]})" if times[0] != times[-1] else f" ({times[0]})"
    return {
        "category": cat,
        "what": (f"{len(cluster)} finding(s) over {len(rows)} evidence row(s)"
                 f"{span} — see the table below."),
        "why": "",
        "how": "",
        "who_when": "",
        "verify": [],
        "caveats": ["No LLM configured — deterministic category only; "
                    "examiner reads evidence rows directly."],
        "source": "heuristic",
    }


def _merge_analysis(base: dict[str, Any], parsed: dict[str, Any]) -> dict[str, Any]:
    """Merge a model's analyst-read JSON into the deterministic skeleton."""
    out = dict(base)
    cat = str(parsed.get("category") or "").strip().lower()
    out["category"] = cat if cat in CATEGORIES else base["category"]
    for key in ("what", "why", "how", "who_when"):
        value = str(parsed.get(key) or "").strip()
        if value:
            out[key] = value[:600]
    for key in ("verify", "caveats"):
        vals = parsed.get(key)
        if isinstance(vals, list):
            out[key] = _dedupe_keep([str(v) for v in vals], 5)
        elif isinstance(vals, str) and vals.strip():
            out[key] = [vals.strip()[:200]]
    out["source"] = str(parsed.get("_source") or "llm")
    return out


def _analysis_with_loop(
    cluster: list[dict[str, Any]], rows: list[dict[str, str]],
    user_msg: str, model: Any, case_dir: Path,
) -> dict[str, Any] | None:
    """WP 10.53: analyst read via the shared bounded tool loop."""
    try:
        from nexus.audit import AuditWriter
        from nexus.langgraph.context_loop import (
            LoopBudget,
            context_loop_enabled,
            run_context_loop,
        )

        if not context_loop_enabled():
            return None
        loop = run_context_loop(
            case_dir=case_dir,
            case_id=case_dir.name,
            question=user_msg,
            model=model,
            system_prompt=(
                _ANALYSIS_SYSTEM
                + "\n\nYou may call the read-only tools for case context "
                  "(schema, run record, sampled rows, KB/RAG methodology), "
                  "but the finding read must stay grounded in the cluster "
                  "evidence shown. Return the analyst-read JSON object as "
                  "the final answer."
            ),
            task="report-cluster",
            terminal_keys=("category", "what", "why"),
            budget=LoopBudget(rounds=2, seconds=120.0, calls=4),
            audit=AuditWriter("nexus", audit_dir=case_dir / "audit"),
        )
        from nexus.modes.llm_desk import _parse_json_response

        parsed = _parse_json_response(str(loop.get("reply") or ""))
        if isinstance(parsed, dict):
            parsed.setdefault("_source", "llm-context-loop")
            return parsed
    except Exception as exc:  # noqa: BLE001 — report must still render
        log.debug("report cluster context loop failed: %s", exc)
    return None


def analyze_cluster(cluster: list[dict[str, Any]], rows: list[dict[str, str]],
                    model=None, steer: str = "",
                    case_dir: Path | None = None) -> dict[str, Any]:
    """One analyst read for a cluster — LLM JSON when a model is available.

    WP 10.53: when ``case_dir`` is supplied, the model gets the shared bounded
    tool loop (schema/run record/sample rows/KB/RAG on demand); without it the
    original one-shot prompt is kept for tests and CLI callers.
    """
    base = _heuristic_analysis(cluster, rows)
    if model is None:
        return base
    steer_block = (
        f"\n\nExaminer steering — honor this direction in the read "
        f"(still only facts from the evidence shown): {steer[:400]}"
        if steer.strip() else ""
    )
    user_msg = (
        _cluster_blob(cluster, rows)
        + steer_block
        + "\n\nReturn JSON only:\n" + _ANALYSIS_SCHEMA
    )
    if case_dir is not None:
        loop_parsed = _analysis_with_loop(cluster, rows, user_msg, model, Path(case_dir))
        if loop_parsed is not None:
            return _merge_analysis(base, loop_parsed)
    try:
        resp = model.invoke([
            {"role": "system", "content": _ANALYSIS_SYSTEM},
            {"role": "user", "content": user_msg},
        ])
        text = getattr(resp, "content", str(resp))
        from nexus.modes.llm_desk import _parse_json_response

        parsed = _parse_json_response(text)
        if not isinstance(parsed, dict):
            return base
        return _merge_analysis(base, parsed)
    except Exception as exc:  # noqa: BLE001 — LLM failure must not break the report
        log.warning("report analysis LLM failed: %s", exc)
        return base


def analyze_clusters(clusters: list[list[dict[str, Any]]],
                     rows_for: dict[int, list[dict[str, str]]],
                     model=None, steer: str = "",
                     case_dir: Path | None = None) -> dict[int, dict[str, Any]]:
    """Analyst read per cluster, keyed by cluster index."""
    out: dict[int, dict[str, Any]] = {}
    for i, cluster in enumerate(clusters):
        out[i] = analyze_cluster(
            cluster, rows_for.get(i, []), model=model, steer=steer,
            case_dir=case_dir)
    return out


def _merge_assessment(base: dict[str, Any], parsed: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key in ("sequence", "scope", "confidence"):
        value = str(parsed.get(key) or "").strip()
        if value:
            out[key] = value[:900]
    for key in ("gaps", "recommended"):
        vals = parsed.get(key)
        if isinstance(vals, list):
            out[key] = _dedupe_keep([str(v) for v in vals], 6)
    out["source"] = str(parsed.get("_source") or "llm")
    return out


def _assessment_with_loop(
    user_msg: str, model: Any, case_dir: Path,
) -> dict[str, Any] | None:
    """WP 10.53: case assessment via the shared bounded tool loop."""
    try:
        from nexus.audit import AuditWriter
        from nexus.langgraph.context_loop import (
            LoopBudget,
            context_loop_enabled,
            run_context_loop,
        )

        if not context_loop_enabled():
            return None
        loop = run_context_loop(
            case_dir=case_dir,
            case_id=case_dir.name,
            question=user_msg,
            model=model,
            system_prompt=(
                _ASSESS_SYSTEM
                + "\n\nYou may call the read-only tools for case context "
                  "(schema, run record, sampled rows, KB/RAG methodology); "
                  "the theory must stay grounded in the cluster reads shown. "
                  "Return the assessment JSON object as the final answer."
            ),
            task="report-assessment",
            terminal_keys=("sequence", "gaps", "recommended"),
            budget=LoopBudget(rounds=2, seconds=120.0, calls=4),
            audit=AuditWriter("nexus", audit_dir=case_dir / "audit"),
        )
        from nexus.modes.llm_desk import _parse_json_response

        parsed = _parse_json_response(str(loop.get("reply") or ""))
        if isinstance(parsed, dict):
            parsed.setdefault("_source", "llm-context-loop")
            return parsed
    except Exception as exc:  # noqa: BLE001 — report must still render
        log.debug("report assessment context loop failed: %s", exc)
    return None


def case_assessment(clusters: list[list[dict[str, Any]]],
                    analyses: dict[int, dict[str, Any]],
                    rows_for: dict[int, list[dict[str, str]]],
                    model=None, steer: str = "",
                    case_dir: Path | None = None) -> dict[str, Any]:
    """Case-level theory: sequence, scope, confidence, gaps, next steps."""
    if not clusters:
        return {}
    # Deterministic skeleton — always present even when the LLM is not.
    cats = [a.get("category", "other") for a in analyses.values()]
    fams = sorted({
        str(r.get("source") or "").split("/")[0]
        for rows in rows_for.values() for r in rows
        if r.get("source")
    })
    all_times = _real_times([r for rows in rows_for.values() for r in rows])
    base = {
        "sequence": "",
        "scope": (f"{len(clusters)} signal cluster(s) across "
                  f"{', '.join(fams) or 'unknown families'}"
                  + (f", {all_times[0]} → {all_times[-1]}"
                     if all_times else "")),
        "confidence": "",
        "gaps": [],
        "recommended": [],
        "categories": cats,
        "source": "heuristic",
    }
    if model is None:
        return base
    # Compact per-cluster brief for the assessment call.
    briefs: list[str] = []
    for i, cluster in enumerate(clusters):
        a = analyses.get(i) or {}
        rows = rows_for.get(i, [])
        times = sorted(str(r.get("time") or "") for r in rows if r.get("time"))
        briefs.append(
            f"#{i}: {a.get('category','other')} | sev "
            f"{cluster[0].get('severity','?')} | {len(cluster)} finding(s), "
            f"{len(rows)} rows"
            + (f" | {times[0]}..{times[-1]}" if times else "")
            + f" | {a.get('what','')[:160]}"
        )
    user_msg = (
        "Cluster reads:\n" + "\n".join(briefs[:24])
        + (f"\n\nExaminer steering — shape the assessment around this "
           f"direction (facts still only from the reads): {steer[:400]}"
           if steer.strip() else "")
        + "\n\nReturn JSON only."
    )
    if case_dir is not None:
        loop_parsed = _assessment_with_loop(user_msg, model, Path(case_dir))
        if loop_parsed is not None:
            return _merge_assessment(base, loop_parsed)
    try:
        resp = model.invoke([
            {"role": "system", "content": _ASSESS_SYSTEM},
            {"role": "user", "content": user_msg},
        ])
        text = getattr(resp, "content", str(resp))
        from nexus.modes.llm_desk import _parse_json_response

        parsed = _parse_json_response(text)
        if not isinstance(parsed, dict):
            return base
        return _merge_assessment(base, parsed)
    except Exception as exc:  # noqa: BLE001
        log.warning("case assessment LLM failed: %s", exc)
    return base


def render_analysis_block(a: dict[str, Any]) -> list[str]:
    """Markdown lines for one cluster's analyst read."""
    if not a:
        return []
    label = "LLM-assisted" if str(a.get("source") or "").startswith("llm") else "deterministic"
    out = [f"**Analyst read** _({label} — verify against evidence rows; "
           "not examiner-approved)_", ""]
    if a.get("category"):
        out.append(f"- **Category:** `{a['category']}`")
    for key, head in (("what", "What"), ("why", "Why it matters"),
                      ("how", "How"), ("who_when", "Who / when")):
        if a.get(key):
            out.append(f"- **{head}:** {a[key]}")
    if a.get("verify"):
        out.append("- **Verify next:**")
        out.extend(f"  - {v}" for v in a["verify"])
    if a.get("caveats"):
        out.append("- **Caveats:**")
        out.extend(f"  - {v}" for v in a["caveats"])
    out.append("")
    return out


def render_assessment(assess: dict[str, Any]) -> list[str]:
    """Markdown lines for the case-level assessment."""
    if not assess:
        return []
    label = "LLM-assisted" if str(assess.get("source") or "").startswith("llm") else "deterministic"
    out = ["## Assessment", "",
           f"_({label} theory-building aid — the examiner decides; nothing "
           "here is an approved conclusion.)_", ""]
    if assess.get("sequence"):
        out += ["**Probable sequence**", "", assess["sequence"], ""]
    if assess.get("scope"):
        out.append(f"- **Scope:** {assess['scope']}")
    if assess.get("confidence"):
        out.append(f"- **Confidence:** {assess['confidence']}")
    if assess.get("categories"):
        cats = ", ".join(f"`{c}`" for c in
                         dict.fromkeys(assess["categories"]))
        out.append(f"- **Categories:** {cats}")
    if assess.get("gaps"):
        out.append("- **Gaps:**")
        out.extend(f"  - {g}" for g in assess["gaps"])
    if assess.get("recommended"):
        out.append("- **Recommended next steps:**")
        out.extend(f"  - {r}" for r in assess["recommended"])
    out.append("")
    return out
