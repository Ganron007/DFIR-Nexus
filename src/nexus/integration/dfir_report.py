"""DFIR Report-style narrative IR export.

Structure mirrors public intrusion write-ups (Key Takeaways → Case Summary →
tactic sections → Timeline → Indicators → Detections → MITRE ATT&CK), in the
spirit of https://thedfirreport.com/reports/ — lab-scoped and evidence-backed.
"""

from __future__ import annotations

import re
from ast import literal_eval
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any


def _format_rag_notes(rag_notes: list[str]) -> list[str]:
    """Turn RAG warmup blobs into examiner-readable bullets."""
    out: list[str] = []
    for note in rag_notes or []:
        text = str(note).strip()
        if not text:
            continue
        if text.startswith("RAG ready"):
            out.append(text)
            continue
        parsed = None
        if text.startswith("[") or text.startswith("{"):
            try:
                parsed = literal_eval(text)
            except (ValueError, SyntaxError):
                parsed = None
        hits = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else None)
        if hits:
            for hit in hits[:5]:
                if not isinstance(hit, dict):
                    continue
                title = hit.get("title") or hit.get("source") or "RAG hit"
                score = hit.get("score")
                src = hit.get("source") or ""
                extra = f" (score {score:.3f})" if isinstance(score, (int, float)) else ""
                src_bit = f" — {src}" if src else ""
                out.append(f"{title}{extra}{src_bit}")
            continue
        out.append(text[:400])
    return out


def _split_questions(text: str) -> list[str]:
    raw = (text or "").strip()
    if not raw:
        return []
    parts = re.split(r"\?\s*|;\s*|\band what\b|\band\b(?=\s+what\b)", raw, flags=re.I)
    out = []
    for p in parts:
        q = re.sub(r"\s+", " ", p).strip(" .,;?")
        if len(q) >= 12:
            if not re.match(r"^(what|how|does|is|are|which)\b", q, re.I):
                q = "What " + q[0].lower() + q[1:]
            out.append(q + "?")
    return out[:6] or [raw if raw.endswith("?") else raw.rstrip(" .,;") + "?"]


def build_qa_spine(
    questions: list[str],
    findings: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """N8: each N1 question is answered from findings or INSUFFICIENT."""
    rows: list[dict[str, str]] = []

    def _blob(f: dict[str, Any]) -> str:
        return " ".join(
            str(f.get(k) or "") for k in ("title", "observation", "description", "interpretation")
        ).lower()

    def _negative(f: dict[str, Any]) -> bool:
        b = _blob(f)
        if any(w in b for w in (
            "no host", "insufficient", "does not support", "not support",
            "no query pack", "does not corroborate", "no malicious",
            "lack intrusion", "not supported by the evidence",
            "do not include indicators of malware",
            "no malware", "no c2", "no beacon", "no intrusion",
            "no mimikatz", "no cobalt",
            "does not show remote", "do not show remote",
        )):
            return True
        return bool(re.search(
            r"\bno\s+(?:host|malware|c2|beacon|intrusion|mimikatz|cobalt)\b",
            b,
        ))

    for q in questions:
        low = q.lower()
        keys = []
        if any(w in low for w in ("insider", "staging", "misuse", "wipe", "pst", "exfil")):
            keys = ["sdelete", "pst", "recycle", "drive", "staging"]
        elif any(w in low for w in ("external", "compromise", "c2", "malware", "intrusion")):
            # Dual-lens prose uses "C2" / "external" while refuting them — do not
            # treat those words as positive intrusion evidence.
            keys = ["mimikatz", "rubeus", "cobalt", "beacon", "psexec", "encodedcommand"]
        else:
            keys = [t for t in re.findall(r"[a-z0-9]{4,}", low) if t not in {
                "what", "host", "activity", "supports", "refutes", "with", "from",
            }][:6]
        external_q = any(w in low for w in ("external", "compromise", "c2", "malware", "intrusion"))
        matched: list[str] = []
        cited = ""
        for f in findings:
            b = _blob(f)
            hits = [k for k in keys if k in b]
            # Refute/absence prose must not count as intrusion evidence.
            # Do not skip the same row for insider keys (sdelete/PST/Drive).
            if external_q and _negative(f):
                if not cited:
                    cited = str(f.get("id") or f.get("title") or "")
                continue
            if not hits:
                continue
            matched.extend(hits)
            if not cited:
                cited = str(f.get("id") or f.get("title") or "")
        matched = list(dict.fromkeys(matched))
        if external_q and not matched:
            rows.append({
                "question": q,
                "answer": "INSUFFICIENT — approved findings do not corroborate this on host artifacts.",
                "cite": cited,
            })
        elif matched:
            rows.append({
                "question": q,
                "answer": f"Supported by approved findings (terms: {', '.join(matched)}).",
                "cite": cited,
            })
        else:
            rows.append({
                "question": q,
                "answer": "INSUFFICIENT — no approved finding rows matched this question.",
                "cite": "",
            })
    return rows


def _sev_rank(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    return order.get((sev or "").lower(), 9)


def build_dfir_markdown(
    *,
    case_id: str,
    case_name: str,
    findings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    timeline: list[dict[str, Any]] | None = None,
    iocs: dict[str, list] | None = None,
    detections: list[dict[str, Any]] | None = None,
    sift_notes: list[str] | None = None,
    rag_notes: list[str] | None = None,
    examiner: str = "",
    status: str = "open",
    severity: str = "high",
    case_summary: str = "",
    tool_ledger: list[dict[str, Any]] | None = None,
    finding_ids: list[str] | None = None,
    questions: list[str] | None = None,
) -> str:
    """Render a detailed DFIR-style Markdown report from approved case data."""
    if finding_ids:
        want = set(finding_ids)
        findings = [f for f in findings if f.get("id") in want]
    approved = [
        f for f in findings
        if str(f.get("status") or f.get("approval_state") or "").upper() in ("APPROVED",)
    ]
    approved.sort(key=lambda f: (_sev_rank(str(f.get("severity", ""))), f.get("title", "")))

    mitre: dict[str, list[str]] = defaultdict(list)
    for f in approved:
        tids = f.get("mitre_ids") or f.get("attack_ids") or f.get("technique_ids") or []
        for tech in f.get("mitre_techniques") or []:
            if isinstance(tech, str):
                tids = list(tids) + [tech]
            elif isinstance(tech, dict) and tech.get("id"):
                tids = list(tids) + [tech["id"]]
        for tid in tids:
            tid = str(tid).strip().upper()
            if tid.startswith("T"):
                mitre[tid].append(f.get("id", "?"))

    # Collect IOCs from evidence metadata + explicit iocs
    ip_set: set[str] = set()
    host_set: set[str] = set()
    hash_set: set[str] = set()
    for ev in evidence:
        for k in ("dest_ip", "source_ip"):
            if ev.get(k):
                ip_set.add(str(ev[k]))
        if ev.get("host"):
            host_set.add(str(ev["host"]))
        if ev.get("sha256"):
            hash_set.add(str(ev["sha256"]))
        meta = ev.get("metadata") or {}
        if isinstance(meta, dict):
            for k in ("dest_ip", "source_ip"):
                if meta.get(k):
                    ip_set.add(str(meta[k]))
            if meta.get("host"):
                host_set.add(str(meta["host"]))
    if iocs:
        for item in iocs.get("ip") or []:
            val = item.get("value") if isinstance(item, dict) else item
            if val:
                ip_set.add(str(val))
        for item in iocs.get("host") or []:
            val = item.get("value") if isinstance(item, dict) else item
            if val:
                host_set.add(str(val))
        for item in iocs.get("hash") or []:
            val = item.get("value") if isinstance(item, dict) else item
            if val:
                hash_set.add(str(val))

    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []
    lines.append(f"# {case_name}")
    lines.append("")
    lines.append(f"**Case ID:** `{case_id}`  ")
    lines.append(f"**Status:** {status} · **Severity:** {severity}  ")
    if examiner:
        lines.append(f"**Examiner:** {examiner}  ")
    lines.append(f"**Generated:** {generated}  ")
    lines.append("")
    lines.append(
        "> Lab IR report from **APPROVED** findings (template, not an LLM file). "
        "Key takeaways, "
        "case summary, evidence-backed sections, timeline, indicators, detections, MITRE."
    )
    lines.append("")

    # Key Takeaways
    lines.append("## Key Takeaways")
    lines.append("")
    if not approved:
        lines.append("- No APPROVED findings yet — examiner HITL gate not complete.")
    else:
        for f in approved[:8]:
            title = f.get("title") or "Untitled finding"
            sev = f.get("severity") or "?"
            lines.append(f"- **[{sev}]** {title}")
        lines.append(
            f"- Investigation registered **{len(evidence)}** evidence items and "
            f"**{len(approved)}** approved findings with HMAC chain-of-custody."
        )
        if sift_notes:
            lines.append(
                "- Supporting tool notes attached "
                f"({len(sift_notes)})."
            )
    lines.append("")

    # N8 Q&A spine
    qs = list(questions or [])
    if qs:
        lines.append("## Examiner questions")
        lines.append("")
        for row in build_qa_spine(qs, approved):
            lines.append(f"- **Q:** {row['question']}")
            cite = f" (`{row['cite']}`)" if row.get("cite") else ""
            lines.append(f"  - **A:** {row['answer']}{cite}")
        lines.append("")

    # Case Summary
    lines.append("## Case Summary")
    lines.append("")
    if case_summary.strip():
        lines.append(case_summary.strip())
    else:
        host_preview = ", ".join(sorted(host_set)[:8])
        lines.append(
            f"This investigation (`{case_id}` / `{case_name}`) is scoped to the "
            "evidence registered for this case. "
            + (
                f"Observed hosts include: {host_preview}. "
                if host_preview
                else "No host identifiers were present in the evidence registry. "
            )
            + "Findings below were staged from MCP tool outputs (with audit_ids) "
            "and approved by the examiner. Do not treat this paragraph as "
            "environment-specific narrative when case_summary was not provided."
        )
    lines.append("")
    lines.append(
        f"Evidence registry size: **{len(evidence)}** items "
        f"(paths/hashes listed in Evidence Registry)."
    )
    lines.append("")

    # Analysts
    lines.append("## Analysts")
    lines.append("")
    lines.append(f"Analysis and reporting: `{examiner or 'examiner'}` (DFIR-Nexus automated + HITL).")
    lines.append("")

    # Table of Contents
    lines.append("#### Table of Contents")
    lines.append("")
    for item in (
        "Key Takeaways",
        "Examiner questions",
        "Case Summary",
        "Findings (Evidence-Backed)",
        "Network",
        "Endpoint / Memory",
        "Timeline / Host",
        "SIFT Linux Tooling",
        "Knowledge / Detection Assist",
        "Timeline",
        "Indicators",
        "Detections",
        "MITRE ATT&CK",
        "Insider Threat Matrix",
        "Evidence Registry",
    ):
        lines.append(f"- {item}")
    lines.append("")

    # Findings detail
    lines.append("## Findings (Evidence-Backed)")
    lines.append("")
    if not approved:
        lines.append("_No approved findings._")
        lines.append("")
    for f in approved:
        lines.append(f"### {f.get('title', 'Untitled')}")
        lines.append("")
        lines.append(f"- **ID:** `{f.get('id')}`")
        lines.append(f"- **Severity:** {f.get('severity')}")
        if f.get("approved_by"):
            lines.append(f"- **Approved by:** {f.get('approved_by')}")
        tids = f.get("mitre_ids") or f.get("attack_ids") or f.get("technique_ids") or []
        if tids:
            lines.append(f"- **MITRE:** {', '.join(str(t) for t in tids)}")
        lines.append("")
        obs = str(f.get("observation") or f.get("description") or "").strip()
        interp = str(f.get("interpretation") or "").strip()
        from nexus.integration.evidence_table import (
            normalize_evidence_rows,
            render_evidence_table,
        )

        rows = normalize_evidence_rows(f)
        lines.append("**Evidence**")
        lines.append("")
        if rows:
            lines.extend(render_evidence_table(rows))
        elif obs:
            lines.append(obs)
            lines.append("")
        if interp and interp != obs:
            lines.append("**Interpretation**")
            lines.append("")
            lines.append(interp)
            lines.append("")
        elif not obs and not rows and interp:
            lines.append(interp)
            lines.append("")

    # Tactic-ish sections derived from finding titles/sources
    def _section(title: str, predicate) -> None:
        matched = [f for f in approved if predicate(f)]
        lines.append(f"## {title}")
        lines.append("")
        if not matched:
            lines.append("_No approved findings mapped to this section for this case._")
            lines.append("")
            return
        for f in matched:
            lines.append(f"- **{f.get('title')}** (`{f.get('id')}`)")
            interp = (f.get("interpretation") or "").strip().split("\n")[0].strip()
            if interp:
                lines.append(f"  - {interp[:280]}")
        lines.append("")

    _section(
        "Network",
        lambda f: "network" in (f.get("title") or "").lower()
        or "onedrive" in (f.get("title") or "").lower()
        or "cloud" in (f.get("title") or "").lower()
        or "ntlm" in (f.get("title") or "").lower()
        or any(
            str(t).startswith(("T1071", "T1021", "T1567", "T1110", "T1087"))
            for t in (f.get("mitre_ids") or f.get("attack_ids") or f.get("technique_ids") or [])
        ),
    )
    _section(
        "Endpoint / Memory",
        lambda f: "process" in (f.get("title") or "").lower()
        or "endpoint" in (f.get("title") or "").lower()
        or "prefetch" in (f.get("title") or "").lower()
        or "temp-directory" in (f.get("title") or "").lower()
        or "bits" in (f.get("title") or "").lower()
        or any(
            str(t).startswith(("T1547", "T1055", "T1105", "T1197"))
            for t in (f.get("mitre_ids") or f.get("attack_ids") or f.get("technique_ids") or [])
        ),
    )
    _section(
        "Timeline / Host",
        lambda f: "timeline" in (f.get("title") or "").lower()
        or "cluster" in (f.get("title") or "").lower()
        or "removable" in (f.get("title") or "").lower()
        or "recent document" in (f.get("title") or "").lower()
        or "email" in (f.get("title") or "").lower()
        or any(
            str(t).startswith(("T1074", "T1025"))
            for t in (f.get("mitre_ids") or f.get("attack_ids") or f.get("technique_ids") or [])
        ),
    )

    # SIFT
    lines.append("## SIFT Linux Tooling")
    lines.append("")
    if sift_notes:
        lines.append(
            "The Linux tool host (SIFT) was used for supporting analysis on this case:"
        )
        lines.append("")
        for note in sift_notes:
            lines.append(f"- {note}")
    else:
        lines.append(
            "_No SIFT tool notes attached. Linux ingest may still have run on the "
            "Windows examiner host from staged `Evidence-files/03-linux/`._"
        )
    lines.append("")

    # RAG / detection assist
    lines.append("## Knowledge / Detection Assist")
    lines.append("")
    if rag_notes:
        for note in _format_rag_notes(list(rag_notes)):
            lines.append(f"- {note}")
    else:
        lines.append("- RAG / detection assist notes not attached to this export.")
    if detections:
        lines.append("")
        lines.append("Sample Sigma / detection hits consulted during analysis:")
        lines.append("")
        for d in detections[:15]:
            title = d.get("title") or d.get("id") or str(d)
            tids = d.get("technique_ids") or []
            extra = f" ({', '.join(tids[:3])})" if tids else ""
            lines.append(f"- {title}{extra}")
    lines.append("")

    # Timeline
    lines.append("## Timeline")
    lines.append("")
    events = list(timeline or [])
    events.sort(key=lambda e: str(e.get("timestamp") or ""))
    if not events:
        lines.append("_No timeline events recorded._")
    else:
        lines.append("| Timestamp | Host | Description | Source |")
        lines.append("|-----------|------|-------------|--------|")
        for e in events[:80]:
            ts = str(e.get("timestamp") or "")[:25]
            host = str(e.get("host") or "").replace("|", "/")
            desc = str(e.get("description") or "").replace("|", "/")[:120]
            src = str(e.get("source") or "").replace("|", "/")
            lines.append(f"| {ts} | {host} | {desc} | {src} |")
        if len(events) > 80:
            lines.append("")
            lines.append(f"_… {len(events) - 80} additional timeline rows omitted._")
        i1_events = [
            e for e in events
            if str(e.get("source") or "").lower().startswith("i1")
        ]
        if i1_events:
            lines.append("")
            lines.append("### Import/ingest (I1)")
            lines.append("")
            lines.append("| Timestamp | Description | Source |")
            lines.append("|-----------|-------------|--------|")
            for e in i1_events[:40]:
                ts = str(e.get("timestamp") or "")[:25]
                desc = str(e.get("description") or "").replace("|", "/")[:120]
                src = str(e.get("source") or "").replace("|", "/")
                lines.append(f"| {ts} | {desc} | {src} |")
    lines.append("")

    # Indicators
    lines.append("## Indicators")
    lines.append("")
    lines.append("### Network")
    lines.append("")
    if ip_set:
        for ip in sorted(ip_set)[:50]:
            lines.append(f"- `{ip}`")
    else:
        lines.append("- _None extracted._")
    lines.append("")
    lines.append("### Hosts")
    lines.append("")
    if host_set:
        for h in sorted(host_set)[:50]:
            lines.append(f"- `{h}`")
    else:
        lines.append("- _None extracted._")
    lines.append("")
    lines.append("### Hashes")
    lines.append("")
    if hash_set:
        for h in sorted(hash_set)[:30]:
            lines.append(f"- `{h}`")
    else:
        lines.append("- _None extracted._")
    lines.append("")

    # Detections
    lines.append("## Detections")
    lines.append("")
    lines.append(
        "Detection engineering follow-ups should prioritize the MITRE techniques "
        "and Sigma hits listed below. Deploy/tune rules in the lab SIEM after "
        "examiner validation of the approved findings."
    )
    lines.append("")
    if detections:
        for d in detections[:25]:
            lines.append(f"- {d.get('title') or d.get('id')}")
    else:
        lines.append("- Run `detection_search` against observed techniques for concrete Sigma candidates.")
    lines.append("")

    # MITRE
    lines.append("## MITRE ATT&CK")
    lines.append("")
    if not mitre:
        lines.append("_No techniques on approved findings._")
    else:
        lines.append("| Technique | Findings |")
        lines.append("|-----------|----------|")
        for tid in sorted(mitre):
            lines.append(f"| `{tid}` | {', '.join(sorted(set(mitre[tid])))} |")
    lines.append("")

    lines.append("## Insider Threat Matrix")
    lines.append("")
    lines.append(
        "Findings mapped to the [Insider Threat Matrix](https://insiderthreatmatrix.org/) "
        "(Motive / Means / Preparation / Infringement / Anti-Forensics). "
        "Host artifacts evidence Means and later stages; Motive is inferred only "
        "when later-stage objects are present."
    )
    lines.append("")
    itm_hits = [
        f for f in approved
        if "insider threat matrix" in (
            str(f.get("interpretation") or "") + str(f.get("observation") or "")
        ).lower()
        or f.get("itm_stage")
    ]
    if not itm_hits:
        lines.append("_No explicit ITM mapping on approved findings._")
    else:
        for f in itm_hits:
            lines.append(f"- **{f.get('title')}** (`{f.get('id')}`)")
            interp = str(f.get("interpretation") or "")
            for line in interp.splitlines():
                if "insider threat matrix" in line.lower() or line.strip().startswith("Insider Threat"):
                    lines.append(f"  - {line.strip()}")
                    break
    lines.append("")

    # Evidence registry
    lines.append("## Evidence Registry")
    lines.append("")
    lines.append(f"Registered items: **{len(evidence)}**")
    lines.append("")
    for ev in evidence[:40]:
        name = ev.get("name") or ev.get("description") or ev.get("path") or "evidence"
        lines.append(f"- {name}")
        if ev.get("path"):
            lines.append(f"  - path: `{ev['path']}`")
        if ev.get("sha256"):
            lines.append(f"  - SHA-256: `{ev['sha256']}`")
        extras = []
        for k in ("host", "source_ip", "dest_ip", "process_name"):
            if ev.get(k):
                extras.append(f"{k}={ev[k]}")
        if extras:
            lines.append(f"  - {', '.join(extras)}")
    if len(evidence) > 40:
        lines.append("")
        lines.append(f"_… {len(evidence) - 40} additional evidence rows omitted._")
    lines.append("")

    if tool_ledger:
        lines.append("## Tool-run inventory")
        lines.append("")
        ok_n = sum(1 for r in tool_ledger if r.get("status") == "OK")
        fail_n = sum(1 for r in tool_ledger if r.get("status") == "FAIL")
        skip_n = sum(1 for r in tool_ledger if r.get("status") == "SKIP")
        lines.append(
            f"**{ok_n} OK** · **{fail_n} FAIL** · **{skip_n} SKIP** "
            f"(total {len(tool_ledger)}). Every OK extraction was available to "
            "the interpretation agent (see `analysis/query_pack.md`)."
        )
        lines.append("")
        lines.append("| Host | Tool | Status | Purpose | audit_id |")
        lines.append("|---|---|---|---|---|")
        for row in tool_ledger:
            lines.append(
                "| {host} | {tool} | {status} | {purpose} | `{aid}` |".format(
                    host=row.get("host") or "",
                    tool=row.get("tool") or "",
                    status=row.get("status") or "",
                    purpose=(row.get("purpose") or "").replace("|", "/")[:80],
                    aid=(row.get("audit_id") or row.get("reason") or "")[:48],
                )
            )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_Only APPROVED findings are included. DRAFT/REJECTED omitted by HITL design. "
        "This is a lab report — not a public attribution claim._"
    )
    lines.append("")
    return "\n".join(lines)
