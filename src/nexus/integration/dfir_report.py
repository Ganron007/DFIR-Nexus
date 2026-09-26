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
from pathlib import Path
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
        elif any(w in low for w in (
            "external", "compromise", "c2", "malware", "intrusion", "attacker",
        )):
            # Host-artifact evidence can support an intrusion/attacker-activity
            # question. Dual-lens prose using "C2" to refute still uses _negative.
            keys = [
                "mimikatz", "rubeus", "cobalt", "beacon", "psexec", "psexesvc",
                "encodedcommand", "wevtutil", "1102", "overwrite", "usn",
                "rundll32", "mshta", "lsass", "schtasks", "persistence",
                "autorun", "wacsvc",
            ]
        else:
            keys = [t for t in re.findall(r"[a-z0-9]{4,}", low) if t not in {
                "what", "host", "activity", "supports", "refutes", "with", "from",
            }][:6]
        external_q = any(w in low for w in (
            "external", "compromise", "c2", "malware", "intrusion", "attacker",
        ))
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
                "answer": f"Supported by findings (terms: {', '.join(matched)}).",
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


def _finding_locs(f: dict[str, Any]) -> set[str]:
    """file:line provenance keys on a finding's evidence rows.

    Uncapped — cluster fusion must see the full evidence set; the 12-row
    display cap made genuinely-overlapping findings look disjoint.
    """
    from nexus.integration.evidence_table import normalize_evidence_rows

    return {
        str(r.get("loc") or "")
        for r in normalize_evidence_rows(f, limit=None)
        if str(r.get("loc") or "").strip()
    }


_PLACEHOLDER_INTERP = re.compile(
    r"matched \d+ row\(s\).*pending examiner review|"
    r"pending interpretation\.",
    re.I | re.S,
)


def _rehydrate_finding(f: dict[str, Any], case_dir) -> dict[str, Any]:
    """Backfill legacy findings staged before parsed evidence rows existed.

    Older DRAFT/APPROVED findings store only the raw CSV row as ``detail``
    with no ``fields`` and no ``loc``. At report time we re-parse the row
    against the source file's header (salient columns render), recover the
    true ``file:line`` by matching the row back into the artifact (same-event
    clustering keys), and regenerate placeholder interpretations through the
    same ``_heuristic_scribe`` path new drafts use.
    """
    ev = f.get("evidence")
    if not isinstance(ev, list):
        return f
    interp = str(f.get("interpretation") or "")
    needs_interp = not interp.strip() or bool(_PLACEHOLDER_INTERP.search(interp))
    legacy_idx = [
        i for i, r in enumerate(ev)
        if isinstance(r, dict)
        and not r.get("fields")
        and str(r.get("detail") or "").strip()
        and str(r.get("artifact") or "").strip()
        and str(r.get("artifact") or "") != "—"
    ]
    if not needs_interp and not legacy_idx:
        return f
    out = dict(f)
    new_ev = [dict(r) if isinstance(r, dict) else r for r in ev]

    attached: list[dict[str, Any]] = []
    raw_texts: list[str] = []
    if legacy_idx or needs_interp:
        pseudo = [
            {
                "file": str(ev[i].get("artifact") or ""),
                "text": str(ev[i].get("detail") or ""),
                "family": str(ev[i].get("source") or "").split("/")[0],
            }
            for i in legacy_idx
        ]
        raw_texts = [p["text"] for p in pseudo]
        try:
            from nexus.langgraph.query_pack import attach_hit_fields

            attached = attach_hit_fields(case_dir, pseudo)
        except Exception:
            attached = []

    if attached:
        from nexus.integration.evidence_table import render_hit_fields

        for idx, ph in zip(legacy_idx, attached, strict=False):
            r = new_ev[idx]
            if ph.get("fields"):
                r["fields"] = ph["fields"]
                rendered = render_hit_fields(ph["fields"])
                if rendered:
                    r["detail"] = rendered[:500]
            if ph.get("host") and not r.get("host"):
                r["host"] = ph["host"]

        # Recover file:line — match the stored raw row back into the artifact.
        # Detail may have been truncated at staging, so prefix-match.
        try:
            from nexus.langgraph.pipeline_runs import resolve_tools_extractions

            root = resolve_tools_extractions(case_dir)
            by_file: dict[str, list[str]] = {}
            for idx, raw in zip(legacy_idx, raw_texts, strict=False):
                r = new_ev[idx]
                if str(r.get("loc") or "").strip():
                    continue
                rel = str(r.get("artifact") or "")
                p = root / rel if rel else None
                if not (p is not None and p.is_file()):
                    continue
                if rel not in by_file:
                    try:
                        by_file[rel] = p.read_text(
                            encoding="utf-8", errors="replace",
                        ).splitlines()
                    except OSError:
                        by_file[rel] = []
                needle = raw.strip()[:160]
                loc = ""
                if needle:
                    for ln, file_line in enumerate(by_file[rel], 1):
                        if needle in file_line:
                            loc = f"{rel}:{ln}"
                            break
                if not loc:
                    t = str(r.get("time") or "").strip()
                    loc = f"{rel}@{t}" if t and t != "—" else rel
                r["loc"] = loc
        except Exception:
            pass

    out["evidence"] = new_ev

    # Regenerate placeholder interpretation + missing severity/techniques via
    # the same heuristic scribe new drafts run — report-layer only, the stored
    # finding record is untouched.
    if needs_interp:
        interp_hits = attached or [
            {
                "family": str(r.get("source") or "").split("/")[0],
                "text": str(r.get("detail") or ""),
                "fields": r.get("fields") or {},
                "file": str(r.get("artifact") or ""),
            }
            for r in new_ev
            if isinstance(r, dict)
        ][:12]
        if interp_hits:
            try:
                from nexus.modes.llm_desk import _heuristic_scribe

                rescribed = _heuristic_scribe(dict(f), interp_hits, case_dir)
                new_interp = str(rescribed.get("interpretation") or "").strip()
                if new_interp and not _PLACEHOLDER_INTERP.search(new_interp):
                    out["interpretation"] = new_interp
                if not out.get("severity") and rescribed.get("severity"):
                    out["severity"] = rescribed["severity"]
                if not (out.get("technique_ids") or out.get("attack_ids")) and rescribed.get("technique_ids"):
                    out["technique_ids"] = rescribed["technique_ids"]
            except Exception:
                pass
    return out


_SIGNAL_TITLE = re.compile(r"^Signal:\s*(.+?)\s*—\s*\d+\s*hit", re.I)


def _finding_dedupe_key(f: dict[str, Any]) -> str:
    """Same signal = same finding regardless of re-run hit counts.

    'Signal: mshta — 39 hit(s) across …' → 'signal:mshta'. Non-signal
    titles key on normalized text.
    """
    title = str(f.get("title") or "")
    m = _SIGNAL_TITLE.search(title)
    if m:
        return f"signal:{m.group(1).strip().lower()}"
    return f"title:{' '.join(title.lower().split())[:100]}"


def _merge_duplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse findings staged more than once for the same signal.

    A full-run re-executed after approval staged F-009…F-016 as literal
    copies of F-001…F-008 — same needle, same evidence. The report shows
    one logical finding citing every ID instead of rendering the chain
    twice. Merged members keep the highest severity and union their
    evidence rows (deduped on file:line).
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for f in findings:
        key = _finding_dedupe_key(f)
        if key not in groups:
            order.append(key)
        groups.setdefault(key, []).append(f)

    out: list[dict[str, Any]] = []
    for key in order:
        members = groups[key]
        if len(members) == 1:
            out.append(members[0])
            continue
        base = dict(min(members, key=lambda f: _sev_rank(str(f.get("severity") or ""))))
        base["id"] = members[0].get("id")
        base["merged_ids"] = [str(f.get("id")) for f in members if f.get("id")]
        ev_seen: set[str] = set()
        merged_ev: list[Any] = []
        for f in members:
            for item in (f.get("evidence") or []):
                if not isinstance(item, dict):
                    merged_ev.append(item)
                    continue
                k = str(item.get("loc") or "") or str(item.get("detail") or "")[:140]
                if k in ev_seen:
                    continue
                ev_seen.add(k)
                merged_ev.append(item)
        base["evidence"] = merged_ev
        tids = sorted({
            str(t)
            for f in members
            for t in (f.get("mitre_ids") or f.get("attack_ids")
                      or f.get("technique_ids") or [])
        })
        if tids:
            base["technique_ids"] = tids
        interp = next(
            (str(f.get("interpretation") or "").strip() for f in members
             if str(f.get("interpretation") or "").strip()
             and not _PLACEHOLDER_INTERP.search(str(f.get("interpretation") or ""))),
            "",
        )
        if interp:
            base["interpretation"] = interp
        out.append(base)
    return out


def _cluster_findings(findings: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group findings that share ≥50% of the smaller evidence set.

    Distinct needles routinely match the same attack rows (mshta vs
    mshta.exe vs rundll32 pivoting the same Sysmon events) — they are one
    chain, not four findings. Union-find over pairwise overlap.
    """
    locs = [_finding_locs(f) for f in findings]
    parent = list(range(len(findings)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            a, b = locs[i], locs[j]
            if not a or not b:
                continue
            shared = len(a & b)
            if shared and shared / min(len(a), len(b)) >= 0.5:
                pi, pj = find(i), find(j)
                if pi != pj:
                    parent[pj] = pi

    groups: dict[int, list[dict[str, Any]]] = {}
    for i, f in enumerate(findings):
        groups.setdefault(find(i), []).append(f)
    return list(groups.values())


def dated_timeline(events: list[dict[str, Any]] | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split N7 events into timestamped chronology vs untimed keyword hits."""
    dated: list[dict[str, Any]] = []
    untimed: list[dict[str, Any]] = []
    for e in events or []:
        src = str(e.get("source") or "").lower()
        desc = str(e.get("description") or "")
        if src.startswith("i1:generic") or desc.startswith("Generic JSONL"):
            continue
        if str(e.get("timestamp") or "").strip():
            dated.append(e)
        else:
            untimed.append(e)
    dated.sort(key=lambda e: str(e.get("timestamp") or ""))
    return dated, untimed


def sift_notes_from_ledger(ledger: list[dict[str, Any]] | None) -> list[str]:
    """SIFT section = tools that ran on a Linux tool host, not extraction listings."""
    notes: list[str] = []
    for row in ledger or []:
        host = str(row.get("host") or "").lower()
        if "sift" not in host and host not in {"linux", "remnux"}:
            continue
        tool = row.get("tool") or "?"
        status = row.get("status") or "?"
        purpose = (row.get("purpose") or "").strip()
        bit = f"`{tool}` {status}"
        if purpose:
            bit += f" — {purpose[:120]}"
        notes.append(bit)
        if len(notes) >= 40:
            break
    return notes


_TL_DETECTIONS = re.compile(r"detections:\s*(.+)", re.I)
_TL_RULETITLE = re.compile(r"RuleTitle:\s*([^·|]+)", re.I)
_TL_DETAILS = re.compile(r"Details:\s*(.+)", re.I)
_TL_MAPDESC = re.compile(r"MapDescription:\s*([^·|]+)", re.I)
_TL_USERNAME = re.compile(r"UserName:\s*([^·|]+)", re.I)
_TL_HITLOC = re.compile(r"^\S+\s+\[\]:\s+(\S+:\d+)")
_TL_RAWCSV = re.compile(r"^\d+,")
_TL_TS_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:[+-]\d{2}:?\d{2})?,\"?")
_TL_CMDLINE = re.compile(r"Cmdline:\s*(.+)", re.I)


def _det_list(text: str) -> str:
    """First two detection names from a semicolon list."""
    dets = [d.strip().strip('"') for d in text.split(";") if d.strip()]
    if not dets:
        return ""
    return "; ".join(dets[:2])[:110] + ("…" if len(dets) > 2 else "")


def _timeline_label(e: dict[str, Any]) -> str:
    """Salient one-line label for a timeline event — what an examiner
    scans, not the raw parser row. Priority: detection names → rule
    title+details → map description → hit location → 'event record'."""
    desc = " ".join(str(e.get("description") or "").split())
    if not desc:
        return "event"
    m = _TL_DETECTIONS.search(desc)
    if m:
        label = _det_list(m.group(1))
        if label:
            return label
    m = _TL_RULETITLE.search(desc)
    if m:
        title = m.group(1).strip()
        det = _TL_DETAILS.search(desc)
        d = det.group(1).strip()[:80] if det else ""
        return f"{title} — {d}"[:110] if d else title[:110]
    m = _TL_MAPDESC.search(desc)
    if m:
        user = _TL_USERNAME.search(desc)
        u = f" ({user.group(1).strip()})" if user else ""
        return f"{m.group(1).strip()}{u}"[:110]
    m = _TL_HITLOC.match(desc)
    if m:
        return f"hit {m.group(1)}"
    # Timestamp-prefixed detection list: '2019-05-21T15:32:57.2+00:00,Hacktool - X;Y;Z'
    m = _TL_TS_PREFIX.match(desc)
    if m:
        rest = desc[m.end():]
        if ";" in rest:
            label = _det_list(rest)
            if label:
                return label
    # Quoted CSV row: '"ts","RuleTitle","level","host","chan",eid,"Cmdline: x"'
    if desc.startswith('"') and '","' in desc:
        cols = [c.strip('" ') for c in desc.split('","')]
        title = cols[1] if len(cols) > 1 else ""
        cmd = _TL_CMDLINE.search(desc)
        c = cmd.group(1).strip().strip('"')[:80] if cmd else ""
        if title and c:
            return f"{title} — {c}"[:110]
        if title:
            return title[:110]
    if _TL_RAWCSV.match(desc) and desc.count(",") >= 4:
        # Unparsed CSV row — e.g. '1,4125,2019-05-21 15:32:57.2,1,Info,…'
        cols = desc.split(",")
        chan = next((c for c in cols if "/" in c or "Sysmon" in c), "")
        eid = cols[3].strip() if len(cols) > 3 else ""
        return f"event record {eid} {chan}".strip()[:110] or "event record"
    return desc[:110]


_IOC_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_IOC_IP = re.compile(r"\b(?!(?:0|127|224|255)\.)\d{1,3}(?:\.\d{1,3}){3}\b")
_IOC_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|"
    r"biz|xyz|top|tk|me|co|uk|de|fr|jp|au|us|club|site|online)\b",
    re.I,
)
_IOC_TASK = re.compile(r"/TN\s+\"?([^\"\s,;]+)", re.I)
_BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "live.com", "msn.com", "office.com",
    "office365.com", "schemas.microsoft.com", "w3.org", "localhost",
}


def _extract_iocs(rows: list[dict[str, str]]) -> dict[str, list[str]]:
    """Pull indicators out of evidence row content — URLs, domains, IPs,
    scheduled-task names, notable host paths. Deterministic extraction;
    the report cites what the rows actually contain."""
    urls: set[str] = set()
    domains: set[str] = set()
    ips: set[str] = set()
    tasks: set[str] = set()
    paths: set[str] = set()
    for r in rows:
        blob = str(r.get("detail") or "")
        for u in _IOC_URL.findall(blob):
            u = u.rstrip(".,;'\"")
            urls.add(u)
            host = u.split("://", 1)[-1].split("/")[0].lower()
            if host and not _IOC_IP.match(host):
                domains.add(host)
        for ip in _IOC_IP.findall(blob):
            if not ip.startswith(("169.254.", "192.168.0.", "10.255.")):
                ips.add(ip)
        for d in _IOC_DOMAIN.findall(blob.lower()):
            if d not in _BENIGN_DOMAINS and not d.endswith(".microsoft.com"):
                domains.add(d)
        for t in _IOC_TASK.findall(blob):
            tasks.add(t.strip())
        for p in re.findall(r"C:\\[^\s\"',;|]+", blob):
            if len(p) < 100 and re.search(
                r"\\(Tasks|Temp|AppData|ProgramData|Users\\Public|"
                r"System32\\(?!drivers)\\[^\\]+$)",
                p,
                re.I,
            ):
                paths.add(p)
    # Truncated fragments: 'https://hoteles' is a cut-off of the full URL —
    # drop any value that is a strict prefix of a longer sibling.
    urls = {
        u for u in urls
        if not any(o != u and o.startswith(u) for o in urls)
    }
    domains = {
        d for d in domains
        if not any(o != d and o.startswith(d) for o in domains)
    }
    return {
        "urls": sorted(urls)[:20],
        "domains": sorted(domains)[:20],
        "ips": sorted(ips)[:20],
        "tasks": sorted(tasks)[:10],
        "paths": sorted(paths)[:15],
    }


def load_case_ledger(case_dir) -> list[dict[str, Any]]:
    import json
    from pathlib import Path

    case_dir = Path(case_dir)
    for lp in (
        case_dir / "extractions" / "_tool_lane_ledger.json",
        case_dir / "ledger" / "_tool_lane_ledger.json",
    ):
        if lp.is_file():
            try:
                raw = json.loads(lp.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(raw, list):
                return raw
    return []


def write_finding_appendices(case_dir: Path, findings: list[dict]) -> list[dict]:
    """Write an exhaustive CSV appendix per APPROVED finding (EH-12).

    The narrative shows sampled rows; the appendix is EVERY row matching the
    finding's cited needles (per family), streamed from the same retrieval
    backends with no result caps. "No direct evidence hits sidelined" is
    enforced here, not by promising the sample was representative.
    Returns [{finding_id, path, rows, needles}] for the report section.
    """
    import csv

    from nexus.langgraph.query_pack import (
        iter_all_hits,
        load_case_intake,
        parse_intake_window,
    )

    case_dir = Path(case_dir)
    out_dir = case_dir / "analysis" / "appendices"
    written: list[dict] = []
    window = parse_intake_window(load_case_intake(case_dir))
    for idx, finding in enumerate(findings or []):
        status = str(
            finding.get("status") or finding.get("approval_state") or ""
        ).upper()
        if status != "APPROVED":
            continue
        evidence = finding.get("evidence") or []
        if not isinstance(evidence, list):
            continue
        needles: list[str] = []
        families: set[str] = set()
        for row in evidence:
            if not isinstance(row, dict):
                continue
            fam = str(row.get("family") or "").strip().lower()
            if fam:
                families.add(fam)
            terms = row.get("terms_list")
            if not isinstance(terms, list):
                terms = [p for p in str(row.get("terms") or "").split(",")]
            for term in terms:
                clean = str(term).strip().lower()
                if clean and clean != "*" and clean not in needles:
                    needles.append(clean)
        if not needles:
            continue
        fid = str(finding.get("id") or f"finding-{idx + 1}")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", fid)[:80]
        path = out_dir / f"{safe}-rows.csv"
        rows_written = 0
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(["family", "file", "line", "terms", "text"])
                for hit in iter_all_hits(
                    case_dir, needles[:40], window, priority_terms=needles[:40],
                ):
                    if families and str(hit.get("family") or "").lower() not in families:
                        continue
                    writer.writerow([
                        hit.get("family", ""), hit.get("file", ""),
                        hit.get("line", ""), hit.get("terms", ""),
                        hit.get("text", ""),
                    ])
                    rows_written += 1
        except Exception:  # noqa: BLE001 — a report must still generate
            continue
        written.append({
            "finding_id": fid,
            "path": f"analysis/appendices/{path.name}",
            "rows": rows_written,
            "needles": needles[:40],
        })
    return written


def _load_saved_answers(case_dir: Any) -> list[dict[str, Any]]:
    """Examiner-saved Mode 1 answers (canonical + legacy file names)."""
    if not case_dir:
        return []
    from nexus.case.saved_answers import load_saved_answers

    return load_saved_answers(case_dir)


def _load_briefing_directions_record(case_dir: Any) -> dict[str, Any]:
    """Raw persisted directions record (source/generated_at/directions)."""
    import json

    if not case_dir:
        return {}
    try:
        loaded = json.loads(
            (Path(case_dir) / "analysis" / "briefing_directions.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _load_briefing_directions(case_dir: Any) -> list[dict[str, Any]]:
    """Persisted LLM briefing directions (analysis/briefing_directions.json)."""
    loaded = _load_briefing_directions_record(case_dir)
    entries = loaded.get("directions") if loaded else []
    return [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []


_ITM_ID_RE = re.compile(r"\bAR[1-5]/(?:MT|ME|PR|IF|AF)\d{3}(?:\.\d{3})?\b", re.IGNORECASE)


def _itm_coverage_lines(findings: list[dict[str, Any]]) -> list[str]:
    """Per-stage ITM coverage + evidenced sections + registry facts (F2).

    Ids are validated against the registry - a finding can never put an
    invented technique id into the report. Absence is stated as absence of
    evidence, not absence of risk (FD-004).
    """
    lines: list[str] = []
    try:
        from nexus.langgraph.itm import itm_index, validate_itm_ids

        index = itm_index()
    except Exception:  # noqa: BLE001 - report must render without the KB
        lines.append("_ITM registry unavailable in this build._")
        return lines

    evidenced: dict[str, list[str]] = {}
    for finding in findings:
        blob = (
            str(finding.get("interpretation") or "")
            + "\n"
            + str(finding.get("observation") or "")
        )
        label = str(finding.get("id") or finding.get("title") or "")[:60]
        for raw in _ITM_ID_RE.findall(blob):
            check = validate_itm_ids("", [raw])
            for canonical in check.get("objects") or []:
                entries = evidenced.setdefault(str(canonical), [])
                if label and label not in entries:
                    entries.append(label)

    stage_total: dict[str, int] = {}
    try:
        from nexus.knowledge.loader import get_itm_registry

        for article in get_itm_registry().get("articles") or []:
            stage = str(article.get("title") or "")
            stage_total[stage] = len(article.get("sections") or [])
    except Exception:  # noqa: BLE001
        stage_total = {}

    stage_evidenced: dict[str, set[str]] = {}
    for section in evidenced:
        info = index.get(section.split("/", 1)[-1].upper())
        if not info:
            continue
        stage_evidenced.setdefault(str(info["stage"]), set()).add(section)

    lines.append("### Stage coverage")
    lines.append("")
    lines.append("| Stage | Evidenced sections | Registry sections |")
    lines.append("|---|---|---|")
    for stage in ("Motive", "Means", "Preparation", "Infringement", "Anti-Forensics"):
        lines.append(
            f"| {stage} | {len(stage_evidenced.get(stage, set()))} "
            f"| {stage_total.get(stage, '-')} |"
        )
    lines.append("")

    if evidenced:
        lines.append("### Evidenced sections")
        lines.append("")
        lines.append("| ITM | Stage | Section | Findings |")
        lines.append("|---|---|---|---|")
        for section in sorted(evidenced):
            info = index.get(section.split("/", 1)[-1].upper()) or {}
            lines.append(
                f"| `{section}` | {info.get('stage') or ''} "
                f"| {info.get('title') or ''} "
                f"| {', '.join(evidenced[section][:3])} |"
            )
        lines.append("")
    else:
        lines.append(
            "_No canonical ITM section ids on findings - no stage is evidenced "
            "by this case's findings. That is absence of evidence, not absence "
            "of risk._"
        )
        lines.append("")

    try:
        from nexus.knowledge.loader import (
            get_atlas_registry,
            get_itm_registry,
            get_mbc_registry,
        )

        itm_counts = get_itm_registry().get("counts") or {}
        atlas_counts = get_atlas_registry().get("counts") or {}
        mbc_counts = get_mbc_registry().get("counts") or {}
        if itm_counts or atlas_counts or mbc_counts:
            lines.append("### Registry facts (analysis knowledge available)")
            lines.append("")
            if itm_counts:
                lines.append(
                    "- **Insider Threat Matrix**: "
                    f"{itm_counts.get('sections', 0)} sections / "
                    f"{itm_counts.get('detections', 0)} detections / "
                    f"{itm_counts.get('preventions', 0)} preventions "
                    f"({itm_counts.get('attack_maps', 0)} ATT&CK maps)"
                )
            if atlas_counts:
                lines.append(
                    "- **MITRE ATLAS** (AI/ML): "
                    f"{atlas_counts.get('techniques', 0)} techniques / "
                    f"{atlas_counts.get('mitigations', 0)} mitigations / "
                    f"{atlas_counts.get('case_studies', 0)} case studies"
                )
            if mbc_counts:
                lines.append(
                    "- **MITRE MBC** (malware): "
                    f"{mbc_counts.get('behaviors', 0)} behaviors / "
                    f"{mbc_counts.get('methods', 0)} methods / "
                    f"{mbc_counts.get('detection_rules', 0)} capa-YARA rules "
                    f"({mbc_counts.get('families', 0)} families)"
                )
            lines.append("")
    except Exception:  # noqa: BLE001
        pass
    return lines


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
    include_draft: bool = False,
    case_dir=None,
    llm: bool = True,
    steer: str = "",
) -> str:
    """Render a detailed DFIR-style Markdown report from case findings.

    Official ``REPORT.md`` uses APPROVED rows only (``include_draft=False``).
    Examiner preview ``REPORT-DRAFT.md`` sets ``include_draft=True``.
    ``case_dir`` enables report-time rehydration of legacy findings (raw-CSV
    evidence rows, placeholder interpretations) — display-layer only.
    ``llm`` enables the N8 analysis layer (per-cluster analyst reads + a
    case assessment) — deterministic category mapping always runs; the LLM
    narrative is labeled and constrained to the evidence rows shown.
    """
    if finding_ids:
        want = set(finding_ids)
        findings = [f for f in findings if f.get("id") in want]
    statuses = ("APPROVED", "DRAFT") if include_draft else ("APPROVED",)
    approved = [
        f for f in findings
        if str(f.get("status") or f.get("approval_state") or "").upper() in statuses
    ]
    if case_dir is not None:
        approved = [_rehydrate_finding(f, case_dir) for f in approved]
    # Re-run duplicates (same signal approved twice) collapse to one logical
    # finding citing every ID — before clustering so copies can't scatter
    # the same evidence across sections.
    approved = _merge_duplicate_findings(approved)
    approved.sort(key=lambda f: (_sev_rank(str(f.get("severity", ""))), f.get("title", "")))

    # Clusters + per-cluster evidence rows, computed once — the render loop
    # and the analysis layer share them. Uncapped: fusion + analysis need
    # the full evidence set; the renderer signature-collapses for display.
    clusters = _cluster_findings(approved)
    from nexus.integration.evidence_table import normalize_evidence_rows

    def _cluster_rows(cluster: list[dict[str, Any]]) -> list[dict[str, str]]:
        seen: set[str] = set()
        merged: list[dict[str, str]] = []
        for f in cluster:
            for r in normalize_evidence_rows(f, limit=None):
                key = str(r.get("loc") or "") or f"{r.get('time')}|{r.get('detail')}"
                if key in seen:
                    continue
                seen.add(key)
                merged.append(r)
        return merged

    rows_for = {i: _cluster_rows(c) for i, c in enumerate(clusters)}

    # N8 analysis layer — per-cluster analyst read + case assessment. The
    # deterministic category map always runs; LLM narrative when configured.
    analyses: dict[int, dict[str, Any]] = {}
    assessment: dict[str, Any] = {}
    llm_ran = False
    if clusters:
        from nexus.langgraph import report_analysis

        model = report_analysis.resolve_model() if llm else None
        analyses = report_analysis.analyze_clusters(
            clusters, rows_for, model, steer=steer, case_dir=case_dir)
        assessment = report_analysis.case_assessment(
            clusters, analyses, rows_for, model, steer=steer, case_dir=case_dir)
        llm_ran = any(a.get("source") == "llm" for a in analyses.values())

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
    banner = (
        "> PREVIEW from **DRAFT** findings. Not HMAC-approved. "
        "Official `REPORT.md` is written after `nexus approve`."
        if include_draft
        else
        "> Lab IR report from **APPROVED** findings — deterministic evidence "
        "tables plus per-section analyst reads."
    )
    if llm_ran:
        banner += (" *Assessment and Analyst read blocks are LLM-assisted — "
                   "verify against the evidence rows; they are not "
                   "examiner-approved conclusions.*")
    lines.append(banner)
    lines.append("")

    # Key Takeaways
    lines.append("## Key Takeaways")
    lines.append("")
    if not approved:
        if include_draft:
            lines.append("- No DRAFT or APPROVED findings staged yet.")
        else:
            lines.append("- No APPROVED findings yet — examiner HITL gate not complete.")
    else:
        for f in approved[:8]:
            title = f.get("title") or "Untitled finding"
            sev = f.get("severity") or "unrated"
            lines.append(f"- **[{sev}]** {title}")
        custody = (
            f"**{len(approved)}** staged DRAFT findings (not HMAC-approved)."
            if include_draft
            else
            f"**{len(approved)}** approved findings with HMAC chain-of-custody."
        )
        lines.append(
            f"- Investigation registered **{len(evidence)}** evidence items and "
            f"{custody}"
        )
        if sift_notes:
            lines.append(
                "- Supporting tool notes attached "
                f"({len(sift_notes)})."
            )
    lines.append("")

    # N8 case assessment — theory of what/why/how/who/when across clusters.
    if assessment:
        from nexus.langgraph.report_analysis import render_assessment

        lines.extend(render_assessment(assessment))

    # Mode 1 LLM directions — the examiner-led starting points, carried into
    # the report as suggested next steps (grounded in the signal map/needle
    # hits; suggestions only, never approved conclusions).
    directions_record = _load_briefing_directions_record(case_dir)
    directions = _load_briefing_directions(case_dir)
    if directions:
        lines.append("## Suggested next steps")
        lines.append("")
        lines.append(
            "_LLM-generated investigation directions grounded in the current "
            "keyword scan and needle-hit signal map — suggestions for the "
            "examiner, not approved conclusions._"
        )
        generated = str(directions_record.get("generated_at") or "").strip()
        source = str(directions_record.get("source") or "llm").strip()
        lines.append(
            f"_Source: {source}"
            + (f" · generated {generated[:19]}" if generated else "")
            + "._"
        )
        lines.append("")
        for direction in directions[:6]:
            title = str(direction.get("title") or "").strip() or "Direction"
            why = str(direction.get("why") or "").strip()
            family = str(direction.get("family") or "").strip()
            needles = [str(n).strip() for n in (direction.get("needles") or []) if str(n).strip()]
            suffix = f" _({family})_" if family else ""
            lines.append(f"- **{title}**{suffix}")
            if why:
                lines.append(f"  - **Why:** {why[:600]}")
            if needles:
                lines.append(
                    "  - **Search:** " + ", ".join(f"`{n[:80]}`" for n in needles[:8])
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

    # Saved Mode 1 answers — examiner-bookmarked answers carried into the report
    saved_answers = _load_saved_answers(case_dir)
    if saved_answers:
        lines.append("## Saved Mode 1 answers")
        lines.append("")
        for row in saved_answers[:20]:
            q = str(row.get("question") or "").strip() or "(question not recorded)"
            lines.append(f"- **Q:** {q}")
            reply = " ".join(str(row.get("reply") or "").split())
            if reply:
                lines.append(f"  - **A:** {reply[:600]}")
            cited = int(row.get("cited_rows") or 0)
            if cited:
                lines.append(f"  - *Cited rows:* {cited}")
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
    toc = [
        "Key Takeaways",
        "Assessment",
        "Examiner questions",
        "Case Summary",
        "Findings",
        "Timeline",
        "Indicators",
        "Detections",
        "MITRE ATT&CK",
        "Insider Threat Matrix",
    ]
    if sift_notes:
        toc.append("SIFT Linux Tooling")
    if rag_notes or detections:
        toc.append("Knowledge / Detection Assist")
    toc.append("Evidence Registry")
    for item in toc:
        lines.append(f"- {item}")
    lines.append("")

    # Findings detail — grouped by investigative category (kill-chain
    # order) so the report reads as an investigation, not a flat list of
    # parser signals. Categories come from the analysis layer (LLM or
    # deterministic map); evidence tables are signature-collapsed.
    lines.append("## Findings")
    lines.append("")
    if not approved:
        lines.append(
            "_No DRAFT or APPROVED findings._"
            if include_draft
            else "_No approved findings._"
        )
        lines.append("")

    _CAT_ORDER = {
        "authentication": 0, "execution": 1, "persistence": 2,
        "defense_evasion": 3, "credential_access": 4, "discovery": 5,
        "lateral_movement": 6, "collection": 7, "command_and_control": 8,
        "exfiltration": 9, "impact": 10, "other": 11,
    }

    def _cat_of(ci: int) -> str:
        return str((analyses.get(ci) or {}).get("category") or "other")

    def _finding_lines(f: dict[str, Any],
                       analysis: dict[str, Any] | None = None) -> list[str]:
        out = [f"#### {f.get('title', 'Untitled')}", ""]
        ids = f.get("merged_ids") or [f.get("id")]
        out.append("- **ID(s):** " + ", ".join(f"`{i}`" for i in ids))
        st = str(f.get("status") or f.get("approval_state") or "").upper()
        if include_draft and st:
            out.append(f"- **Status:** {st}")
        out.append(f"- **Severity:** {f.get('severity') or 'unrated'}")
        if f.get("approved_by"):
            out.append(f"- **Approved by:** {f.get('approved_by')}")
        tids = f.get("mitre_ids") or f.get("attack_ids") or f.get("technique_ids") or []
        if tids:
            out.append(f"- **MITRE:** {', '.join(str(t) for t in tids)}")
        out.append("")
        obs = str(f.get("observation") or f.get("description") or "").strip()
        interp = str(f.get("interpretation") or "").strip()
        if _PLACEHOLDER_INTERP.search(interp):
            interp = ""
        from nexus.integration.evidence_table import (
            normalize_evidence_rows,
            render_evidence_table,
        )

        rows = normalize_evidence_rows(f, limit=None)
        out.append("**Evidence**")
        out.append("")
        if rows:
            out.extend(render_evidence_table(rows))
        elif obs:
            out.append(obs)
            out.append("")
        if interp and interp != obs:
            out.append("**Interpretation**")
            out.append("")
            out.append(interp)
            out.append("")
        elif not obs and not rows and interp:
            out.append(interp)
            out.append("")
        if analysis:
            from nexus.langgraph.report_analysis import render_analysis_block

            out.extend(render_analysis_block(analysis))
        return out

    def _cluster_lines(ci: int, cluster: list[dict[str, Any]]) -> list[str]:
        """One fused section for needles that hit the same attack chain."""
        names = list(dict.fromkeys(
            (m.group(1) if (m := _SIGNAL_TITLE.search(str(f.get("title") or "")))
             else str(f.get("title") or ""))
            for f in cluster
        ))
        best = min(cluster, key=lambda f: _sev_rank(str(f.get("severity") or "")))
        tids = sorted({
            str(t)
            for f in cluster
            for t in (f.get("mitre_ids") or f.get("attack_ids") or f.get("technique_ids") or [])
        })
        out = [
            f"#### Correlated signal — {len(names)} needle(s) on one attack chain",
            "",
            f"Needles {', '.join(f'`{n}`' for n in names)} matched an "
            "overlapping hit set — one attack chain, reported once.",
            "",
        ]
        for f in cluster:
            ids = f.get("merged_ids") or [f.get("id")]
            out.append(
                f"- {' '.join(f'`{i}`' for i in ids)} "
                f"**{f.get('title', 'Untitled')}** "
                f"(severity: {f.get('severity') or 'unrated'}"
                + (f", approved by {f.get('approved_by')}" if f.get("approved_by") else "")
                + ")"
            )
        out.append(f"- **Cluster severity:** {best.get('severity') or 'unrated'}")
        if tids:
            out.append(f"- **MITRE:** {', '.join(tids)}")
        out.append("")
        from nexus.integration.evidence_table import render_evidence_table

        out.append("**Evidence**")
        out.append("")
        out.extend(render_evidence_table(rows_for.get(ci, [])))
        interps = [
            str(f.get("interpretation") or "").strip()
            for f in cluster
            if str(f.get("interpretation") or "").strip()
            and not _PLACEHOLDER_INTERP.search(str(f.get("interpretation") or ""))
        ]
        if interps:
            out.append("**Interpretation**")
            out.append("")
            out.append(interps[0])
            out.append("")
        if analyses.get(ci):
            from nexus.langgraph.report_analysis import render_analysis_block

            out.extend(render_analysis_block(analyses[ci]))
        return out

    by_cat: dict[str, list[int]] = {}
    for ci in range(len(clusters)):
        by_cat.setdefault(_cat_of(ci), []).append(ci)
    for cat in sorted(by_cat, key=lambda c: (_CAT_ORDER.get(c, 99), c)):
        lines.append(f"### {cat.replace('_', ' ').title()}")
        lines.append("")
        for ci in by_cat[cat]:
            cluster = clusters[ci]
            if len(cluster) == 1:
                lines.extend(_finding_lines(cluster[0], analyses.get(ci)))
            else:
                lines.extend(_cluster_lines(ci, cluster))

    # Timeline — interpreted chronology, not a raw row dump. Events are
    # bucketed per timestamp, identical descriptions collapse with counts,
    # and each family contributes its salient label (detection name /
    # map description / rule title + command line) instead of raw CSV.
    lines.append("## Timeline")
    lines.append("")
    dated, untimed = dated_timeline(timeline)
    if not dated and not untimed:
        lines.append("_No timeline events recorded._")
    else:
        if dated:
            from collections import Counter

            by_ts: dict[str, dict[str, Counter]] = {}
            for e in dated:
                ts = str(e.get("timestamp") or "")[:19]
                if not ts:
                    continue
                fam = str(e.get("family") or e.get("source") or "?").replace("|", "/")
                label = _timeline_label(e)
                by_ts.setdefault(ts, {}).setdefault(fam, Counter())[label] += 1
            lines.append("| Time (UTC) | What happened |")
            lines.append("|---|---|")
            shown = 0
            for ts in sorted(by_ts):
                if shown >= 45:
                    break
                parts = []
                for fam in sorted(by_ts[ts]):
                    labels = by_ts[ts][fam]
                    total = sum(labels.values())
                    top = "; ".join(
                        f"{lab} ×{n}" if n > 1 else lab
                        for lab, n in labels.most_common(2)
                    )
                    if len(labels) > 2:
                        top += "; …"
                    parts.append(f"**{fam}** ×{total} — {top}")
                lines.append(f"| {ts} | {' · '.join(parts)} |")
                shown += 1
            remaining = len(by_ts) - shown
            if remaining > 0:
                lines.append(
                    f"\n_… {remaining} more timestamp group(s) — full set on "
                    "the Timeline page._"
                )
        else:
            lines.append("_No dated N7 events. Keyword hits without timestamps are below._")
        i1_events = [
            e for e in dated
            if str(e.get("source") or "").lower().startswith("i1")
        ]
        if i1_events:
            lines.append("")
            lines.append("### Import/ingest (I1)")
            lines.append("")
            for e in i1_events[:15]:
                ts = str(e.get("timestamp") or "")[:19]
                desc = _timeline_label(e)
                src = str(e.get("source") or "").replace("|", "/")
                lines.append(f"- {ts} — {desc} `{src}`")
            if len(i1_events) > 15:
                lines.append(f"- _… {len(i1_events) - 15} more ingest events._")
        if untimed:
            lines.append("")
            lines.append(
                f"_{len(untimed)} untimed keyword hit(s) — review on the "
                "Timeline page._"
            )
    lines.append("")

    # Indicators — extracted from evidence row content (URLs, domains,
    # task names, host paths) merged with the custody registry's
    # IPs/hosts/hashes.
    all_rows = [r for rows in rows_for.values() for r in rows]
    content_iocs = _extract_iocs(all_rows)
    ip_set.update(content_iocs["ips"])
    lines.append("## Indicators")
    lines.append("")

    def _ioc_block(title: str, items: list[str]) -> None:
        if not items:
            return
        lines.append(f"### {title}")
        lines.append("")
        for it in items:
            lines.append(f"- `{it}`")
        lines.append("")

    _ioc_block("URLs / domains", content_iocs["urls"] + [
        d for d in content_iocs["domains"]
        if not any(d in u for u in content_iocs["urls"])
    ])
    _ioc_block("IP addresses", sorted(ip_set)[:50])
    _ioc_block("Scheduled tasks / persistence objects", content_iocs["tasks"])
    _ioc_block("Notable host paths", content_iocs["paths"])
    if host_set:
        _ioc_block("Hosts", sorted(host_set)[:50])
    if hash_set:
        _ioc_block("Hashes", sorted(hash_set)[:30])
    if not any([
        content_iocs["urls"], content_iocs["domains"], ip_set,
        content_iocs["tasks"], content_iocs["paths"], host_set, hash_set,
    ]):
        lines.append("- _No indicators extracted from approved evidence._")
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
    lines.extend(_itm_coverage_lines(approved))
    lines.append("")

    # Evidence registry
    # Methodology appendix — SIFT tool-host jobs + RAG/detection assist
    # live near the end; the report body is evidence + analysis.
    if sift_notes:
        lines.append("## SIFT Linux Tooling")
        lines.append("")
        for note in sift_notes:
            lines.append(f"- {note}")
        lines.append("")

    if rag_notes or detections:
        lines.append("## Knowledge / Detection Assist")
        lines.append("")
        if rag_notes:
            for note in _format_rag_notes(list(rag_notes)):
                lines.append(f"- {note}")
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

    app_dir = (Path(case_dir) / "analysis" / "appendices") if case_dir else None
    appendix_files = sorted(app_dir.glob("*-rows.csv")) if app_dir and app_dir.is_dir() else []
    if appendix_files:
        lines.append("## Evidence Appendices")
        lines.append("")
        lines.append(
            "Complete matched-row dumps per approved finding (no result caps — "
            "the narrative shows samples, these are every matching row)."
        )
        lines.append("")
        for ap in appendix_files:
            rows_n = 0
            try:
                with ap.open(encoding="utf-8", errors="replace") as fh:
                    rows_n = max(0, sum(1 for _ in fh) - 1)
            except OSError:
                pass
            lines.append(f"- `analysis/appendices/{ap.name}` — {rows_n} rows")
        lines.append("")

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

    # Submission integrity (WP 10.4): a finding whose seal no longer matches was
    # edited after staging. Surface it - never silently repair a tamper signal.
    try:
        from nexus.analysis.integrity import verify_seal

        broken = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            ok, reason = verify_seal(f)
            if not ok and (f.get("seal") or f.get("content_hash")):
                broken.append((str(f.get("id") or f.get("finding_id") or "?"), reason))
    except Exception:  # noqa: BLE001
        broken = []
    if broken:
        lines.append("## Submission integrity")
        lines.append("")
        lines.append(
            f"**{len(broken)} finding(s) changed after staging** (WP 10.4 seal mismatch). "
            "The stored content no longer matches the digest recorded at submission:"
        )
        lines.append("")
        for fid, reason in broken:
            lines.append(f"- `{fid}` — {reason}")
        lines.append("")

    # Coverage audit (WP 10.2) — required reading before sealing: which
    # applicable tools never ran, which indexed families no finding cites, and
    # which needles were never queried (so their 0-hit rows prove nothing).
    try:
        from nexus.analysis.coverage_audit import load_coverage_audit, report_section

        coverage_lines = report_section(load_coverage_audit(case_dir))
    except Exception:  # noqa: BLE001 - a missing audit must not break the report
        coverage_lines = []
    if coverage_lines:
        lines.extend(coverage_lines)

    lines.append("---")
    lines.append("")
    if include_draft:
        lines.append(
            "_PREVIEW includes DRAFT findings. HMAC `nexus approve` writes official `REPORT.md`._"
        )
    else:
        lines.append(
            "_Only APPROVED findings are included. DRAFT/REJECTED omitted by HITL design. "
            "This is a lab report — not a public attribution claim._"
        )
    lines.append("")
    return "\n".join(lines)


def write_findings_preview(case_dir, llm: bool = True) -> Path:
    """Write ``reports/REPORT-DRAFT.md`` from staged DRAFT+APPROVED findings.

    ``llm`` toggles the N8 analysis layer's model calls — tests and offline
    use pass ``llm=False`` (deterministic category mapping still runs).
    """
    import json

    import yaml

    case_dir = Path(case_dir)
    findings_path = case_dir / "findings.json"
    findings = []
    if findings_path.is_file():
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
    meta: dict = {}
    case_yaml = case_dir / "CASE.yaml"
    if case_yaml.is_file():
        meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
    intake = meta.get("intake") if isinstance(meta.get("intake"), dict) else {}
    questions = _split_questions(str((intake or {}).get("question") or meta.get("question") or ""))
    evidence = []
    ev_path = case_dir / "evidence.json"
    if ev_path.is_file():
        raw = json.loads(ev_path.read_text(encoding="utf-8"))
        evidence = raw if isinstance(raw, list) else raw.get("evidence") or []
    timeline = []
    try:
        from nexus.langgraph.timeline_merge import rebuild_case_timeline

        timeline = rebuild_case_timeline(case_dir)
    except Exception:
        tl_path = case_dir / "timeline.json"
        if tl_path.is_file():
            timeline = json.loads(tl_path.read_text(encoding="utf-8"))
            if not isinstance(timeline, list):
                timeline = []
    ledger = load_case_ledger(case_dir)
    md = build_dfir_markdown(
        case_id=str(meta.get("case_id") or case_dir.name),
        case_name=str(meta.get("name") or case_dir.name),
        findings=findings,
        evidence=evidence if isinstance(evidence, list) else [],
        timeline=timeline,
        examiner=str(meta.get("examiner") or ""),
        status=str(meta.get("status") or "open"),
        severity=str(meta.get("severity") or "unrated"),
        case_summary=str((intake or {}).get("question") or meta.get("description") or ""),
        tool_ledger=ledger if isinstance(ledger, list) else None,
        questions=questions,
        include_draft=True,
        sift_notes=sift_notes_from_ledger(ledger),
        case_dir=case_dir,
        llm=llm,
    )
    out = case_dir / "reports" / "REPORT-DRAFT.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    return out
