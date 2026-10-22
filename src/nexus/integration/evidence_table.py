"""Turn finding observations into examiner-readable evidence tables.

Reports must not dump parser prose or raw CSV lines. Each finding shows
Time | Source | Artifact / path | What it shows, then interpretation.
"""

from __future__ import annotations

import re
from typing import Any

from nexus.langgraph.evidence_rows import row_time

_TS = re.compile(
    r"\b(20\d{2}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2})(?::(\d{2}(?:\.\d+)?))?)?"
)
_TIME_ONLY = re.compile(r"\b(\d{2}:\d{2}:\d{2})\b")
_PATH = re.compile(
    r"[A-Za-z]:\\[^\n,;]+?(?=(?:\s+and\s+|\s+at\s+|\s+with\s+|[,;]|$))",
)
_PATH_EXT = re.compile(
    r"[A-Za-z]:\\[^\n,;]+?\.(?:exe|sys|pst|ost|lnk|zip|pf|dll)\b",
    re.I,
)
_DRIVE_FOLDER = re.compile(r"G:\\My Drive\\[^\n,;]+")
_EXE = re.compile(
    r"\b[\w.-]+\.(?:exe|sys|pst|ost|lnk|zip|pf|dll)\b",
    re.I,
)
_LAST_RUN = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9 .\\_-]{1,80}?)\s+"
    r"(?:prefetch\s+)?last run\s+(?P<ts>20\d{2}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
    re.I,
)
_BETWEEN = re.compile(
    r"on\s+(20\d{2}-\d{2}-\d{2})\s+between\s+(\d{2}:\d{2}:\d{2})\s+and\s+(\d{2}:\d{2}:\d{2})",
    re.I,
)
_N4_LINE = re.compile(
    # greedy file: Windows paths contain ':' (C:\...\a.csv:12 terms=...:) —
    # anchoring on the LAST ':line terms=' keeps them parseable. Terms may
    # themselves contain ':' so they are matched non-greedily up to ': body'.
    r"^(?P<file>.+):(?P<line>\d+)\s+terms=(?P<terms>.*?):\s+(?P<body>.*)$"
)
# Only undecodable bytes (U+FFFD) mark a row as garbage. This used to also
# match CJK ranges, silently deleting legitimate APAC evidence rows from
# finding tables and reports (EH-5). Never filter by script.
_GARBAGE = re.compile(r"[\ufffd]")
_SOURCE_SPLIT = re.compile(
    r"(?=(?:\b(?:amcache|appcompat|pecmd|jlecmd/?\s*lecmd|jlecmd|"
    r"recmd|rbcmd|srumecmd|srum|wxtcmd|psreadline|hayabusa|sqlecmd|"
    r"evtxecmd|mftecmd|RECmd|RBCmd|SrumECmd|WordWheelQuery|UserAssist|"
    r"OpenSavePidlMRU|RecentDocs|(?<!jlecmd/)lecmd)\b))",
    re.I,
)
_SOURCE_NAME = re.compile(
    r"^(amcache|appcompat|pecmd|jlecmd/?\s*lecmd|jlecmd|(?<!jlecmd/)lecmd|recmd|rbcmd|"
    r"srumecmd|srum|wxtcmd|psreadline|hayabusa|sqlecmd|evtxecmd|mftecmd|"
    r"RECmd|RBCmd|SrumECmd|Prefetch)\b",
    re.I,
)
_NUMBERED = re.compile(r"\s*\(\d+\)\s+")
_USB_PRODUCT = re.compile(
    r"\b(TOSHIBA [A-Za-z0-9 .+-]+|External USB 3\.0(?: USB Device)?|"
    r"USB DISK 2\.0|USB Mass Storage Device)\b",
    re.I,
)

# Most-informative parsed CSV fields first — what an examiner reads.
SALIENT_HIT_FIELDS = (
    "RuleTitle", "detections", "MapDescription", "Payload", "CommandLine",
    "Details", "Message", "ExecutableInfo", "ImagePath", "ParentCommandLine",
    "TargetFilename", "Event Data", "Path", "IpAddress", "RemoteHost",
    "UserName", "EventID", "Event ID",
)


def render_hit_fields(fields: dict[str, Any]) -> str:
    """'What it shows' from parsed CSV fields — 'k: v' pairs, not raw text."""
    if not isinstance(fields, dict):
        return ""
    ordered = [k for k in SALIENT_HIT_FIELDS if k in fields]
    ordered.extend(k for k in fields if k not in SALIENT_HIT_FIELDS)
    parts = []
    for key in ordered:
        value = " ".join(str(fields.get(key) or "").split())
        if not value:
            continue
        # Continuation rows misalign a timestamp column onto free text —
        # show the value bare instead of 'timestamp: CommandLine: …'.
        if key.lower() in ("timestamp", "timecreated", "time") and not value[:4].isdigit():
            parts.append(value)
        else:
            parts.append(f"{key}: {value}")
    return " · ".join(parts)


def _cell(value: Any) -> str:
    text = " ".join(str(value or "").split())
    text = text.replace("|", "/")
    return text or "—"


def _fmt_ts(date: str, time: str | None, sec: str | None = None) -> str:
    if not date:
        return "—"
    if not time:
        return date
    clock = time if not sec else f"{time}:{sec.split('.')[0]}"
    if clock.count(":") == 1:
        clock = f"{clock}:00"
    return f"{date} {clock}"


def _first_ts(text: str) -> str:
    m = _BETWEEN.search(text)
    if m:
        return f"{m.group(1)} {m.group(2)} to {m.group(3)}"
    m = _TS.search(text)
    if not m:
        return "—"
    return _fmt_ts(m.group(1), m.group(2), m.group(3))


def _artifact(text: str) -> str:
    ext = _PATH_EXT.findall(text)
    if ext:
        return ext[0].rstrip(".,;")
    drive = _DRIVE_FOLDER.findall(text)
    named = _EXE.findall(text)
    if drive:
        folder = drive[0].split(" and ")[0].rstrip(".,;")
        if named and named[0].lower() not in folder.lower():
            return f"{folder}\\{named[0]}"
        return folder
    paths = _PATH.findall(text)
    folder = paths[0].rstrip(".,;") if paths else ""
    if named:
        if folder and named[0].lower() not in folder.lower():
            return f"{folder}\\{named[0]}"
        return named[0]
    return folder


def _source_of(chunk: str) -> str:
    m = _SOURCE_NAME.search(chunk.strip())
    if not m:
        low = chunk.lower()
        for name in (
            "amcache", "appcompat", "pecmd", "jlecmd", "lecmd", "recmd",
            "rbcmd", "srumecmd", "srum", "wxtcmd", "psreadline", "hayabusa",
            "sqlecmd", "prefetch",
        ):
            if name in low:
                return name
        return "host"
    raw = re.sub(r"\s+", "", m.group(1)).lower()
    aliases = {
        "srumecmd": "srum",
        "recmd": "recmd",
        "rbcmd": "rbcmd",
        "jlecmd/lecmd": "jlecmd/lecmd",
    }
    return aliases.get(raw, raw)


def _row(time: str, source: str, artifact: str, detail: str, audit_id: str = "", loc: str = "") -> dict[str, str]:
    return {
        "time": time or "—",
        "source": source or "host",
        "artifact": artifact or "—",
        "detail": detail or "—",
        "audit_id": audit_id or "",
        "loc": loc or "",
    }


def _looks_n4(text: str) -> bool:
    return "terms=" in text or "N4 query-pack hits" in text


def rows_from_n4_observation(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("n4 query-pack"):
            continue
        m = _N4_LINE.match(line)
        body = m.group("body") if m else line
        if _GARBAGE.search(body):
            continue
        source = "n4"
        if m:
            fam = m.group("file").replace("\\", "/").split("/")[0]
            source = fam.split("_")[0] if fam else "n4"
        ts = _first_ts(body)
        prod = _USB_PRODUCT.search(body)
        artifact = prod.group(1).strip() if prod else (_artifact(body) or "")
        if not artifact:
            # device instance before first timestamp
            head = body.split(",")[0].strip()
            if head and not _GARBAGE.search(head) and len(head) < 80:
                artifact = head
        detail = body
        if m:
            terms = m.group("terms").strip()
            detail = f"{terms}: {body}"
        rows.append(_row(ts, source, artifact or "USB/device", detail))
    return rows


def rows_from_observation(text: str) -> list[dict[str, str]]:
    text = (text or "").strip()
    if not text:
        return []
    if _looks_n4(text):
        return rows_from_n4_observation(text)
    if re.search(r"\bno hits\b|\bcontain no hits\b|\bno malicious\b", text, re.I):
        return [_row("—", "query pack", "—", text)]

    numbered = _NUMBERED.split(text)
    pieces: list[str] = []
    for part in numbered:
        part = part.strip(" :")
        if not part:
            continue
        pieces.extend(p.strip(" :") for p in re.split(r";\s+(?:and\s+)?", part) if p.strip(" :"))
    chunks: list[str] = []
    for part in pieces:
        bits = [p.strip(" :") for p in _SOURCE_SPLIT.split(part) if p.strip(" :")]
        chunks.extend(bits if bits else [part])

    rows: list[dict[str, str]] = []
    for chunk in chunks:
        if len(chunk) < 8:
            continue
        last_runs = list(_LAST_RUN.finditer(chunk))
        if len(last_runs) >= 2:
            src = _source_of(chunk)
            for hit in last_runs:
                name = hit.group("name").strip(" ,")
                name = re.sub(
                    r"^(?:amcache|appcompat|pecmd|jlecmd|lecmd|recmd|rbcmd|"
                    r"srum|wxtcmd|and)\s+",
                    "",
                    name,
                    flags=re.I,
                ).strip()
                rows.append(_row(hit.group("ts"), src, name or "—", f"{name} last run"))
            # Whatever the chunk says beyond its "last run" entries keeps its own row when it
            # carries a time. This used to be a GoogleDriveFS-only regex from an earlier case
            # (D135); any program's leftover dated text is kept the same way.
            remainder = _LAST_RUN.sub(" ", chunk).strip(" ;,.")
            rest_ts = _first_ts(remainder)
            if rest_ts and len(remainder) > 20:
                rows.append(_row(rest_ts, src, _artifact(remainder) or "—", remainder))
            continue
        src = _source_of(chunk)
        if src == "host" and chunk.lower().startswith("host artifacts"):
            # peel intro; keep rest if it names a tool
            rest = chunk.split(":", 1)[-1].strip()
            if rest and rest != chunk:
                chunk = rest
                src = _source_of(chunk)
        ts = _first_ts(chunk)
        art = _artifact(chunk)
        detail = chunk
        if art and art in detail:
            detail = detail.replace(art, art.split("\\")[-1], 1)
        rows.append(_row(ts, src, art or "—", detail))

    # Drop a leading intro row that is only "Host artifacts show…"
    cleaned = []
    for r in rows:
        blob = f"{r['artifact']} {r['detail']}".lower()
        if r["source"] == "host" and "host artifacts show" in blob and r["artifact"] == "—":
            continue
        if r["artifact"] == "—" and r["time"] == "—" and len(r["detail"]) < 40:
            continue
        cleaned.append(r)
    return cleaned or rows


def normalize_evidence_rows(
    finding: dict[str, Any],
) -> list[dict[str, str]]:
    """Prefer structured `evidence` on the finding; else parse observation.

    Every stored row is returned. Pagination belongs at the evidence query
    boundary, where continuation is explicit and auditable.
    """
    structured = finding.get("evidence") or (finding.get("metadata") or {}).get("evidence")
    rows: list[dict[str, str]] = []
    if isinstance(structured, list):
        for item in structured:
            if not isinstance(item, dict):
                continue
            detail = (
                str(item.get("detail") or item.get("what") or "").strip()
                or render_hit_fields(item.get("fields"))
                or str(item.get("text") or "—")
            )
            ts = row_time(item) or str(item.get("timestamp") or "")
            if not ts or ts == "—":
                ts = _first_ts(detail)
            rows.append(_row(
                ts or "—",
                str(item.get("source") or item.get("family") or item.get("tool") or "host"),
                str(item.get("artifact") or item.get("path") or item.get("name") or "—"),
                detail,
                audit_id=str(item.get("audit_id") or ""),
                loc=str(item.get("loc") or item.get("file_line") or ""),
            ))
    if rows:
        return rows
    obs = str(finding.get("observation") or finding.get("description") or "")
    return rows_from_observation(obs)


def _family_of(source: str) -> str:
    """'chainsaw/chainsaw\\hunt.csv\\sigma.csv' → 'chainsaw'."""
    head = str(source or "").replace("\\", "/").split("/")[0].strip()
    return head or str(source or "host")


def _detail_with_artifact(r: dict[str, str]) -> str:
    """Fold a meaningful artifact into the detail cell — no junk column."""
    art = str(r.get("artifact") or "").strip()
    detail = str(r.get("detail") or "")
    if not art or art == "—" or art in detail or art in str(r.get("loc") or ""):
        return detail
    return f"{art} — {detail}"


def collapse_signatures(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Group identical detection rows — 'what it shows' + source — into one
    row with a ×N count. Massive evidence sets (40 near-identical detections)
    collapse to their distinct signatures; file:line cites the first."""
    order: list[tuple[str, str]] = []
    sigs: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        detail = _detail_with_artifact(r)
        key = (_family_of(str(r.get("source") or "")), detail.lower())
        if key in sigs:
            sigs[key]["n"] += 1
            continue
        order.append(key)
        sigs[key] = {"row": r, "detail": detail, "n": 1}
    out: list[dict[str, str]] = []
    for key in order:
        entry = sigs[key]
        r = dict(entry["row"])
        r["source"] = key[0]
        r["detail"] = (
            f"{entry['detail']}  _(×{entry['n']})_" if entry["n"] > 1
            else entry["detail"]
        )
        out.append(r)
    return out


def render_evidence_table(
    rows: list[dict[str, str]],
) -> list[str]:
    if not rows:
        return ["_No structured evidence rows._", ""]
    # Keep every evidence row and its location visible. Similarity grouping
    # belongs in a separate summary, never in the evidence table itself.
    sig = rows
    has_audit = any(str(r.get("audit_id") or "").strip() for r in sig)
    has_loc = any(str(r.get("loc") or "").strip() for r in sig)
    cols = "| Time (UTC) | Source | What it shows |"
    rule = "|---|---|---|"
    if has_audit:
        cols += " audit_id |"
        rule += "---|"
    if has_loc:
        cols += " file:line |"
        rule += "---|"
    lines = [cols, rule]
    for r in sig:
        cells = (
            f"| {_cell(r.get('time'))} | {_cell(_family_of(str(r.get('source') or '')))} "
            f"| {_cell(r.get('detail'))} |"
        )
        if has_audit:
            cells += f" {_cell(r.get('audit_id'))} |"
        if has_loc:
            cells += f" {_cell(r.get('loc'))} |"
        lines.append(cells)
    lines.append("")
    return lines


def evidence_rows_from_n4_hits(hits: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for h in hits or []:
        body = str(h.get("text") or "")
        if _GARBAGE.search(body):
            continue
        ts = _first_ts(body)
        prod = _USB_PRODUCT.search(body)
        artifact = prod.group(1).strip() if prod else (_artifact(body) or str(h.get("terms") or "—"))
        source = str(h.get("family") or "n4")
        loc = f"{h.get('file')}:{h.get('line')}"
        rows.append(_row(ts, source, artifact, f"{loc} {body}", loc=loc))
    return rows
