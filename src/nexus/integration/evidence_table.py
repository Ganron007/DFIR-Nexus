"""Turn finding observations into examiner-readable evidence tables.

Reports must not dump parser prose or raw CSV lines. Each finding shows
Time | Source | Artifact / path | What it shows, then interpretation.
"""

from __future__ import annotations

import re
from typing import Any

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
    r"^(?P<file>[^:\n]+):(?P<line>\d+)\s+terms=(?P<terms>[^:]+):\s+(?P<body>.*)$"
)
_GARBAGE = re.compile(r"[\ufffd\u4e00-\u9fff\u3400-\u4dbf]")
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

_MAX_ROWS = 12
_CELL = 160


def _cell(value: Any) -> str:
    text = " ".join(str(value or "").split())
    text = text.replace("|", "/")
    if len(text) > _CELL:
        text = text[: _CELL - 1] + "…"
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


def _row(time: str, source: str, artifact: str, detail: str) -> dict[str, str]:
    return {
        "time": time or "—",
        "source": source or "host",
        "artifact": artifact or "—",
        "detail": detail or "—",
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
        if len(rows) >= _MAX_ROWS:
            break
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
            # leftover GoogleDriveFS e.g. times
            eg = re.search(
                r"(GOOGLEDRIVEFS\.EXE|GoogleDriveFS\.exe).{0,80}?"
                r"on\s+(20\d{2}-\d{2}-\d{2}).{0,20}?"
                r"\(([^)]+)\)",
                chunk,
                re.I,
            )
            if eg:
                times = ", ".join(_TIME_ONLY.findall(eg.group(3))[:6])
                rows.append(_row(
                    f"{eg.group(2)} {times}" if times else eg.group(2),
                    src,
                    "GOOGLEDRIVEFS.EXE",
                    "repeated prefetch / ActivitiesCache runs",
                ))
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
        if len(rows) >= _MAX_ROWS:
            break

    # Drop a leading intro row that is only "Host artifacts show…"
    cleaned = []
    for r in rows:
        blob = f"{r['artifact']} {r['detail']}".lower()
        if r["source"] == "host" and "host artifacts show" in blob and r["artifact"] == "—":
            continue
        if r["artifact"] == "—" and r["time"] == "—" and len(r["detail"]) < 40:
            continue
        cleaned.append(r)
    return cleaned[:_MAX_ROWS] or rows[:_MAX_ROWS]


def normalize_evidence_rows(finding: dict[str, Any]) -> list[dict[str, str]]:
    """Prefer structured `evidence` on the finding; else parse observation."""
    structured = finding.get("evidence") or (finding.get("metadata") or {}).get("evidence")
    rows: list[dict[str, str]] = []
    if isinstance(structured, list):
        for item in structured:
            if not isinstance(item, dict):
                continue
            rows.append(_row(
                str(item.get("time") or item.get("timestamp") or "—"),
                str(item.get("source") or item.get("family") or item.get("tool") or "host"),
                str(item.get("artifact") or item.get("path") or item.get("name") or "—"),
                str(item.get("detail") or item.get("what") or item.get("text") or "—"),
            ))
            if len(rows) >= _MAX_ROWS:
                break
    if rows:
        return rows
    obs = str(finding.get("observation") or finding.get("description") or "")
    return rows_from_observation(obs)


def render_evidence_table(rows: list[dict[str, str]]) -> list[str]:
    if not rows:
        return ["_No structured evidence rows._", ""]
    lines = [
        "| Time (UTC) | Source | Artifact / path | What it shows |",
        "|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {_cell(r.get('time'))} | {_cell(r.get('source'))} | "
            f"{_cell(r.get('artifact'))} | {_cell(r.get('detail'))} |"
        )
    lines.append("")
    return lines


def evidence_rows_from_n4_hits(hits: list[dict[str, Any]], limit: int = _MAX_ROWS) -> list[dict[str, str]]:
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
        rows.append(_row(ts, source, artifact, f"{loc} {body}"))
        if len(rows) >= limit:
            break
    return rows
