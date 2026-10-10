"""Outlook OST / PST lane wrapper (WO-TA item 5).

Reads every message of an OST or PST with libpff-python (`pypff`, pinned
20260926, `pip install libpff-python==20260926`) and writes one CSV row per
message, so the case indexer reads the mail like any other tool output.

    run-pff-ost.py <mail file> <output.csv>

Columns: folder, delivery_time, sender_name, subject, body_preview.
body_preview is the plain-text body, cut to 2000 characters, with line breaks
turned into spaces so every message stays one CSV row. The source file is only
read; the wrapper never writes beside it.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

_BODY_CAP = 2000
_COLUMNS = ("folder", "delivery_time", "sender_name", "subject", "body_preview")


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _walk(folder, path: str, rows: list[dict]) -> None:
    for i in range(folder.number_of_sub_messages):
        msg = folder.get_sub_message(i)
        body = _text(msg.plain_text_body).replace("\r", " ").replace("\n", " ")
        when = msg.delivery_time
        rows.append({
            "folder": path,
            "delivery_time": when.isoformat(sep=" ") if when else "",
            "sender_name": _text(msg.sender_name),
            "subject": _text(msg.subject),
            "body_preview": body[:_BODY_CAP],
        })
    for i in range(folder.number_of_sub_folders):
        sub = folder.get_sub_folder(i)
        _walk(sub, f"{path}/{_text(sub.name)}", rows)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    source, target = Path(argv[0]), Path(argv[1])
    if not source.is_file():
        print(f"mail file not found: {source}", file=sys.stderr)
        return 2
    import pypff  # noqa: PLC0415 - optional dependency, reported as a job failure

    handle = pypff.file()
    handle.open(str(source))
    try:
        rows: list[dict] = []
        _walk(handle.get_root_folder(), "", rows)
    finally:
        handle.close()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)} message(s) written to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
