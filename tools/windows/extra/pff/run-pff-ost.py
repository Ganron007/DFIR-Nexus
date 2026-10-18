"""Outlook OST / PST lane wrapper (WO-TA item 5).

Reads every item of an OST or PST with libpff-python (`pypff`, pinned
20260926, `pip install libpff-python==20260926`) and writes one CSV row per
item, so the case indexer reads the mail like any other tool output.

    run-pff-ost.py <mail file> <output.csv>

Each item is read by its MAPI properties (MS-OXPROPS), not by the Python type
pypff gives it: a store holds mail, meetings, contacts and address-book items,
and pypff returns some of them as a plain item without the message attributes.
Reading them as messages ended the walk at the first such item, and two of
sample S09's three stores wrote nothing (2026-10-18).

Columns: folder, message_class, timestamp (the delivery time, else the client
submit time, which a sent item has instead, else the creation time; UTC),
delivery_time, client_submit_time, creation_time, sender_name, sender_email,
to, cc, bcc, subject, message_id, attachments (each attachment's name and size;
the content is not read), transport_headers and body_preview (the plain-text
body, else the text of the HTML body, which most of S09's mail has instead,
else the text of the compressed RTF body). Text values have their line breaks turned into spaces so
every item stays one CSV row; the body is cut to 2000 characters. The source
file is only read; the wrapper never writes beside it.
"""
from __future__ import annotations

import csv
import re
import sys
from datetime import UTC
from html.parser import HTMLParser
from pathlib import Path

_BODY_CAP = 2000
_COLUMNS = (
    "folder", "message_class", "timestamp", "delivery_time", "client_submit_time", "creation_time", "sender_name",
    "sender_email", "to", "cc", "bcc", "subject", "message_id", "attachments", "transport_headers", "body_preview",
)
# MAPI property IDs (MS-OXPROPS): the ID is the upper 16 bits of the tag, which is what pypff reports as entry_type.
_TEXT = {
    0x001A: "message_class", 0x0037: "subject", 0x0C1A: "sender_name", 0x0C1F: "sender_email",
    0x5D01: "sender_smtp", 0x0E04: "to", 0x0E03: "cc", 0x0E02: "bcc", 0x1035: "message_id",
    0x007D: "transport_headers", 0x1000: "body",
}
_TIMES = {0x0E06: "delivery_time", 0x0039: "client_submit_time", 0x3007: "creation_time"}
_HTML_BODY = 0x1013  # PR_HTML, binary: a message with an HTML body only has no PR_BODY
_RTF_BODY = 0x1009  # PR_RTF_COMPRESSED: some mail has its body only here


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _one_line(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ").strip()


class _HtmlText(HTMLParser):
    """The text of an HTML body, without its markup, scripts or styles."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs) -> None:
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data) -> None:
        if not self._skip and data.strip():
            self.parts.append(data.strip())


def _html_text(data: bytes) -> str:
    parser = _HtmlText()
    parser.feed(data.decode("utf-8", errors="replace"))
    parser.close()
    return " ".join(parser.parts)


# PR_RTF_COMPRESSED: [MS-OXRTFCP] 2.1.3 (LZFu). A 16-byte header (COMPSIZE, RAWSIZE, COMPTYPE, CRC), then control
# bytes whose bits, least significant first, mark a literal byte (0) or a 2-byte big-endian reference (1: a 12-bit
# offset and a 4-bit length less 2) into a 4096-byte ring that starts with the specification's preloaded RTF prefix;
# a reference to the write position ends the stream, and COMPTYPE MELA is stored uncompressed. The RTF is then read
# as text: ignorable destinations and the font, colour and style tables dropped, \par and \line as line breaks,
# \'hh and \uN as characters, other control words and braces dropped.
_PRELOAD = (
    b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript "
    b"\\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par "
    b"\\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"
)
_LZFU = 0x75465A4C
_MELA = 0x414C454D


def _rtf_decompress(data: bytes) -> bytes:
    """The RTF a PR_RTF_COMPRESSED value holds; ValueError when it is not one."""
    if len(data) < 16:
        raise ValueError("shorter than the compressed-RTF header")
    raw_size = int.from_bytes(data[4:8], "little")
    comp_type = int.from_bytes(data[8:12], "little")
    body = data[16:]
    if comp_type == _MELA:
        return body[:raw_size]
    if comp_type != _LZFU:
        raise ValueError(f"unknown compression type {comp_type:#x}")
    ring = bytearray(4096)
    ring[: len(_PRELOAD)] = _PRELOAD
    write = len(_PRELOAD)
    out = bytearray()
    i = 0
    while i < len(body):
        control = body[i]
        i += 1
        for bit in range(8):
            if i >= len(body):
                return bytes(out)
            if not control & (1 << bit):
                out.append(body[i])
                ring[write] = body[i]
                write = (write + 1) % 4096
                i += 1
                continue
            if i + 1 >= len(body):
                return bytes(out)
            word = (body[i] << 8) | body[i + 1]
            i += 2
            offset, length = word >> 4, (word & 0xF) + 2
            if offset == write:
                return bytes(out)
            for k in range(length):
                byte = ring[(offset + k) % 4096]
                out.append(byte)
                ring[write] = byte
                write = (write + 1) % 4096
    return bytes(out)


_TOKEN = re.compile(rb"\\'([0-9a-fA-F]{2})|\\u(-?\d+)\??|\\([a-zA-Z]+)(-?\d+)? ?|\\([^a-zA-Z])|([{}])|(\r\n|\n|\r)|([^\\{}\r\n]+)")
_SKIP_DESTINATIONS = {b"fonttbl", b"colortbl", b"stylesheet", b"info", b"pict", b"header", b"footer", b"themedata",
                      b"datastore", b"latentstyles", b"listtable", b"listoverridetable", b"rsidtbl", b"generator"}


def _rtf_text(rtf: bytes) -> str:
    """The text an RTF document shows, without its control words and tables."""
    out: list[str] = []
    stack: list[bool] = []
    skipping = False
    ignorable = False
    for m in _TOKEN.finditer(rtf):
        hex_char, uni, word, _arg, symbol, brace, _newline, text = m.groups()
        if brace == b"{":
            stack.append(skipping)
            ignorable = False
        elif brace == b"}":
            skipping = stack.pop() if stack else False
        elif symbol is not None:
            if symbol == b"*":
                ignorable = True
            elif not skipping and symbol in (b"\\", b"{", b"}"):
                out.append(symbol.decode("latin-1"))
            elif not skipping and symbol == b"~":
                out.append(" ")
        elif word is not None:
            if ignorable or word in _SKIP_DESTINATIONS:
                skipping = True
                ignorable = False
            elif not skipping and word in (b"par", b"line", b"row"):
                out.append("\n")
            elif not skipping and word == b"tab":
                out.append("\t")
        elif hex_char is not None and not skipping:
            out.append(bytes([int(hex_char, 16)]).decode("cp1252", errors="replace"))
        elif uni is not None and not skipping:
            out.append(chr(int(uni) % 0x10000))
        elif text is not None and not skipping:
            out.append(text.decode("cp1252", errors="replace"))
    return "".join(out).strip()


def _properties(item) -> dict[str, object]:
    """The item's text and time properties, by MAPI property ID."""
    props: dict[str, object] = {}
    for r in range(item.number_of_record_sets):
        record_set = item.get_record_set(r)
        for e in range(record_set.number_of_entries):
            entry = record_set.get_entry(e)
            name = _TEXT.get(entry.entry_type)
            try:
                if name and name not in props:
                    props[name] = _text(entry.get_data_as_string())
                elif entry.entry_type in _TIMES and _TIMES[entry.entry_type] not in props:
                    props[_TIMES[entry.entry_type]] = entry.get_data_as_datetime()
                elif entry.entry_type in (_HTML_BODY, _RTF_BODY) and entry.entry_type not in props:
                    props[entry.entry_type] = entry.data or b""  # converted only when no plainer body exists
            except (OSError, ValueError, TypeError):
                continue  # a property of another type than its ID implies: not read, the rest of the item is
    return props


def _body(props: dict[str, object]) -> str:
    """The plain-text body, else the text of the HTML body, else the text of the compressed RTF body."""
    if props.get("body"):
        return _text(props["body"])
    if props.get(_HTML_BODY):
        return _html_text(props[_HTML_BODY])
    if props.get(_RTF_BODY):
        try:
            return _rtf_text(_rtf_decompress(props[_RTF_BODY]))
        except ValueError:
            return ""
    return ""


def _when(value) -> str:
    return value.replace(tzinfo=UTC).isoformat() if value is not None and hasattr(value, "isoformat") else ""


def _attachments(item) -> str:
    """Each attachment's name and size, as the store records them; the content is not read."""
    out: list[str] = []
    for i in range(getattr(item, "number_of_attachments", 0) or 0):
        try:
            att = item.get_attachment(i)
            out.append(f"{_text(att.long_filename) or '(unnamed)'} ({att.size} bytes)")
        except (OSError, ValueError):
            out.append("(attachment not readable)")
    return "; ".join(out)


def _row(item, folder: str) -> dict[str, str]:
    props = _properties(item)
    times = {k: _when(props.get(k)) for k in _TIMES.values()}
    return {
        "folder": folder,
        "message_class": _text(props.get("message_class")),
        "timestamp": times["delivery_time"] or times["client_submit_time"] or times["creation_time"],
        **times,
        "sender_name": _one_line(_text(props.get("sender_name"))),
        "sender_email": _text(props.get("sender_smtp")) or _text(props.get("sender_email")),
        "to": _one_line(_text(props.get("to"))),
        "cc": _one_line(_text(props.get("cc"))),
        "bcc": _one_line(_text(props.get("bcc"))),
        "subject": _one_line(_text(props.get("subject"))),
        "message_id": _text(props.get("message_id")),
        "attachments": _attachments(item),
        "transport_headers": _one_line(_text(props.get("transport_headers"))),
        "body_preview": _one_line(_body(props))[:_BODY_CAP],
    }


def _walk(folder, path: str, rows: list[dict]) -> None:
    for i in range(folder.number_of_sub_messages):
        rows.append(_row(folder.get_sub_message(i), path))
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
    print(f"{len(rows)} item(s) written to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
