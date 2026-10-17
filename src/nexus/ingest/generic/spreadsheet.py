"""Spreadsheet importer (.xlsx / .xlsm): every sheet's rows, read as the examiner's tool exported them.

Examiners receive tool reports as workbooks: SRUM-DUMP writes one sheet per SRUM table, other tools export their
grids the same way. A workbook was read by no importer, so its rows never reached the case (sample S02,
2026-10-18: `SRUM_DUMP_OUTPUT.xlsx` beside the raw `srudb.dat`). Each sheet's first row is its header; each later
row is one record, with the sheet named in the row. A report is derived evidence: its rows are what the tool
said, which the raw artifact can confirm or contradict.

openpyxl reads the workbook in read-only, values-only mode; without it, no workbook is claimed.
"""

from __future__ import annotations

import logging
import zipfile
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.base import Importer
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity

log = logging.getLogger(__name__)

_SUFFIXES = (".xlsx", ".xlsm")


def _openpyxl():
    try:
        import openpyxl
    except ImportError:
        return None
    return openpyxl


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=UTC)).isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


class SpreadsheetImporter(Importer):
    """Reader for Excel workbooks (Office Open XML)."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.SPREADSHEET

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        if not path.is_file() or path.suffix.lower() not in _SUFFIXES or _openpyxl() is None:
            return False
        try:
            with zipfile.ZipFile(path) as z:
                return "xl/workbook.xml" in z.namelist()
        except (OSError, zipfile.BadZipFile):
            return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        openpyxl = _openpyxl()
        if openpyxl is None:
            return
        book = openpyxl.load_workbook(path, read_only=True, data_only=True)
        try:
            for sheet in book.worksheets:
                header: list[str] | None = None
                for cells in sheet.iter_rows(values_only=True):
                    values = list(cells)
                    if header is None:
                        if any(v not in (None, "") for v in values):
                            header = [_text(v).strip() or f"column_{i + 1}" for i, v in enumerate(values)]
                        continue
                    if not any(v not in (None, "") for v in values):
                        continue
                    yield self._row(sheet.title, header, values)
        finally:
            book.close()

    @staticmethod
    def _row_time(row: dict[str, Any]) -> datetime | None:
        """The row's first date cell, else a time column's text that reads as a date; a number is never a time.

        A column named for a time can hold a duration: SRUM-DUMP's ConnectedTime and cycle-time counters read as
        epoch seconds put rows in 1970-1982, while the row's Srum Entry Creation date cell was passed over.
        """
        from nexus.langgraph.timestamps import parse_text_time

        for value in row.values():
            if isinstance(value, datetime):
                return value if value.tzinfo else value.replace(tzinfo=UTC)
        for name, value in row.items():
            if isinstance(value, str) and any(w in name.lower() for w in ("time", "date", "created", "stamp")):
                got = parse_text_time(value)
                if got:
                    return got["dt"]
        return None

    def _row(self, sheet: str, header: list[str], values: list[Any]) -> Artifact:
        row = {header[i] if i < len(header) else f"column_{i + 1}": values[i] for i in range(len(values))}
        ts = self._row_time(row)
        synthesized = ts is None
        if ts is None:
            ts = datetime.now(UTC)
        fields = {k: _text(v) for k, v in row.items() if v not in (None, "")}
        description = f"{sheet}: " + "; ".join(f"{k}={v}" for k, v in fields.items())
        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.UNKNOWN,
            source=ArtifactSource.SPREADSHEET,
            timestamp=ts,
            ts_synthesized=synthesized,
            severity=Severity.INFORMATIONAL,
            description=description,
            raw={"sheet": sheet, **fields},
            tags=["spreadsheet", f"sheet.{sheet.lower().replace(' ', '_')}"],
        )
