"""A SQLite database in the evidence is read from a copy, never opened where it lies.

A database left in write-ahead-log mode keeps its newest pages in ``<name>-wal`` and its index in ``<name>-shm``.
Opening it in place, even read-only, writes the ``-shm`` file and can checkpoint the log into the database on close,
which changes the evidence; opening it with ``immutable=1`` writes nothing but ignores the log and loses its pages
(sample S09's Magnet AXIOM Case.mfdb holds 320 MB in its log, 2026-10-18). The database and its companions are copied
into a temporary folder and the copy is opened normally, so the log is replayed into the copy.
"""
from __future__ import annotations

import contextlib
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from pathlib import Path

SQLITE_MAGIC = b"SQLite format 3\x00"
COMPANION_SUFFIXES = ("-wal", "-shm", "-journal")


def is_sqlite(path: Path) -> bool:
    try:
        with Path(path).open("rb") as fh:
            return fh.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def tables(path: Path) -> set[str]:
    """The table names a database file holds, read without writing beside it (the log is not replayed)."""
    uri = f"{Path(path).resolve().as_uri()}?mode=ro&immutable=1"
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return set()
    try:
        return {r[0] for r in con.execute("select name from sqlite_master where type = 'table'")}
    except sqlite3.Error:
        return set()
    finally:
        con.close()


@contextlib.contextmanager
def snapshot(path: Path) -> Iterator[sqlite3.Connection]:
    """A connection to a copy of the database with its write-ahead log, removed when the block ends."""
    path = Path(path)
    with tempfile.TemporaryDirectory(prefix="nexus-sqlite-") as work:
        copy = Path(work) / path.name
        shutil.copyfile(path, copy)
        for suffix in COMPANION_SUFFIXES:
            companion = path.with_name(path.name + suffix)
            if companion.is_file():
                shutil.copyfile(companion, copy.with_name(copy.name + suffix))
        con = sqlite3.connect(copy)
        try:
            yield con
        finally:
            con.close()
