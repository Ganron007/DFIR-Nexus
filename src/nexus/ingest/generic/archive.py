"""Generic archive/zip extractor.

Extracts ``.zip``, ``.tar``, ``.tar.gz``, ``.tgz``, and ``.tar.bz2``
archives into a temporary directory, then dispatches each extracted file
to the importer registry for automatic re-import. This enables recursive
ingestion of nested forensic exports.
"""

from __future__ import annotations

import logging
import shutil
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
)

log = logging.getLogger(__name__)

_ARCHIVE_EXTENSIONS = {".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz"}


class ArchiveImporter(Importer):
    """Extracts archives and re-dispatches extracted files to the importer registry."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.GENERIC_JSONL

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file extension matches a known archive format."""
        if not path.is_file():
            return False
        name = path.name.lower()
        return any(name.endswith(ext) for ext in _ARCHIVE_EXTENSIONS)

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Extract the archive and yield Artifacts from contained files.

        Each extracted file is passed to the importer registry via
        ``autodetect()``. Files that no importer can handle are skipped.
        The extracted contents are cleaned up after processing.
        """
        tmp_dir: Path | None = None
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix="nexus_archive_"))
            extracted = self._extract(path, tmp_dir)
            if not extracted:
                log.info("No files extracted from %s", path)
                return

            from nexus.ingest.registry import get_registry

            registry = get_registry()

            for extracted_file in extracted:
                try:
                    importer_cls = registry.autodetect(extracted_file)
                    if importer_cls is None:
                        log.debug("No importer for extracted file %s", extracted_file)
                        continue
                    importer = importer_cls()
                    yield from importer.parse(extracted_file)
                except Exception:
                    log.warning(
                        "Failed to import extracted file %s", extracted_file, exc_info=True
                    )
        except Exception:
            log.warning("Failed to process archive %s", path, exc_info=True)
        finally:
            if tmp_dir is not None and tmp_dir.exists():
                try:
                    shutil.rmtree(tmp_dir)
                except OSError:
                    log.debug("Failed to clean up temp dir %s", tmp_dir)

    def _extract(self, archive_path: Path, dest: Path) -> list[Path]:
        """Extract archive contents to dest. Returns list of extracted file paths."""
        name = archive_path.name.lower()
        if name.endswith(".zip"):
            return self._extract_zip(archive_path, dest)
        if tarfile.is_tarfile(str(archive_path)):
            return self._extract_tar(archive_path, dest)
        log.warning("Unsupported archive format: %s", archive_path)
        return []

    @staticmethod
    def _extract_zip(archive_path: Path, dest: Path) -> list[Path]:
        """Extract a zip archive safely (skip path traversal)."""
        extracted: list[Path] = []
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                for member in zf.infolist():
                    # Prevent path traversal
                    target = dest / member.filename
                    try:
                        target = target.resolve()
                        if not str(target).startswith(str(dest.resolve())):
                            log.warning("Skipping path traversal: %s", member.filename)
                            continue
                    except (ValueError, OSError):
                        continue

                    if member.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue

                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    extracted.append(target)
        except (zipfile.BadZipFile, OSError):
            log.warning("Failed to extract zip: %s", archive_path, exc_info=True)
        return extracted

    @staticmethod
    def _extract_tar(archive_path: Path, dest: Path) -> list[Path]:
        """Extract a tar archive safely (skip path traversal)."""
        extracted: list[Path] = []
        try:
            with tarfile.open(archive_path, "r:*") as tf:
                for member in tf.getmembers():
                    target = dest / member.name
                    try:
                        target = target.resolve()
                        if not str(target).startswith(str(dest.resolve())):
                            log.warning("Skipping path traversal: %s", member.name)
                            continue
                    except (ValueError, OSError):
                        continue

                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    if member.issym() or member.islnk():
                        continue

                    target.parent.mkdir(parents=True, exist_ok=True)
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    with src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    extracted.append(target)
        except (tarfile.TarError, OSError):
            log.warning("Failed to extract tar: %s", archive_path, exc_info=True)
        return extracted
