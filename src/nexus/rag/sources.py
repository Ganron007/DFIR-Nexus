"""RAG knowledge sources — JSONL bundles, typed documents, search results."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCORE_EXCELLENT = 0.85
SCORE_GOOD = 0.75

BUILTIN_SEED = Path(__file__).parent / "data" / "seed.jsonl"


class MatchQuality(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    WEAK = "weak"


@dataclass
class RAGDocument:
    """One searchable knowledge record."""

    id: str
    text: str
    source: str
    technique_id: str = ""
    platform: str = ""
    title: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "source": self.source,
            "technique_id": self.technique_id,
            "platform": self.platform,
            "title": self.title,
            "metadata": self.metadata,
        }


@dataclass
class SearchHit:
    """One RAG search result."""

    document: RAGDocument
    score: float
    quality: MatchQuality

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.document.to_dict(),
            "score": round(self.score, 4),
            "quality": self.quality.value,
        }


def score_quality(score: float) -> MatchQuality:
    if score >= SCORE_EXCELLENT:
        return MatchQuality.EXCELLENT
    if score >= SCORE_GOOD:
        return MatchQuality.GOOD
    return MatchQuality.WEAK


def load_jsonl(path: Path) -> Iterator[RAGDocument]:
    """Load RAG documents from a JSONL file."""
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                log.warning("Skipping invalid JSONL line %s in %s: %s", lineno, path, e)
                continue
            yield RAGDocument(
                id=str(row.get("id", f"{path.stem}-{lineno}")),
                text=str(row.get("text", "")),
                source=str(row.get("source", "custom")),
                technique_id=str(row.get("technique_id", "")),
                platform=str(row.get("platform", "")),
                title=str(row.get("title", "")),
                metadata=dict(row.get("metadata") or {}),
            )


def load_directory(directory: Path) -> list[RAGDocument]:
    """Load all JSONL files from a directory."""
    docs: list[RAGDocument] = []
    if not directory.is_dir():
        return docs
    for path in sorted(directory.glob("**/*.jsonl")):
        docs.extend(load_jsonl(path))
    return docs


def load_builtin_seed() -> list[RAGDocument]:
    """Load the shipped seed corpus (always available offline)."""
    if not BUILTIN_SEED.is_file():
        return []
    return list(load_jsonl(BUILTIN_SEED))
