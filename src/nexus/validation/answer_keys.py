"""Answer keys for accuracy measurement (WO-A1 / WP 10.3, D20 = B).

An accuracy number is only worth what its key is worth, so the key is built
here, from the evidence, and its **exclusions are stated rather than dropped**:
a file with no technique label is not a silent non-event, it is a reported
exclusion. Two keys ship:

``evtx_to_mitre_key``
    The Hayabusa sample corpus: ``TA0002-Execution/T1059.001-PowerShell/``
    folders label the EVTX inside them. Sub-techniques stay distinct from their
    parents (``T1059.001`` is never folded into ``T1059``) because folding
    inflates recall and hides exactly the depth an examiner asked about. The
    unlabelled corners (``Antivirus/``, ``EVTX_full_APT_attack_steps/``) cannot
    be scored and are reported as excluded, with their hashes.

``self_describing_key``
    Ground truth read out of the evidence itself: Prefetch file names name the
    executables that ran, typed task XML names the task URI and command, a
    ``SOFTWARE`` hive names installed software. No labels needed - the artefact
    is its own key.
"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TECHNIQUE_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)\s*[-_]\s*(.*)$")
TACTIC_RE = re.compile(r"^(TA\d{4})\s*[-_]\s*(.*)$")
# PECmd/Prefetch names: <EXE>-<hash>-<runs>.pf, <EXE>-<runs>.pf or <runs>-<EXE>.pf
PREFETCH_RE = re.compile(
    r"^(?:"
    r"(?P<runfirst>\d+)-(?P<exe2>.+)"          # 9-POWERSHELL.EXE
    r"|(?P<exe>.+?)-(?P<hash>[0-9A-Fa-f]{4,})-(?P<runs>\d+)"  # EXE-3A1B2C3D-9
    r"|(?P<exe3>.+)-(?P<runs2>\d+)"           # EXE-12
    r")$",
    re.IGNORECASE,
)
_PREFETCH_SUFFIXES = {".pf", ".prefetch"}
_GENERIC_OUTPUT = {"output", "prefetch_output", "pecmd_output"}


@dataclass
class KeyEntry:
    """One scorable item: a labelled file, or an entity read from evidence."""

    file: str
    sha256: str = ""
    tactic: str = ""
    technique: str = ""
    label: str = ""
    entity: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"file": self.file}
        if self.sha256:
            out["sha256"] = self.sha256
        if self.tactic:
            out["tactic"] = self.tactic
        if self.technique:
            out["technique"] = self.technique
        if self.label:
            out["label"] = self.label
        if self.entity:
            out["entity"] = self.entity
        return out


@dataclass
class Excluded:
    """A file present in the corpus that this key cannot score. Never silent."""

    file: str
    reason: str
    sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = {"file": self.file, "reason": self.reason}
        if self.sha256:
            out["sha256"] = self.sha256
        return out


@dataclass
class AnswerKey:
    kind: str
    root: str
    entries: list[KeyEntry] = field(default_factory=list)
    excluded: list[Excluded] = field(default_factory=list)
    built_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def techniques(self) -> set[str]:
        return {e.technique for e in self.entries if e.technique}

    def entities(self) -> set[str]:
        return {e.entity for e in self.entries if e.entity}

    def expected(self, dimension: str = "techniques") -> set[str]:
        return self.techniques() if dimension == "techniques" else self.entities()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "root": self.root,
            "built_at": self.built_at,
            "counts": {
                "entries": len(self.entries),
                "techniques": len(self.techniques()),
                "entities": len(self.entities()),
                "excluded": len(self.excluded),
            },
            "entries": [e.to_dict() for e in self.entries],
            "excluded": [x.to_dict() for x in self.excluded],
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.rglob("*") if p.is_file())


def evtx_to_mitre_key(root: str | Path) -> AnswerKey:
    """Ground truth from the ``EVTX-to-MITRE-Attack`` folder tree."""
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"answer-key root is not a directory: {root}")
    key = AnswerKey(kind="evtx-to-mitre", root=str(root))

    for tactic_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        tactic_match = TACTIC_RE.match(tactic_dir.name)
        if not tactic_match:
            # Antivirus/ and EVTX_full_APT_attack_steps/ carry no technique
            # label. Scoring them would need a guess, so they are excluded and
            # reported (D20 = B: internal, but honest).
            for path in _files(tactic_dir):
                key.excluded.append(
                    Excluded(
                        file=str(path.relative_to(root)).replace("\\", "/"),
                        reason=f"no technique label under {tactic_dir.name}",
                        sha256=_sha256(path),
                    )
                )
            continue
        tactic = tactic_match.group(1)

        for tech_dir in sorted(p for p in tactic_dir.iterdir() if p.is_dir()):
            tech_match = TECHNIQUE_RE.match(tech_dir.name)
            if not tech_match:
                for path in _files(tech_dir):
                    key.excluded.append(
                        Excluded(
                            file=str(path.relative_to(root)).replace("\\", "/"),
                            reason=f"folder {tech_dir.name} is not a technique label",
                            sha256=_sha256(path),
                        )
                    )
                continue
            technique, label = tech_match.group(1), tech_match.group(2).strip()
            for path in _files(tech_dir):
                key.entries.append(
                    KeyEntry(
                        file=str(path.relative_to(root)).replace("\\", "/"),
                        sha256=_sha256(path),
                        tactic=tactic,
                        technique=technique,
                        label=label,
                    )
                )
    return key


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _prefetch_executable(name: str) -> str | None:
    stem = Path(name).stem.strip()
    if not stem or stem.lower() in _GENERIC_OUTPUT:
        return None
    match = PREFETCH_RE.match(stem)
    if not match:
        return None
    return (match.group("exe2") or match.group("exe") or match.group("exe3") or "").strip() or None


def _task_entities(path: Path) -> list[str]:
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []
    found: list[str] = []
    for element in tree.iter():
        tag = _strip_ns(element.tag)
        if tag not in {"URI", "Command"}:
            continue
        text = (element.text or "").strip()
        if not text:
            continue
        prefix = "task" if tag == "URI" else "command"
        value = f"{prefix}:{text}"
        if value not in found:
            found.append(value)
    return found


def self_describing_key(evidence_root: str | Path) -> AnswerKey:
    """Ground truth read out of the evidence: Prefetch names, task XML, hives.

    SOFTWARE uninstall keys need a hive parse; this key does not open hives, so
    a hive is reported as an excluded source rather than being quietly absent
    from the numbers.
    """
    root = Path(evidence_root)
    if not root.is_dir():
        raise FileNotFoundError(f"evidence root is not a directory: {root}")
    key = AnswerKey(kind="self-describing", root=str(root))

    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = str(path.relative_to(root)).replace("\\", "/")
        parts = rel.lower().split("/")
        suffix = path.suffix.lower()

        if suffix in {".hiv", ".hive"} or path.name.upper().startswith("SOFTWARE"):
            key.excluded.append(
                Excluded(file=rel, reason="SOFTWARE hives need a hive parse; not read by this key")
            )
            continue

        if suffix in _PREFETCH_SUFFIXES or "prefetch" in parts:
            executable = _prefetch_executable(path.name)
            if executable:
                key.entries.append(
                    KeyEntry(file=rel, entity=executable.upper(), sha256=_sha256(path))
                )
            elif suffix not in {".csv", ".jsonl", ".json", ".zip", ".txt", ".md"}:
                key.excluded.append(
                    Excluded(
                        file=rel,
                        reason="Prefetch file name does not name an executable",
                    )
                )
            continue

        if suffix == ".xml" and ("task" in rel.lower()):
            entities = _task_entities(path)
            if not entities:
                key.excluded.append(
                    Excluded(file=rel, reason="task XML has no URI or Command")
                )
            for entity in entities:
                key.entries.append(
                    KeyEntry(file=rel, entity=entity, sha256=_sha256(path))
                )
    return key