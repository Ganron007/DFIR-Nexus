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
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TECHNIQUE_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)\s*[-_]\s*(.*)$")
TACTIC_RE = re.compile(r"^(TA\d{4})\s*[-_]\s*(.*)$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
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
    window: str = ""

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
        if self.window:
            out["window"] = self.window
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
class Unlabelled:
    """A file registered in the case that the key does not label.

    Reported rather than dropped: a registered file with no manifest entry is
    evidence the scoring run could not use, and saying so is the difference
    between "recall is low" and "recall is unmeasured for part of the case".
    """

    sha256: str
    names: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"sha256": self.sha256}
        if self.names:
            out["names"] = list(self.names)
        return out


@dataclass
class AnswerKey:
    kind: str
    root: str
    entries: list[KeyEntry] = field(default_factory=list)
    excluded: list[Excluded] = field(default_factory=list)
    built_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    #: Where an operator manifest was read from (provenance), if any.
    manifest: str = ""
    #: Case id this key was scoped to by :meth:`restrict_to`, if any.
    case: str = ""
    #: Registered files with no entry, and manifest entries not in the case.
    unlabelled: list[Unlabelled] = field(default_factory=list)
    ignored: list[dict[str, str]] = field(default_factory=list)
    matched: int = 0
    #: Hashes the operator declared clean (`role: benign`). Used by the K1
    #: false-positive metric to attribute a finding's cited rows to benign
    #: evidence (WO-K1).
    benign: list[str] = field(default_factory=list)

    def techniques(self) -> set[str]:
        return {e.technique for e in self.entries if e.technique}

    def entities(self) -> set[str]:
        return {e.entity for e in self.entries if e.entity}

    def benign_hashes(self) -> set[str]:
        """Hashes the operator declared clean (`role: benign`)."""
        return {str(h).strip().lower() for h in self.benign if str(h).strip()}

    def expected(self, dimension: str = "techniques") -> set[str]:
        return self.techniques() if dimension == "techniques" else self.entities()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": self.kind,
            "root": self.root,
            "built_at": self.built_at,
            "counts": {
                "entries": len(self.entries),
                "techniques": len(self.techniques()),
                "entities": len(self.entities()),
                "excluded": len(self.excluded),
                "matched": self.matched,
                "unlabelled": len(self.unlabelled),
                "ignored": len(self.ignored),
                "benign": len(self.benign_hashes()),
            },
            "entries": [e.to_dict() for e in self.entries],
            "excluded": [x.to_dict() for x in self.excluded],
        }
        if self.manifest:
            out["manifest"] = self.manifest
        if self.case:
            out["case"] = self.case
        if self.unlabelled:
            out["unlabelled"] = [u.to_dict() for u in self.unlabelled]
        if self.ignored:
            out["ignored"] = [dict(i) for i in self.ignored]
        return out

    @classmethod
    def from_manifest(cls, manifest_path: str | Path) -> AnswerKey:
        """Ground truth the operator writes and keeps **outside the case**.

        YAML or JSON::

            entries:
              - sha256: <64 hex>
                techniques: [T1059.001, T1003]   # optional
                entities: [powershell.exe]        # optional
                window: "2026-09-01..2026-09-02"  # optional
                notes: "Campaign H step 3"        # optional

        Matching is by content hash, so the evidence may be renamed freely —
        that is the point. A random sample often arrives named after what it is,
        and a key that read names would put the answer inside the case (V10).

        Malformed entries are reported in ``excluded`` rather than dropped: the
        same rule this module states for its file-derived keys.
        """
        path = Path(manifest_path)
        if not path.is_file():
            raise FileNotFoundError(f"manifest not found: {path}")
        raw = path.read_text(encoding="utf-8")
        loaded: Any = None
        try:
            loaded = json.loads(raw)
        except ValueError:
            try:
                import yaml

                loaded = yaml.safe_load(raw)
            except Exception:  # noqa: BLE001 — a bad manifest must say so
                loaded = None
        if not isinstance(loaded, dict):
            raise ValueError(f"manifest must be a mapping with an 'entries' list: {path}")
        raw_entries = loaded.get("entries")
        if not isinstance(raw_entries, list):
            raise ValueError(f"manifest has no 'entries' list: {path}")

        key = cls(kind="operator-manifest", root=str(path), manifest=str(path))
        for index, item in enumerate(raw_entries):
            where = f"entries[{index}]"
            if not isinstance(item, dict):
                key.excluded.append(Excluded(file=where, reason="entry is not a mapping"))
                continue
            digest = str(item.get("sha256") or "").strip().lower()
            if not _SHA256_RE.match(digest):
                key.excluded.append(
                    Excluded(file=where, reason="missing or malformed sha256 (need 64 hex)")
                )
                continue
            techniques = [
                str(t).strip().upper() for t in (item.get("techniques") or []) if str(t).strip()
            ]
            entities = [str(e).strip() for e in (item.get("entities") or []) if str(e).strip()]
            role = str(item.get("role") or "").strip().lower()
            if role == "benign":
                # A file the operator declares clean. It contributes no expected
                # technique, but it must be listed so the false-positive metric
                # can attribute a finding's cited rows to benign evidence
                # (WO-K1: "DRAFTs whose cited rows come only from benign files").
                key.benign.append(digest)
                continue
            if not techniques and not entities:
                key.excluded.append(
                    Excluded(
                        file=where,
                        reason="no techniques and no entities — nothing to score",
                        sha256=digest,
                    )
                )
                continue
            label = str(item.get("notes") or "").strip()
            window = str(item.get("window") or "").strip()
            for technique in techniques:
                key.entries.append(
                    KeyEntry(file=digest, sha256=digest, technique=technique,
                             label=label, window=window)
                )
            for entity in entities:
                key.entries.append(
                    KeyEntry(file=digest, sha256=digest, entity=entity,
                             label=label, window=window)
                )
        return key

    def restrict_to(self, case_dir: str | Path) -> AnswerKey:
        """Scope the key to the files actually registered in this case, by hash.

        Registered files with no entry become ``unlabelled``; manifest entries
        that are not registered are ``ignored``. Both are reported, so a scoring
        run states which of its inputs it could use rather than quietly scoring
        a subset. Returns a new key; the receiver is unchanged.
        """
        case_dir = Path(case_dir)
        registered = _registered_hashes(case_dir)
        scoped = AnswerKey(
            kind=self.kind,
            root=self.root,
            manifest=self.manifest,
            case=case_dir.name,
            excluded=list(self.excluded),
            # Only benign files actually registered in this case count.
            benign=[h for h in self.benign if h in registered],
        )
        covered: set[str] = set()
        ignored: set[str] = set()
        for entry in self.entries:
            digest = (entry.sha256 or "").strip().lower()
            if not digest:
                # Nothing to match on; keep it rather than silently discarding.
                scoped.entries.append(entry)
                continue
            if digest in registered:
                scoped.entries.append(entry)
                covered.add(digest)
            elif digest not in ignored:
                ignored.add(digest)
                scoped.ignored.append(
                    {"sha256": digest, "reason": "not registered in this case"}
                )
        for digest, names in sorted(registered.items()):
            if digest not in covered:
                scoped.unlabelled.append(Unlabelled(sha256=digest, names=names))
        scoped.matched = len(covered)
        return scoped

    def entries_for_sha(self, sha256: str) -> list[KeyEntry]:
        """Entries labelled for one file hash."""
        wanted = (sha256 or "").strip().lower()
        return [e for e in self.entries if (e.sha256 or "").lower() == wanted]


def _registered_hashes(case_dir: Path) -> dict[str, list[str]]:
    """``sha256 -> names`` from a case's evidence registry. Absent file is empty."""
    path = Path(case_dir) / "evidence.json"
    if not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    items = loaded if isinstance(loaded, list) else (loaded.get("evidence") or [])
    if not isinstance(items, list):
        return {}
    out: dict[str, list[str]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        digest = str(
            item.get("sha256") or item.get("file_hash_sha256") or ""
        ).strip().lower()
        if not digest:
            continue
        names = out.setdefault(digest, [])
        name = str(item.get("name") or item.get("path") or "").strip()
        if name and name not in names:
            names.append(name)
    return out


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