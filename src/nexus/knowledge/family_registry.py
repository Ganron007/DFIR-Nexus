"""Shared family vocabulary with directional evidence-kind matching.

The registry describes what each producer can yield. A requirement naming a
producer matches that producer; a requirement naming an evidence kind matches
any producer that yields that kind. Two producers do not become synonyms merely
because both yield one kind: memory event logs do not make an EVTX parser a
memory-image parser.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

REGISTRY_PATH = Path(__file__).resolve().parents[1] / "data/schema/family_registry.yaml"


def _name(value: Any) -> str:
    return str(value or "").strip().lower()


class FamilyRegistry:
    """Validated names, aliases and kinds from one registry document."""

    def __init__(self, document: dict[str, Any]):
        families = document.get("families")
        if not isinstance(families, dict) or not families:
            raise ValueError("family registry must contain a nonempty families mapping")
        self._aliases: dict[str, str] = {}
        self._names: dict[str, set[str]] = {}
        self._kinds: dict[str, set[str]] = {}
        self._importers: dict[str, str] = {}
        self._importer_spellings: dict[str, str] = {}
        self._containers: set[str] = set()
        self._platforms: dict[str, str] = {}
        self._classes: dict[str, str] = {}
        self._completeness: dict[str, str] = {}
        self._priorities: dict[str, str] = {}
        for raw_name, spec in families.items():
            name = _name(raw_name)
            if not name or not isinstance(spec, dict):
                raise ValueError(f"invalid family entry: {raw_name!r}")
            if name in self._names:
                raise ValueError(f"duplicate family name after normalization: {name!r}")
            aliases = spec.get("aliases", [])
            kinds = spec.get("kinds", [])
            importers = spec.get("importer_classes", [])
            if not isinstance(aliases, list) or not isinstance(kinds, list) or not isinstance(importers, list):
                raise ValueError(f"family {name}: aliases, kinds and importer_classes must be lists")
            names = {name, *(_name(alias) for alias in aliases)}
            if "" in names or any(item.startswith("kind:") for item in names):
                raise ValueError(f"family {name}: invalid family name or alias")
            for item in names:
                previous = self._aliases.get(item)
                if previous is not None and previous != name:
                    raise ValueError(f"family alias {item!r} belongs to both {previous!r} and {name!r}")
                self._aliases[item] = name
            self._names[name] = names
            self._kinds[name] = {_name(kind).removeprefix("kind:") for kind in kinds}
            if "" in self._kinds[name]:
                raise ValueError(f"family {name}: empty evidence kind")
            container = spec.get("container", False)
            if not isinstance(container, bool) or (container and kinds):
                raise ValueError(f"family {name}: container is true or false, and a container yields no evidence kind")
            if container:
                self._containers.add(name)
            if spec.get("platform") is not None:
                if not _name(spec["platform"]) or not spec.get("platform_source"):
                    raise ValueError(f"family {name}: a platform needs its platform_source")
                self._platforms[name] = _name(spec["platform"])
            if spec.get("class"):
                self._classes[name] = _name(spec["class"])
            if spec.get("completeness"):
                self._completeness[name] = _name(spec["completeness"])
            if spec.get("priority"):
                self._priorities[name] = _name(spec["priority"])
            for importer in importers:
                identifier = _name(importer)
                if not identifier or identifier in self._importers:
                    raise ValueError(f"duplicate or empty importer class: {importer!r}")
                self._importers[identifier] = name
                self._importer_spellings[identifier] = str(importer)
        self._known_kinds = set().union(*self._kinds.values())
        self._kind_platforms: dict[str, str] = {}
        for raw_kind, spec in (document.get("kind_platforms") or {}).items():
            kind = _name(raw_kind).removeprefix("kind:")
            if (kind not in self._known_kinds or not isinstance(spec, dict) or not _name(spec.get("platform"))
                    or not spec.get("source")):
                raise ValueError(f"kind_platforms {raw_kind!r}: a known kind with a platform and its source")
            self._kind_platforms[kind] = _name(spec["platform"])

    @classmethod
    def load(cls, path: Path = REGISTRY_PATH) -> FamilyRegistry:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise ValueError("family registry must be a mapping")
        return cls(doc)

    def names(self, value: str) -> set[str]:
        """Return exact producer spellings, or the kind token for a kind selector."""
        value = _name(value)
        if not value:
            return set()
        if value.startswith("kind:"):
            return {value}
        canonical = self._aliases.get(value)
        if canonical:
            names = set(self._names[canonical])
            # A source can have the same name as its evidence kind (EVTX is one).
            # The bare selector remains usable for both; `kind:` is explicit.
            if value in self._known_kinds:
                names.add(f"kind:{value}")
            return names
        if value in self._known_kinds:
            return {f"kind:{value}"}
        return {value}

    def kinds_of(self, family: str) -> set[str]:
        """The evidence kinds a producer yields (any of its spellings); empty for an unknown name."""
        canonical = self._aliases.get(_name(family))
        return set(self._kinds[canonical]) if canonical else set()

    def platforms(self, families: Iterable[str]) -> set[str]:
        """The platforms a case's producers place it on (D484): a producer's own `platform`, or that of an evidence
        kind it yields (`kind_platforms`, each from its pinned artifact entry). Empty when none says."""
        out: set[str] = set()
        for family in families:
            canonical = self._aliases.get(_name(family))
            if canonical is None:
                continue
            if canonical in self._platforms:
                out.add(self._platforms[canonical])
            out |= {self._kind_platforms[kind] for kind in self._kinds[canonical] if kind in self._kind_platforms}
        return out

    def is_container(self, family: str) -> bool:
        """Whether a producer's rows hold whatever its input held (the generic CSV and JSONL importers, spreadsheets):
        its name says nothing about the evidence, so it is never a reason to choose knowledge. The importer class
        that actually parsed a row (its evidence group) says what the row is."""
        return self._aliases.get(_name(family)) in self._containers

    def known(self, selector: str) -> bool:
        """Whether a selector names a registry producer (any of its spellings) or an evidence kind. A name that is
        neither can never be matched by any case: it is a vocabulary defect, not a coverage gap."""
        value = _name(selector)
        if value.startswith("kind:"):
            return value[5:] in self._known_kinds
        return value in self._aliases or value in self._known_kinds

    def intersect(self, case_families: Iterable[str], declared: Iterable[str]) -> set[str]:
        """Return matching declared selectors, without transitive producer equivalence."""
        available: set[str] = set()
        for family in case_families:
            available.update(self.names(family))
            canonical = self._aliases.get(_name(family))
            if canonical:
                available.update(f"kind:{kind}" for kind in self._kinds[canonical])
        return {str(item) for item in declared if self.names(item) & available}

    def producers_for(self, selector: str) -> set[str]:
        """Resolve a selector to producer names for consumers that need field inventories."""
        value = _name(selector)
        if value.startswith("kind:"):
            kind = value[5:]
        elif value in self._aliases and value not in self._known_kinds:
            return self.names(value)
        elif value in self._known_kinds:
            kind = value
        else:
            return {value} if value else set()
        result = {spelling for name, kinds in self._kinds.items() if kind in kinds for spelling in self._names[name]}
        if value in self._aliases:
            result.update(self._names[self._aliases[value]])
        return result

    def importer_families(self, importer_classes: Iterable[str]) -> set[str]:
        """Producer families justified by actual observed importer classes."""
        return {self._importers[name] for item in importer_classes
                if (name := _name(item)) in self._importers}

    def canonical_family(self, value: str) -> str:
        """A producer's canonical name; unknown selectors retain their spelling."""
        name = _name(value)
        return self._aliases.get(name, name)

    def class_of(self, family: str) -> str:
        """The evidence class of a family: detection, raw, enriched, imported, reference, container, or unclassified."""
        norm = _name(family)
        canonical = self._aliases.get(norm, norm)
        if canonical in self._classes:
            return self._classes[canonical]
        if canonical in _DETECTION_FAMILIES or "detection" in canonical or canonical in ("densityscout",):
            return "detection"
        if self.is_container(canonical) or canonical in _CONTAINER_FAMILIES:
            return "container"
        if canonical in _REFERENCE_FAMILIES:
            return "reference"
        if canonical in _ENRICHED_FAMILIES:
            return "enriched"
        if canonical in _IMPORTED_FAMILIES:
            return "imported"
        if norm in self._aliases or norm in self._known_kinds or norm.removeprefix("kind:") in self._known_kinds:
            return "raw"
        return "unclassified"

    def completeness_of(self, family: str) -> str:
        """The completeness of a family: filtered (detections), complete (raw), partial, sampled, or unknown."""
        canonical = self._aliases.get(_name(family))
        if canonical in self._completeness:
            return self._completeness[canonical]
        cls = self.class_of(family)
        if cls == "detection":
            return "filtered"
        if cls in ("raw", "enriched"):
            return "complete"
        if cls in ("imported", "container"):
            return "partial"
        if cls == "reference":
            return "sampled"
        return "unknown"

    def priority_of(self, family: str) -> str:
        """The investigation priority: leads (detection), primary (raw/enriched), context (imported/container)."""
        canonical = self._aliases.get(_name(family))
        if canonical in self._priorities:
            return self._priorities[canonical]
        cls = self.class_of(family)
        if cls == "detection":
            return "leads"
        if cls in ("raw", "enriched"):
            return "primary"
        return "context"

    def has_absence_authority(self, family: str) -> bool:
        """Whether absence of an event in this family proves non-occurrence.

        True only for complete raw or enriched forensic artifacts. Detection families
        (filtered alerts) never carry absence authority (EV-SEM.4).
        """
        return self.class_of(family) in ("raw", "enriched") and self.completeness_of(family) == "complete"

    def family_semantics(self, family: str) -> dict[str, Any]:
        """Complete semantic descriptor for a family (EV-SEM.2, EV-SEM.3)."""
        canonical = self.canonical_family(family)
        cls = self.class_of(family)
        comp = self.completeness_of(family)
        prio = self.priority_of(family)
        auth = self.has_absence_authority(family)
        kinds = sorted(self.kinds_of(family))
        platforms = sorted(self.platforms([family]))
        platform = platforms[0] if platforms else "any"
        return {
            "family": family,
            "canonical": canonical,
            "class": cls,
            "completeness": comp,
            "priority": prio,
            "absence_authority": auth,
            "kinds": kinds,
            "platform": platform,
        }

    def evidence_group(self, source: str, importer_classes: Iterable[str]) -> set[str]:
        """All selectors belonging to one indexed source/provenance group."""
        family = _name(source)
        return ({family} if family else set()) | self.importer_families(importer_classes)

    def importer_classes_for(self, selectors: Iterable[str]) -> set[str]:
        """Concrete importer classes associated with the declared producer selectors."""
        families = {self._aliases.get(_name(selector), _name(selector)) for selector in selectors}
        return {self._importer_spellings[identifier] for identifier, family in self._importers.items()
                if family in families}


def family_source_query(selectors: Iterable[str]) -> dict[str, Any]:
    """Query both native family rows and precisely identified importer rows."""
    names = list(dict.fromkeys(str(item) for item in selectors if str(item).strip()))
    if not names:
        raise ValueError("family source query requires a selector")
    family = {"terms": {"family": names}}
    importers = sorted(get_family_registry().importer_classes_for(names))
    if not importers:
        return family
    return {"bool": {"should": [family, {"terms": {"importer_leaf": importers}}], "minimum_should_match": 1}}


def encode_evidence_group(source: str, importer_classes: Iterable[str]) -> str:
    """Stable index key; store actual class names, not derived knowledge labels."""
    return json.dumps([_name(source), sorted({_name(value) for value in importer_classes if _name(value)})],
                      ensure_ascii=True, separators=(",", ":"))


def decode_evidence_group(value: str) -> tuple[str, list[str]]:
    """Decode a materialized source/class key, rejecting incomplete data."""
    try:
        payload = json.loads(value)
        if (not isinstance(payload, list) or len(payload) != 2 or not isinstance(payload[0], str)
                or not payload[0] or not isinstance(payload[1], list)
                or not all(isinstance(item, str) and item for item in payload[1])):
            raise ValueError("invalid source or importers")
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid indexed evidence group") from exc
    return payload[0], payload[1]


def selection_groups(index_groups: list[dict[str, Any]], sources: Iterable[str] | None = None) -> list[set[str]]:
    """Select measured index groups, retaining each source/importer relationship."""
    wanted = {_name(source) for source in sources} if sources is not None else None
    result = []
    for group in index_groups:
        if not isinstance(group, dict) or not isinstance(group.get("families"), list):
            raise ValueError("invalid measured evidence group")
        source = _name(group.get("source"))
        names = {_name(name) for name in group["families"] if _name(name)}
        if not source or source not in names or int(group.get("rows") or 0) <= 0:
            raise ValueError("incomplete measured evidence group")
        if wanted is None or source in wanted:
            result.append(names)
    return result


def hit_evidence_families(hits: Iterable[dict[str, Any]]) -> set[str]:
    """Evidence selectors actually present on retrieved rows."""
    registry = get_family_registry()
    families: set[str] = set()
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        importers = hit.get("importer_leaf") if isinstance(hit.get("importer_leaf"), list) else []
        families.update(registry.evidence_group(str(hit.get("family") or ""), importers))
    return families


@lru_cache(maxsize=1)
def get_family_registry() -> FamilyRegistry:
    return FamilyRegistry.load()


def family_names(family: str) -> set[str]:
    return get_family_registry().names(family)


def families_intersect(case_families: Iterable[str], declared: Iterable[str]) -> set[str]:
    return get_family_registry().intersect(case_families, declared)


_DETECTION_FAMILIES = frozenset({
    "hayabusa", "chainsaw", "sigma", "deepbluecli", "yara", "suricata",
    "zeek_notice", "zircolite", "capa", "defender_detectionhistory",
    "densityscout",
})

_CONTAINER_FAMILIES = frozenset({
    "generic_csv", "generic_jsonl", "csv", "jsonl", "spreadsheet",
})

_REFERENCE_FAMILIES = frozenset({
    "abuseipdb", "virustotal", "threat_intel", "misp", "otx", "kisa",
})

_ENRICHED_FAMILIES = frozenset({
    "plaso", "timeline", "super_timeline", "kusto",
})

_IMPORTED_FAMILIES = frozenset({
    "aws_s3_access", "aws_vpc_flow", "azure", "azure_activity", "azure_signin",
    "cloudtrail", "crowdstrike", "sentinelone", "carbon_black", "elastic",
    "splunk", "cybertriage", "axiom", "ftk", "x-ways", "encase", "gcp_audit",
})


def class_of(family: str) -> str:
    """The evidence class of a family."""
    return get_family_registry().class_of(family)


def completeness_of(family: str) -> str:
    """The completeness of a family."""
    return get_family_registry().completeness_of(family)


def priority_of(family: str) -> str:
    """The priority of a family."""
    return get_family_registry().priority_of(family)


def has_absence_authority(family: str) -> bool:
    """Whether this family has authority to prove non-occurrence."""
    return get_family_registry().has_absence_authority(family)


def family_semantics(family: str) -> dict[str, Any]:
    """Complete semantic descriptor for a family (EV-SEM.2)."""
    return get_family_registry().family_semantics(family)


def case_coverage_statement(
    case_dir: Path | str | None = None,
    family_rows: dict[str, int] | list[str] | set[str] | None = None,
) -> dict[str, Any]:
    """Compute the per-class coverage statement for a case (EV-SEM.6)."""
    registry = get_family_registry()
    observed: set[str] = set()
    if family_rows is not None:
        if isinstance(family_rows, dict):
            observed = {str(k).strip() for k in family_rows if str(k).strip()}
        else:
            observed = {str(k).strip() for k in family_rows if str(k).strip()}
    elif case_dir is not None:
        cpath = Path(case_dir)
        ev_file = cpath / "evidence.json"
        if ev_file.is_file():
            try:
                raw = json.loads(ev_file.read_text(encoding="utf-8"))
                items = raw if isinstance(raw, list) else (raw.get("files") or [])
                for item in items:
                    fam = item.get("recognized_family") or item.get("family")
                    if fam:
                        observed.add(str(fam).strip())
            except Exception:
                pass
        ext_dir = cpath / "extractions"
        if ext_dir.is_dir():
            try:
                for child in ext_dir.iterdir():
                    if child.is_dir():
                        observed.add(child.name)
            except Exception:
                pass

    by_class: dict[str, list[str]] = {
        "raw": [],
        "detection": [],
        "imported": [],
        "enriched": [],
        "reference": [],
        "container": [],
        "unclassified": [],
    }
    for fam in sorted(observed):
        cls = registry.class_of(fam)
        if cls not in by_class:
            cls = "unclassified"
        by_class[cls].append(fam)

    raw_count = len(by_class["raw"])
    detection_count = len(by_class["detection"])
    imported_count = len(by_class["imported"])
    enriched_count = len(by_class["enriched"])
    reference_count = len(by_class["reference"])
    container_count = len(by_class["container"])
    unclassified_count = len(by_class["unclassified"])

    parts: list[str] = []
    parts.append(f"raw families complete ({raw_count})")
    parts.append(f"detection families filtered ({detection_count})")
    if imported_count:
        parts.append(f"imported/cloud telemetry ({imported_count})")
    if enriched_count:
        parts.append(f"enriched timelines ({enriched_count})")
    if reference_count:
        parts.append(f"reference/intel ({reference_count})")
    if container_count:
        parts.append(f"containers ({container_count})")
    if unclassified_count:
        parts.append(f"unclassified ({unclassified_count})")

    statement = "; ".join(parts)
    return {
        "statement": statement,
        "by_class": {k: sorted(v) for k, v in by_class.items()},
        "raw": sorted(by_class["raw"]),
        "raw_count": raw_count,
        "detection": sorted(by_class["detection"]),
        "detection_count": detection_count,
        "imported": sorted(by_class["imported"]),
        "imported_count": imported_count,
        "enriched": sorted(by_class["enriched"]),
        "enriched_count": enriched_count,
        "reference": sorted(by_class["reference"]),
        "reference_count": reference_count,
        "container": sorted(by_class["container"]),
        "container_count": container_count,
        "unclassified": sorted(by_class["unclassified"]),
        "unclassified_count": unclassified_count,
        "raw_complete": True,
        "detection_filtered": True,
    }


def render_coverage_statement(
    case_dir: Path | str | None = None,
    family_rows: dict[str, int] | list[str] | set[str] | None = None,
) -> str:
    """Render human-readable per-class coverage statement string."""
    stmt = case_coverage_statement(case_dir, family_rows)
    return str(stmt.get("statement") or "")



