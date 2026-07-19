"""SigmaHQ repository download and indexing."""

from __future__ import annotations

import logging
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import httpx

from nexus.detection.indexer import DetectionIndexer

log = logging.getLogger(__name__)

SIGMAHQ_REPO = "https://github.com/SigmaHQ/sigma"
SIGMAHQ_ZIP = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
DEFAULT_RULES_SUBDIR = Path("rules")


def sigma_rules_path(repo_root: Path) -> Path:
    """Return the rules directory inside a SigmaHQ checkout."""
    direct = repo_root / "rules"
    if direct.is_dir():
        return direct
    nested = repo_root / "sigma-master" / "rules"
    if nested.is_dir():
        return nested
    return direct


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract ZIP members, rejecting path traversal outside dest."""
    dest = Path(dest).resolve()
    for member in zf.infolist():
        target = dest / member.filename
        target_resolved = target.resolve()
        try:
            target_resolved.relative_to(dest)
        except ValueError as exc:
            raise RuntimeError(f"Unsafe ZIP member path: {member.filename}") from exc
        zf.extract(member, dest)


def download_sigma_repo(dest: Path, force: bool = False) -> Path:
    """Download SigmaHQ rules to dest. Returns path to rules/ directory.

    Tries shallow git clone first; falls back to ZIP download.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    rules_dir = sigma_rules_path(dest)
    if rules_dir.is_dir() and any(rules_dir.rglob("*.yml")) and not force:
        log.info("SigmaHQ rules already present at %s", rules_dir)
        return rules_dir

    if shutil.which("git"):
        try:
            if dest.joinpath(".git").exists():
                subprocess.run(
                    ["git", "-C", str(dest), "pull", "--depth", "1"],
                    check=True,
                    capture_output=True,
                    timeout=120,
                )
            else:
                subprocess.run(
                    ["git", "clone", "--depth", "1", SIGMAHQ_REPO, str(dest)],
                    check=True,
                    capture_output=True,
                    timeout=180,
                )
            rules_dir = sigma_rules_path(dest)
            if rules_dir.is_dir():
                return rules_dir
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log.warning("git clone failed, falling back to ZIP: %s", e)

    zip_path = dest / "sigma-master.zip"
    with httpx.Client(timeout=120.0, follow_redirects=True) as client:
        resp = client.get(SIGMAHQ_ZIP)
        resp.raise_for_status()
        zip_path.write_bytes(resp.content)

    extract_root = dest / "sigma-extract"
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        _safe_extract_zip(zf, extract_root)
    zip_path.unlink(missing_ok=True)

    # Move sigma-master/rules to dest/rules
    for child in extract_root.iterdir():
        src_rules = child / "rules"
        if src_rules.is_dir():
            target = dest / "rules"
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(src_rules, target)
            shutil.rmtree(extract_root)
            return target

    raise RuntimeError("SigmaHQ ZIP did not contain rules/")


def install_and_index_sigma(
    repo_dest: Path,
    index_dest: Path,
    force_download: bool = False,
) -> dict[str, Any]:
    """Download SigmaHQ (if needed) and index rules into index_dest."""
    rules_dir = download_sigma_repo(repo_dest, force=force_download)
    indexer = DetectionIndexer(index_dest)
    count = indexer.index_sigma_directory(rules_dir)
    return {
        "rules_dir": str(rules_dir),
        "index_path": str(index_dest),
        "rules_indexed": count,
    }


def mitre_navigator_layer(
    technique_ids: list[str],
    name: str = "DFIR-Nexus Coverage",
    description: str = "Techniques observed in case",
) -> dict[str, Any]:
    """Export MITRE ATT&CK Navigator layer v4.5 JSON."""
    techniques = []
    for tid in technique_ids:
        tid = tid.strip().upper()
        if not tid.startswith("T"):
            continue
        techniques.append(
            {
                "techniqueID": tid,
                "color": "#ff6666",
                "comment": "Observed in investigation",
                "enabled": True,
                "score": 1,
            }
        )
    return {
        "name": name,
        "description": description,
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": "observed", "color": "#ff6666"}],
    }


def sigma_to_kql(yaml_content: str) -> str:
    """Translate Sigma YAML to Elastic KQL (requires pysigma)."""
    try:
        from sigma.backends.elastic import ElasticLuceneBackend
        from sigma.collection import SigmaCollection
    except ImportError as e:
        raise ImportError("Install dfir-nexus[detection] for Sigma translation") from e

    collection = SigmaCollection.from_yaml(yaml_content)
    backend = ElasticLuceneBackend()
    lines = []
    for rule in collection.rules:
        converted = backend.convert_rule(rule, output_format="default")
        if converted:
            lines.append(str(converted[0]))
    return "\n".join(lines)


def sigma_to_spl(yaml_content: str) -> str:
    """Translate Sigma YAML to Splunk SPL (requires pysigma)."""
    try:
        from sigma.backends.splunk import SplunkBackend
        from sigma.collection import SigmaCollection
    except ImportError as e:
        raise ImportError("Install dfir-nexus[detection] for Sigma translation") from e

    collection = SigmaCollection.from_yaml(yaml_content)
    # SplunkBackend constructor requires a SigmaConfig in newer pysigma versions;
    # instantiate without args and let pysigma use defaults.
    backend = SplunkBackend()  # type: ignore[call-arg,no-untyped-call]
    lines: list[str] = []
    for rule in collection.rules:
        converted = backend.convert_rule(rule)  # type: ignore[attr-defined]
        if converted:
            lines.append(str(converted[0]))
    return "\n".join(lines)


def sigma_translate(yaml_content: str, target: str = "kql") -> str:
    """Translate Sigma YAML to a SIEM query language.

    Supported targets: kql, elastic, lucene, spl, splunk.
    """
    normalized = target.strip().lower()
    if normalized in ("kql", "elastic", "lucene", "kibana"):
        return sigma_to_kql(yaml_content)
    if normalized in ("spl", "splunk"):
        return sigma_to_spl(yaml_content)
    raise ValueError(f"Unsupported Sigma translation target: {target}")
