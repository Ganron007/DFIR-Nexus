"""Inventory candidate family producers from the lane and importer definitions.

This is a source inventory, not an assertion that each candidate has produced
populated evidence. Dynamic output-directory arguments are reported explicitly.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

from nexus.ingest.registry import get_registry
from nexus.ingest.schemas import ArtifactSource
from nexus.langgraph.lane_gate import STAGED_FAMILY
from nexus.langgraph.query_pack import _FAMILY_HINTS, _TOOL_FAMILIES, _TREE_TOOLS, _family

REPO = Path(__file__).resolve().parents[2]
LANE = REPO / "src/nexus/langgraph/tool_lane.py"
NETWORK_LANE = REPO / "src/nexus/langgraph/network_lane.py"


def inventory() -> dict:
    source = LANE.read_text(encoding="utf-8")
    directories: dict[str, list[int]] = {}
    dynamic: list[dict] = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "out_dir" and node.args):
            continue
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            directories.setdefault(arg.value, []).append(node.lineno)
        else:
            dynamic.append({"line": node.lineno, "argument": ast.get_source_segment(source, arg)})

    # These virtual paths exercise the actual family classifier; no files are created or parsed.
    root = Path("extractions")
    projected = {name: _family(root / name / "rows.csv", root) for name in sorted(directories)}
    stdout = {name: _family(root / f"{name}-capture-digest.txt", root)
              for name in (*_TOOL_FAMILIES, *_TREE_TOOLS)}
    direct_paths: dict[str, list[str]] = {}
    tool_names: dict[str, list[str]] = {}
    for path in (LANE, NETWORK_LANE):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                    and any(isinstance(part, ast.Name) and part.id == "extractions"
                            for part in ast.walk(node.left))
                    and isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)):
                direct_paths.setdefault(node.right.value, []).append(f"{path.name}:{node.lineno}")
            if (isinstance(node, ast.keyword) and node.arg == "tool"
                    and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                tool_names.setdefault(node.value.value, []).append(f"{path.name}:{node.value.lineno}")
    registry = get_registry()
    importers = [
        {"source": source_type.value,
         "classes": [f"{cls.__module__}.{cls.__name__}" for cls in registry.candidates(source_type)]}
        for source_type in registry.all_sources()
    ]
    evidence: dict[str, dict[str, list[str]]] = {}

    def add(name: str, kind: str, refs: list[str]) -> None:
        if name:
            evidence.setdefault(name, {}).setdefault(kind, []).extend(refs)

    for folder, family in projected.items():
        add(family, "out_dir_projection", [f"tool_lane.py:{n}" for n in directories[folder]])
    for tool, family in stdout.items():
        add(family, "stdout_name_projection", [f"query_pack.py:_TOOL_FAMILIES/{tool}"])
    for folder, refs in direct_paths.items():
        if not folder.startswith("_") and not folder.endswith(".json"):
            # A literal path reference is a candidate: it may be nested or input staging.
            add(_family(root / folder / "rows.csv", root), "direct_path_projection", refs)
    for name, refs in tool_names.items():
        if not name.startswith("("):
            add(name, "literal_job_tool", refs)
    for row in importers:
        add(row["source"], "registered_importer_source", row["classes"])
    for source_type in ArtifactSource:
        add(source_type.value, "declared_artifact_source", ["ingest/schemas.py:ArtifactSource"])
    for name in _FAMILY_HINTS:
        add(name, "classifier_hint", ["query_pack.py:_FAMILY_HINTS"])
    for artifact, family in STAGED_FAMILY.items():
        add(family, "staged_family", [f"lane_gate.py:STAGED_FAMILY/{artifact}"])
    return {
        "lane_out_dirs": directories,
        "dynamic_out_dirs": dynamic,
        "folder_family_projection": projected,
        "stdout_family_projection": stdout,
        "direct_extraction_paths": direct_paths,
        "literal_tool_names": tool_names,
        "classifier_hints": list(_FAMILY_HINTS),
        "registered_importers": importers,
        "declared_artifact_sources": [source_type.value for source_type in ArtifactSource],
        "candidate_evidence": evidence,
    }


if __name__ == "__main__":
    print(json.dumps(inventory(), indent=2, sort_keys=True))
