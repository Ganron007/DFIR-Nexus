"""KL1 regression guards: ensure KB is completely removed from product runtime."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import nexus
from nexus.app import create_server, in_process_tools
from nexus.langgraph.backbone import MODE2_TOOL_ALLOWLIST
from nexus.langgraph.context_loop import _TOOL_ARGS
from nexus.modes.multi_role import ROLES


def test_serve_and_loops_register_no_kb_tools():
    """`serve` registers no kb_* tool, and no loop tool or role allowlist names one."""
    server = create_server()
    tools = in_process_tools(server)
    kb_tools = [name for name in tools if name.startswith("kb_")]
    assert not kb_tools, f"FastMCP registered unexpected KB tools: {kb_tools}"

    for role_name, role_obj in ROLES.items():
        role_kb = [t for t in role_obj.tools if t.startswith("kb_") or "kb" in t.lower()]
        assert not role_kb, f"Role {role_name} tools contains KB tools: {role_kb}"

    loop_kb = [t for t in _TOOL_ARGS if t.startswith("kb_") or "kb" in t.lower()]
    assert not loop_kb, f"context_loop._TOOL_ARGS contains KB tools: {loop_kb}"

    backbone_kb = [t for t in MODE2_TOOL_ALLOWLIST if t.startswith("kb_")]
    assert not backbone_kb, f"MODE2_TOOL_ALLOWLIST contains KB tools: {backbone_kb}"


def test_src_nexus_has_no_kb_references():
    """src/nexus must not contain doc_extract, NEXUS_KB_DIR, kb_bridge, kb_query, or kb_search."""
    nexus_root = Path(nexus.__file__).parent
    forbidden = ["doc_extract", "NEXUS_KB_DIR", "kb_bridge", "kb_query", "kb_search"]

    violations: list[str] = []
    for path in nexus_root.rglob("*"):
        if path.is_file() and path.suffix in {".py", ".yaml", ".yml", ".json", ".md", ".txt"}:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for token in forbidden:
                if token in content:
                    violations.append(f"{path.relative_to(nexus_root)} contains {token}")

    assert not violations, "Forbidden KB references found in src/nexus:\n" + "\n".join(violations)


def test_case_quarantine_contamination_guard():
    """Contamination guard: asserts no shipped knowledge file or RAG doc contains case identifiers."""
    quarantine_file = os.environ.get("NEXUS_CASE_QUARANTINE_FILE")
    if not quarantine_file or not os.path.exists(quarantine_file):
        pytest.skip("NEXUS_CASE_QUARANTINE_FILE unset or file does not exist")

    # Read case identifiers from file (one per line, ignoring comments/blank lines)
    identifiers: list[str] = []
    with open(quarantine_file, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                identifiers.append(stripped)

    if not identifiers:
        pytest.skip("No case identifiers in quarantine file")

    knowledge_root = Path(nexus.__file__).parent / "data" / "knowledge"
    contaminated: list[str] = []
    for path in knowledge_root.rglob("*"):
        if path.is_file() and path.suffix in {".yaml", ".yml", ".json", ".md", ".txt"}:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for cid in identifiers:
                if cid in content:
                    contaminated.append(f"{path.name} contains quarantined case identifier {cid}")

    assert not contaminated, "Shipped knowledge files contaminated with case data:\n" + "\n".join(contaminated)
