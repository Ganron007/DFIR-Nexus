"""Forensic knowledge base — YAML-driven artifact, tool, and discipline data.

Provides enrichment context for tool responses: caveats, advisories,
corroboration suggestions, investigation playbooks, and discipline rules.
"""

from nexus.knowledge.loader import (
    get_artifact,
    list_artifacts,
    get_artifacts_for_tool,
    get_tool,
    list_tools,
    get_rules,
    get_playbook,
    list_playbooks,
    get_confidence_definitions,
    get_anti_patterns,
    get_evidence_standards,
    get_evidence_template,
    get_checkpoint,
    list_checkpoints,
    get_corroboration,
    get_false_positive_context,
    get_tool_interpretation,
    get_collection_checklist,
    get_investigation_framework,
    clear_cache,
)

__all__ = [
    "get_artifact", "list_artifacts", "get_artifacts_for_tool",
    "get_tool", "list_tools",
    "get_rules", "get_playbook", "list_playbooks",
    "get_confidence_definitions", "get_anti_patterns",
    "get_evidence_standards", "get_evidence_template",
    "get_checkpoint", "list_checkpoints",
    "get_corroboration", "get_false_positive_context",
    "get_tool_interpretation", "get_collection_checklist",
    "get_investigation_framework", "clear_cache",
]
