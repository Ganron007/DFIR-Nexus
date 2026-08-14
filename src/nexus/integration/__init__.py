"""DFIR-Nexus Integration Module.

Phase 6 — Velociraptor monitoring, case export, AI vision.
"""

from nexus.integration.case_export import (
    CaseExporter,
    export_to_html,
    export_to_json,
    export_to_markdown,
    export_to_stix,
)
from nexus.integration.export_formats import (
    export_case_zip,
    export_findings_csv,
    export_to_docx,
)
from nexus.integration.exporters import (
    build_misp_attributes,
    build_timesketch_timeline,
    push_iris,
    push_misp,
    push_timesketch,
)
from nexus.integration.knowledge_graph import build_case_knowledge_graph
from nexus.integration.notifications import notify_channel
from nexus.integration.vql_runner import (
    HTTPVelociraptorClient,
    MockVelociraptorClient,
    MonitorConfig,
    VQLQuerySpec,
    VQLResult,
    VQLRunner,
)

__all__ = [
    "CaseExporter",
    "HTTPVelociraptorClient",
    "MockVelociraptorClient",
    "MonitorConfig",
    "VQLQuerySpec",
    "VQLResult",
    "VQLRunner",
    "build_case_knowledge_graph",
    "build_misp_attributes",
    "build_timesketch_timeline",
    "export_case_zip",
    "export_findings_csv",
    "export_to_docx",
    "export_to_html",
    "export_to_json",
    "export_to_markdown",
    "export_to_stix",
    "notify_channel",
    "push_iris",
    "push_misp",
    "push_timesketch",
]
