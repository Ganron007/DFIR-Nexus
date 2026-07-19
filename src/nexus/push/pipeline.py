"""Push ingest pipeline — normalize, register evidence, optional findings."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from enum import Enum
from typing import Any

try:
    from nexus.case import ApprovalState, FindingSeverity
except ImportError:
    class ApprovalState(str, Enum):  # noqa: UP042
        DRAFT = "draft"
        PENDING_REVIEW = "pending_review"
        APPROVED = "approved"
        REJECTED = "rejected"

    class FindingSeverity(str, Enum):  # noqa: UP042
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
        INFORMATIONAL = "informational"

from nexus.push.payload import normalize_push_payload

log = logging.getLogger(__name__)


class PushPipeline:
    """Process inbound push payloads into case evidence + metadata."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    def process(self, case_id: str, body: dict[str, Any] | list[Any]) -> dict[str, Any]:
        if self.manager is None:
            return {"success": False, "error": "Case manager is not available"}

        case = self.manager.get_case(case_id)
        if case is None:
            return {"success": False, "error": f"Case not found: {case_id}"}

        envelope = normalize_push_payload(body)
        kind = envelope.get("kind", "unknown")
        registered = 0
        errors: list[str] = []

        if kind == "capture":
            ok = self._register_capture(case_id, envelope.get("capture") or {})
            registered += int(ok)
        elif kind in {"capture_batch", "batch"}:
            for capture in envelope.get("captures") or []:
                if self._register_capture(case_id, capture):
                    registered += 1
        elif kind == "artifact_batch":
            for artifact in envelope.get("artifacts") or []:
                if isinstance(artifact, dict):
                    ok = self._register_artifact_dict(case_id, artifact)
                    registered += int(ok)
        else:
            # Generic JSON blob as evidence
            name = f"push-{kind}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
            self.manager.add_evidence(
                case_id,
                name=name,
                description=f"Push ingest ({kind})",
                collected_by="push-server",
                metadata={"push_envelope": envelope},
            )
            registered = 1

        # Optional auto-finding when captures look suspicious
        finding_id = None
        if registered and self._should_raise_finding(envelope):
            finding = self.manager.add_finding(
                case_id,
                title="Push capture flagged for review",
                description="Automated triage of inbound push capture",
                severity=FindingSeverity.MEDIUM,
                created_by="push-server",
                metadata={"push_kind": kind},
                initial_state=ApprovalState.DRAFT,
            )
            finding_id = finding.id if finding else None

        return {
            "success": True,
            "case_id": case_id,
            "kind": kind,
            "registered": registered,
            "errors": errors,
            "finding_id": finding_id,
        }

    def _register_capture(self, case_id: str, capture: dict[str, Any]) -> bool:
        if not capture:
            return False
        title = str(capture.get("title") or "capture")
        body_preview = capture.get("body")
        if isinstance(body_preview, (dict, list)):
            body_preview = json.dumps(body_preview)[:4000]
        self.manager.add_evidence(
            case_id,
            name=title[:120],
            description=str(body_preview or "")[:2000],
            collected_by="push-server",
            metadata={
                "push_capture": capture,
                "source": capture.get("source"),
                "url": capture.get("url"),
            },
        )
        return True

    def _register_artifact_dict(self, case_id: str, artifact: dict[str, Any]) -> bool:
        self.manager.add_evidence(
            case_id,
            name=str(artifact.get("description") or artifact.get("id") or "artifact")[:120],
            description=json.dumps(artifact)[:2000],
            artifact_id=artifact.get("id"),
            collected_by="push-server",
            metadata={"push_artifact": artifact},
        )
        return True

    @staticmethod
    def _should_raise_finding(envelope: dict[str, Any]) -> bool:
        text = json.dumps(envelope).lower()
        return any(x in text for x in ("mimikatz", "lsass", "beacon", "cobalt", "ransom"))
