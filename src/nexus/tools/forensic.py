"""Investigation records — findings, timeline, TODOs, discipline, reasoning.

All data is persisted to the active case directory as JSON files.
"""

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter
from nexus.case_manager import CaseManager
from nexus.knowledge import loader as fk

manager = CaseManager()
_MAX_TEXT = 10_000
_MAX_SHORT = 200


def _validate_str(value: str | None, field: str, max_len: int) -> None:
    if value is not None and isinstance(value, str):
        if len(value) > max_len:
            raise ValueError(f"{field} exceeds {max_len} characters")
        if "\x00" in value:
            raise ValueError(f"{field} contains null byte")


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def record_finding(
        title: str = "",
        description: str = "",
        observation: str = "",
        interpretation: str = "",
        confidence: str = "MEDIUM",
        confidence_justification: str = "",
        finding_type: str = "",
        artifacts: list[dict] | None = None,
        host: str = "",
        affected_account: str = "",
        event_timestamp: str = "",
        attack_ids: list[str] | None = None,
        mitre_techniques: list[dict] | None = None,
        supporting_commands: list[dict] | None = None,
        iocs: list[dict] | None = None,
        audit_ids: list[str] | None = None,
        analyst_override: str = "",
        finding: dict | None = None,
        itm_stage: str = "",
        itm_objects: list[str] | None = None,
    ) -> dict:
        """Stage a finding as DRAFT for human review.

        Every artifact must include a valid audit_id from a previous
        tool execution. The AI cannot approve its own findings.
        """
        _validate_str(title, "title", 500)
        _validate_str(observation, "observation", _MAX_TEXT)
        _validate_str(interpretation, "interpretation", _MAX_TEXT)
        _validate_str(confidence_justification, "confidence_justification", _MAX_TEXT)
        _validate_str(host, "host", 200)
        _validate_str(affected_account, "affected_account", 200)
        _validate_str(analyst_override, "analyst_override", _MAX_SHORT)

        finding_data = dict(finding or {})
        if title:
            finding_data["title"] = title
        if observation or description:
            finding_data["observation"] = observation or description
        if interpretation:
            finding_data["interpretation"] = interpretation
        if confidence:
            finding_data["confidence"] = confidence.upper()
        if confidence_justification:
            finding_data["confidence_justification"] = confidence_justification
        if finding_type:
            finding_data["type"] = finding_type
        else:
            finding_data.setdefault("type", "finding")
        if host:
            finding_data["host"] = host
        if affected_account:
            finding_data["affected_account"] = affected_account
        if event_timestamp:
            finding_data["event_timestamp"] = event_timestamp
        if attack_ids:
            finding_data["mitre_ids"] = attack_ids
        if mitre_techniques:
            finding_data["mitre_techniques"] = mitre_techniques
        if iocs:
            finding_data["iocs"] = iocs
        if audit_ids:
            finding_data["audit_ids"] = audit_ids
        if itm_stage:
            finding_data["itm_stage"] = itm_stage
        if itm_objects:
            finding_data["itm_objects"] = itm_objects

        try:
            result = manager.record_finding(
                finding_data,
                examiner_override=analyst_override,
                supporting_commands=supporting_commands,
                artifacts=artifacts,
                audit=audit,
            )
        except Exception as e:
            return {"error": str(e)}

        if result.get("status") in ("STAGED", "VALIDATION_FAILED"):
            audit.log(tool="record_finding",
                      params={"title": title, "confidence": confidence},
                      result_summary=result)

        return result

    @server.tool()
    def record_timeline_event(
        timestamp: str,
        description: str,
        event_type: str = "other",
        source: str = "",
        artifact_ref: str = "",
        related_findings: list[str] | None = None,
        host: str = "",
        affected_account: str = "",
        analyst_override: str = "",
    ) -> dict:
        """Record a chronological event in the incident narrative.

        Not every timestamp is a timeline event — only events that
        would appear in the final IR report.
        """
        _validate_str(description, "description", _MAX_TEXT)
        _validate_str(analyst_override, "analyst_override", _MAX_SHORT)

        event = {
            "timestamp": timestamp,
            "description": description,
            "event_type": event_type,
            "source": source,
            "artifact_ref": artifact_ref,
            "related_findings": related_findings or [],
            "host": host,
            "affected_account": affected_account,
        }
        try:
            result = manager.record_timeline_event(
                event, examiner_override=analyst_override)
        except Exception as e:
            return {"error": str(e)}

        audit.log(tool="record_timeline_event",
                  params={"timestamp": timestamp, "event_type": event_type},
                  result_summary=result)
        return result

    @server.tool()
    def get_findings(status: str = "", limit: int = 20, offset: int = 0) -> dict:
        """Retrieve findings filtered by status (DRAFT/APPROVED/REJECTED)."""
        try:
            all_findings = manager.get_findings(status or None)
            total = len(all_findings)
            paginated = all_findings[offset:offset + limit] if limit > 0 else all_findings
            return {"findings": paginated, "total": total, "limit": limit, "offset": offset}
        except Exception as e:
            return {"error": str(e)}

    @server.tool()
    def get_timeline(
        status: str = "",
        event_type: str = "",
        start_date: str = "",
        end_date: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """Retrieve timeline events with optional filters."""
        try:
            all_events = manager.get_timeline(
                status=status or None,
                event_type=event_type or None,
                start_date=start_date or None,
                end_date=end_date or None,
            )
            total = len(all_events)
            paginated = all_events[offset:offset + limit] if limit > 0 else all_events
            return {"events": paginated, "total": total, "limit": limit, "offset": offset,
                    "has_more": total > offset + limit}
        except Exception as e:
            return {"error": str(e)}

    @server.tool()
    def add_todo(
        description: str,
        assignee: str = "",
        priority: str = "medium",
        related_findings: list[str] | None = None,
        analyst_override: str = "",
    ) -> dict:
        """Create a TODO item. Priority: high/medium/low."""
        _validate_str(description, "description", _MAX_TEXT)
        _validate_str(assignee, "assignee", _MAX_SHORT)
        try:
            result = manager.add_todo(description, assignee, priority,
                                      related_findings, analyst_override)
        except Exception as e:
            return {"error": str(e)}
        audit.log(tool="add_todo", params={"description": description[:100]},
                  result_summary=result)
        return result

    @server.tool()
    def list_todos(status: str = "open", assignee: str = "") -> list:
        """List TODO items. Status: open/completed/all."""
        try:
            return manager.list_todos(status, assignee)
        except Exception as e:
            return [{"error": str(e)}]

    @server.tool()
    def update_todo(todo_id: str, status: str = "", note: str = "",
                    assignee: str = "", priority: str = "",
                    analyst_override: str = "") -> dict:
        """Update a TODO — change status, add note, reassign."""
        try:
            result = manager.update_todo(todo_id, status, note, assignee,
                                          priority, analyst_override)
        except Exception as e:
            return {"error": str(e)}
        return result

    @server.tool()
    def complete_todo(todo_id: str, analyst_override: str = "") -> dict:
        """Mark a TODO as completed."""
        try:
            result = manager.complete_todo(todo_id, analyst_override)
        except Exception as e:
            return {"error": str(e)}
        return result

    @server.tool()
    def log_reasoning(text: str, analyst_override: str = "") -> dict:
        """Record analytical reasoning to the audit trail.

        No approval needed. Call when choosing what to examine next,
        forming a hypothesis, or ruling something out.
        """
        _validate_str(text, "text", _MAX_TEXT)
        audit.log(tool="log_reasoning",
                  params={"text": text[:500], "analyst_override": analyst_override},
                  result_summary={"status": "logged"},
                  source="orchestrator")
        return {"status": "logged"}

    @server.tool()
    def log_external_action(
        command: str,
        output_summary: str,
        purpose: str,
        analyst_override: str = "",
        hook_audit_id: str = "",
        input_files: list[str] | None = None,
        output_files: list[str] | None = None,
    ) -> dict:
        """Record a non-MCP tool execution (e.g. via Bash) in the audit trail.

        Returns an audit_id that can be used in record_finding's
        artifacts list for provenance tracking.
        """
        _validate_str(command, "command", _MAX_TEXT)
        _validate_str(output_summary, "output_summary", _MAX_TEXT)
        _validate_str(purpose, "purpose", _MAX_TEXT)
        _validate_str(analyst_override, "analyst_override", _MAX_SHORT)

        source = "orchestrator_verified" if hook_audit_id else "orchestrator_voluntary"
        audit_id = audit.log(
            tool="log_external_action",
            params={"command": command[:200], "purpose": purpose[:200]},
            result_summary={"status": "logged", "source": source},
            source=source,
            input_files=input_files or None,
        )
        return {
            "status": "logged",
            "audit_id": audit_id,
            "source": source,
        }

    @server.tool()
    def get_investigation_framework() -> dict:
        """Get the full investigation framework: phases, rules, playbooks."""
        return fk.get_investigation_framework() or {"note": "No framework data loaded"}

    @server.tool()
    def get_rules() -> list:
        """Get all forensic discipline rules for investigation methodology."""
        return fk.get_rules()

    @server.tool()
    def get_checkpoint_requirements(action_type: str) -> dict:
        """Get requirements that must be met before taking a specific action.

        Args:
            action_type: Checkpoint type (attribution, root_cause, exclusion, containment, eradication, recovery, notification)
        """
        result = fk.get_checkpoint(action_type)
        if result:
            return result
        return {"error": f"No checkpoint found for '{action_type}'", "available": fk.list_checkpoints()}

    @server.tool()
    def get_evidence_standards() -> list:
        """Get evidence classification levels and standards."""
        return fk.get_evidence_standards()

    @server.tool()
    def get_confidence_definitions() -> dict:
        """Get confidence level criteria for findings (HIGH/MEDIUM/LOW)."""
        return fk.get_confidence_definitions()

    @server.tool()
    def get_anti_patterns() -> list:
        """Get common forensic mistakes (anti-patterns) to avoid."""
        return fk.get_anti_patterns()

    @server.tool()
    def get_evidence_template() -> dict:
        """Get the required evidence format template."""
        return fk.get_evidence_template()

    @server.tool()
    def get_tool_guidance(tool_name: str) -> dict:
        """Get interpretation guidance for a specific forensic tool.

        Args:
            tool_name: Tool name (e.g. 'MFTECmd', 'Hayabusa')
        """
        result = fk.get_tool_interpretation(tool_name)
        if result:
            return result
        return {"note": f"No guidance for '{tool_name}'"}

    @server.tool()
    def get_false_positive_context(tool_name: str, finding_type: str) -> dict:
        """Get common false positive scenarios for a tool+finding combination.

        Args:
            tool_name: Tool name
            finding_type: Finding type
        """
        result = fk.get_false_positive_context(tool_name, finding_type)
        if result:
            return result
        return {"note": f"No false positive data for '{tool_name}'/'{finding_type}'"}

    @server.tool()
    def get_corroboration_suggestions(finding_type: str) -> list:
        """Get cross-reference and corroboration suggestions for a finding type.

        Args:
            finding_type: Finding type (e.g. 'persistence', 'credential_theft')
        """
        return fk.get_corroboration(finding_type)

    @server.tool()
    def list_playbooks() -> list:
        """List all available forensic playbooks."""
        return fk.list_playbooks()

    @server.tool()
    def get_playbook(name: str) -> dict:
        """Get a step-by-step forensic playbook by name.

        Args:
            name: Playbook name (use list_playbooks() to see available)
        """
        result = fk.get_playbook(name)
        if result:
            return result
        slugs = fk.list_playbook_slugs()
        return {"error": f"Playbook '{name}' not found", "available": slugs}

    @server.tool()
    def get_collection_checklist(artifact_type: str) -> list:
        """Get evidence collection checklist for an artifact type.

        Args:
            artifact_type: Artifact type (e.g. 'evtx', 'registry', 'memory')
        """
        result = fk.get_collection_checklist(artifact_type)
        if result:
            return result
        types = fk.list_collection_checklists()
        return {"error": f"No checklist for '{artifact_type}'", "available": types}
