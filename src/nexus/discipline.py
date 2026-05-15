"""Finding validation rules — provenance, confidence, attribution gates.

Mirrors the upstream discipline module. Validates that findings meet
structural requirements before staging.
"""

_ALLOWED_FINDING_FIELDS = {
    "title", "observation", "interpretation", "confidence",
    "confidence_justification", "type", "audit_ids", "mitre_ids",
    "mitre_techniques", "iocs", "event_type", "artifact_ref",
    "related_findings", "host", "event_timestamp", "affected_account",
    "artifacts", "supporting_commands",
}

_VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH", "SPECULATIVE"}
_VALID_TYPES = {"finding", "execution", "persistence", "attribution", "exclusion",
                "conclusion", "network", "lateral", "auth", "file",
                "registry", "other"}


def validate_finding(finding: dict) -> dict:
    """Validate a finding before staging.

    Returns {"valid": True} or {"valid": False, "errors": [...]}.
    """
    errors = []
    warnings = []

    if not isinstance(finding, dict):
        return {"valid": False, "errors": ["Finding must be a dict"]}

    title = finding.get("title", "")
    if not title or not isinstance(title, str):
        errors.append("Finding must have a 'title' string field")

    observation = finding.get("observation", "")
    interpretation = finding.get("interpretation", "")
    if not observation:
        errors.append("Missing required field: observation")
    if not interpretation:
        errors.append("Missing required field: interpretation")

    confidence = finding.get("confidence", "").upper()
    if confidence and confidence not in _VALID_CONFIDENCE:
        errors.append(f"Invalid confidence '{confidence}'. Use: {', '.join(sorted(_VALID_CONFIDENCE))}")

    finding_type = finding.get("type", "")
    if finding_type and finding_type not in _VALID_TYPES:
        errors.append(f"Invalid type '{finding_type}'. Use one of: {', '.join(_VALID_TYPES)}")

    confidence_justification = finding.get("confidence_justification", "")
    if not confidence_justification:
        errors.append("Missing confidence_justification (FD-005: confidence must be justified)")

    audit_ids = finding.get("audit_ids", [])
    if audit_ids and not isinstance(audit_ids, list):
        errors.append("audit_ids must be a list")
        audit_ids = []

    if finding_type == "attribution" and len(audit_ids) < 3:
        errors.append(f"Attribution requires at least 3 audit_ids (FD-003), got {len(audit_ids)}")

    has_mitre = bool(finding.get("mitre_ids") or finding.get("mitre_techniques"))
    if confidence == "HIGH" and not has_mitre:
        warnings.append("HIGH confidence findings should include MITRE ATT&CK technique IDs")

    event_ts = finding.get("event_timestamp", "")
    if event_ts:
        import re
        if not re.match(
            r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$",
            event_ts,
        ):
            errors.append(
                f"event_timestamp '{event_ts}' is not valid ISO 8601. "
                "Use format like '2026-01-24T15:00:41Z' or '2026-01-24'."
            )
    elif finding_type == "finding":
        warnings.append(
            "type=finding without event_timestamp -- include event_timestamp "
            "(ISO 8601) for when the incident event occurred."
        )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }


def _build_finding_considerations(finding: dict) -> list[str]:
    """Assemble pre-acceptance guidance for a staged finding."""
    considerations = [
        "FD-001: Every claim must reference at least one audit_id from an actual tool call",
    ]
    confidence = finding.get("confidence", "").upper()
    if confidence == "HIGH":
        considerations.append(
            "HIGH confidence requires 2+ independent corroborating sources "
            "-- are yours truly independent?"
        )
    if confidence == "LOW" or confidence == "SPECULATIVE":
        considerations.append(
            "LOW/SPECULATIVE confidence findings should clearly state what additional "
            "evidence would strengthen the finding"
        )
    if finding.get("type") == "attribution":
        considerations.append(
            "Anti-pattern: premature_attribution. Attribution requires multiple "
            "corroborating TTPs, not just a single IOC match."
        )
    if finding.get("type") == "exclusion":
        considerations.append(
            "Anti-pattern: confirmation_bias. Ensure exclusion is based on evidence "
            "of absence, not absence of evidence."
        )
    return considerations


def validate_examiner(examiner: str) -> str | None:
    """Validate and normalize examiner identity. Returns error string or None."""
    import re
    if not examiner:
        return "Examiner identity cannot be empty"
    if not re.match(r"^[a-z0-9][a-z0-9-]{0,19}$", examiner):
        return f"Invalid examiner '{examiner}': must be lowercase alphanumeric + hyphens, max 20 chars"
    return None


def validate_case_id(case_id: str) -> str | None:
    """Validate case ID. Returns error string or None."""
    if not case_id or not case_id.strip():
        return "Case ID cannot be empty"
    if "\x00" in case_id:
        return "Case ID contains null byte"
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        return f"Invalid case ID (path traversal characters): {case_id}"
    return None
