"""Examiner case intake — persisted on CASE.yaml, used by all pipeline modes.

Hypothesis is one field. It never replaces the mandatory tool lane.
Playbook IDs select extra hunt/corroboration work, not a different parser set.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Host-compromise questions hunt artifacts parsers actually emit
# (execution, persistence, log wipe, remote exec) — not only malware names.
_HOST_HUNT_PLAYBOOKS = (
    "external_compromise",
    "log_tampering",
    "suspicious_execution",
    "remote_access",
    "suspicious_autorun",
    "powershell_anomaly",
    "credential_access",
)

INTAKE_KEYS = (
    "name",
    "description",
    "hypothesis",
    "notes",
    "host",
    "timezone",
    "window",
    "subjects",
    "known_good",
    "question",
    "playbooks",
    "sample_files",
    "extras",
    "query_extra",
    "sift_evidence_root",
    "sift_triage_root",
    "sift_memory_file",
    "sift_os",
    "sift_disk_image",
    "sift_disk_offset",
    "sift_required",
    # WO-R1F items 6/7d: who set the intake, and how many interpretation rounds
    # the examiner asked for. Without these in the whitelist, `persist_case_intake`
    # silently dropped them and the CLI flag appeared to do nothing.
    "set_by",
    "interpret_rounds",
    # D224: the responders' own tools and when they acquired. Without them every mode read the
    # acquisition as the incident (F-Response removing its own firewall rules was staged as
    # anti-forensics, DRAFT 042).
    "responder_tools",
    "acquisition_window",
)


def responder_block(case_dir: Path) -> str:
    """The examiner's statement of the responders' own activity, for every investigative prompt (D224).

    Empty when the examiner set neither field: nothing is inferred from the evidence.
    """
    import yaml

    try:
        meta = yaml.safe_load((Path(case_dir) / "CASE.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return ""
    intake = meta.get("intake") if isinstance(meta, dict) else None
    lines = responder_lines(intake if isinstance(intake, dict) else {})
    return "RESPONDER ACTIVITY " + "\n".join(lines) if lines else ""


def responder_lines(intake: dict[str, Any]) -> list[str]:
    """The responder statement from an intake dict; the digest renders the same lines (Mode 1)."""
    tools = str(intake.get("responder_tools") or "").strip()
    window = str(intake.get("acquisition_window") or "").strip()
    if not tools and not window:
        return []
    lines = [f"(examiner intake, set by {intake.get('set_by') or 'the examiner'}):"]
    if tools:
        lines.append(f"- the responders' own tools on this case: {tools}")
    if window:
        lines.append(f"- acquisition window: {window}")
    lines.append("Rows these tools made, and rows inside the window that the acquisition explains, record the "
                 "response, not the incident. A claim resting on them says so; they are not attacker activity "
                 "unless other evidence shows it.")
    return lines


#: The examiner's words that make a case an insider case: they select the data-staging playbook and the Insider
#: Threat Matrix for the pattern role (Part 12 FM-11). One definition for both.
_INSIDER_WORDS = ("staging", "exfil", "insider", "data theft")


def insider_intake(ctx: dict[str, Any] | None) -> bool:
    """Whether the examiner's intake names an insider case (hypothesis, description or question)."""
    ctx = ctx or {}
    text = " ".join(str(ctx.get(k) or "") for k in ("hypothesis", "description", "question")).lower()
    return any(word in text for word in _INSIDER_WORDS)


def extra_playbook_names(ctx: dict[str, Any] | None) -> list[str]:
    """Playbooks named by the examiner, plus hypothesis keyword hints."""
    ctx = ctx or {}
    raw = str(ctx.get("playbooks") or "").strip()
    names = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
    hyp = " ".join(
        str(ctx.get(k) or "") for k in ("hypothesis", "description", "question")
    ).lower()
    if any(k in hyp for k in ("usb", "removable", "thumb drive")):
        names.append("usb_activity")
    if insider_intake(ctx):
        names.append("data_staging")
    if any(
        k in hyp
        for k in (
            "external", "compromise", "intrusion", "malware", "c2",
            "phishing", "initial access", "persistence",
            "attacker", "beacon",
        )
    ):
        names.extend(_HOST_HUNT_PLAYBOOKS)
    if any(k in hyp for k in ("email", "pst", "outlook", "mailbox", "bec")):
        names.append("email_compromise")
    if any(k in hyp for k in ("memory", "volatility", "ram dump", "memdump", "lsass dump")):
        names.append("memory_forensics")
    if any(
        k in hyp
        for k in ("linux", "ubuntu", "ssh key", "authorized_keys", "cron", "systemd", "auth.log")
    ):
        names.append("linux_forensics")
    if any(k in hyp for k in ("browser", "chrome", "firefox", "browsing history", "download")):
        names.append("browser_forensics")
    if any(k in hyp for k in ("phishing", "phish", "spam", "malicious email")):
        names.append("phishing_analysis")
    if any(k in hyp for k in ("shellbags", "folder access", "user activity", "deleted files")):
        names.extend(("user_activity", "file_deletion"))
    if any(k in hyp for k in ("timeline", "supertimeline", "super timeline", "plaso")):
        names.append("supertimeline")
    return list(dict.fromkeys(names))


def persist_case_intake(case_dir: Path, ctx: dict[str, Any] | None) -> dict[str, str]:
    """Merge intake fields into CASE.yaml. Returns the written intake dict.

    WO-R2F item 6 (D45): only what the examiner set is stored. The product used
    to derive playbooks from the hypothesis keywords and write them into
    `CASE.yaml` beside `set_by: operator` — the reviewer found 7 hunt playbooks
    in SC1's intake after 36c had said "no playbooks", so the file misrepresented
    who decided what. Playbook *selection* stays a runtime act: `tool_context`
    and the hunt node call `extra_playbook_names` on the live context and get
    the same names without them ever being attributed to the examiner.
    """
    import yaml

    ctx = ctx or {}
    intake = {}
    meta_path = case_dir / "CASE.yaml"
    meta: dict[str, Any] = {}
    if meta_path.is_file():
        loaded = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            meta = loaded
            if isinstance(meta.get("intake"), dict):
                intake = {str(k): str(v) for k, v in meta["intake"].items() if v is not None}
    # A case written before this fix carries the derived list. Merging alone
    # would keep it forever, so the stored value is dropped unless the examiner
    # re-supplies it in THIS call — the only way a playbook enters the file.
    if not str(ctx.get("playbooks") or "").strip():
        intake.pop("playbooks", None)
    for k in INTAKE_KEYS:
        if str(ctx.get(k) or "").strip():
            intake[k] = str(ctx.get(k)).strip()
    if not intake:
        return {}
    meta["intake"] = intake
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(yaml.dump(meta, default_flow_style=False), encoding="utf-8")
    return intake


def clear_case_intake(case_dir: Path, keys: tuple[str, ...]) -> dict[str, str]:
    """Remove intake keys (e.g. clearing the SIFT lane selection).

    ``persist_case_intake`` only merges non-empty values, so a flag can never
    be switched off through it - this is the explicit removal path (operator
    2026-09-29: clearing the SIFT selection is a first-class recovery).
    """
    import yaml

    meta_path = case_dir / "CASE.yaml"
    if not meta_path.is_file():
        return {}
    loaded = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        return {}
    intake = loaded.get("intake")
    if not isinstance(intake, dict):
        return {}
    for key in keys:
        intake.pop(key, None)
    loaded["intake"] = intake
    meta_path.write_text(yaml.dump(loaded, default_flow_style=False), encoding="utf-8")
    return {str(k): str(v) for k, v in intake.items() if v is not None}
