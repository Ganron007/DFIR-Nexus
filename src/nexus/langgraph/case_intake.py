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
)


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
    if any(k in hyp for k in ("staging", "exfil", "insider", "data theft")):
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
    """Merge intake fields into CASE.yaml. Returns the written intake dict."""
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
    for k in INTAKE_KEYS:
        if str(ctx.get(k) or "").strip():
            intake[k] = str(ctx.get(k)).strip()
    playbooks = extra_playbook_names({**intake, **ctx})
    if playbooks:
        intake["playbooks"] = ",".join(playbooks)
    if not intake:
        return {}
    meta["intake"] = intake
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(yaml.dump(meta, default_flow_style=False), encoding="utf-8")
    return intake
