"""Tests for Rule Five Anonymizer Quality (T2-43 / WP 15.10)."""

import json
from pathlib import Path

from nexus.ingest.anonymize import Anonymizer, deanonymize
from nexus.llm.egress import anonymize_text, load_anonymizer, restore_text


def test_filenames_not_tagged_as_hosts():
    """Binary, script, and artifact filenames must not be tagged as {{HOST_n}}."""
    anon = Anonymizer()
    sample = (
        "Attacker executed mimikatz.exe and injected evil.dll. "
        "The script payload.ps1 was called by setup.bat and malware.bin. "
        "Log saved to trace.log and evidence in dump.dmp."
    )
    result, tokens = anon.anonymize(sample)
    assert "mimikatz.exe" in result
    assert "evil.dll" in result
    assert "payload.ps1" in result
    assert "setup.bat" in result
    assert "malware.bin" in result
    assert "trace.log" in result
    assert "dump.dmp" in result
    assert "{{HOST_" not in result


def test_sid_tokenization():
    """Windows SIDs must be tokenized as {{SID_n}}."""
    anon = Anonymizer()
    sample = (
        "User account SID S-1-5-21-3623811015-3361044348-30300820-1013 was modified. "
        "Local system SID is S-1-5-18."
    )
    result, tokens = anon.anonymize(sample)
    assert "S-1-5-21-3623811015-3361044348-30300820-1013" not in result
    assert "S-1-5-18" not in result
    assert "{{SID_1}}" in result
    assert "{{SID_2}}" in result

    # Verify reversible deanonymization
    restored = deanonymize(result, tokens)
    assert "S-1-5-21-3623811015-3361044348-30300820-1013" in restored
    assert "S-1-5-18" in restored


def test_standalone_usernames():
    """Configured standalone usernames must be tokenized as {{ACCT_n}}."""
    anon = Anonymizer(users={"victim_admin", "alice", "bob"})
    sample = "User victim_admin logged on, while alice and bob logged off."
    result, tokens = anon.anonymize(sample)
    assert "victim_admin" not in result
    assert "alice" not in result
    assert "bob" not in result
    assert "{{ACCT_" in result

    restored = deanonymize(result, tokens)
    assert "victim_admin" in restored
    assert "alice" in restored
    assert "bob" in restored


def test_preserve_adversary_iocs_from_file(tmp_path: Path):
    """Adversary IOCs stored in case's iocs.json must be preserved in allowlist."""
    case_dir = tmp_path / "CASE-IOCS"
    case_dir.mkdir()
    iocs_data = [
        {"type": "ipv4-addr", "value": "198.51.100.44"},
        {"type": "domain", "value": "c2-attacker.com"},
        {"type": "file:hash:sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    ]
    (case_dir / "iocs.json").write_text(json.dumps(iocs_data), encoding="utf-8")

    engine = load_anonymizer(case_dir)
    text = (
        "Internal host 192.168.1.50 contacted C2 server 198.51.100.44 and domain c2-attacker.com. "
        "Payload hash was e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
    )
    result, tokens = engine.anonymize(text)
    # Victim internal IP should be tokenized
    assert "192.168.1.50" not in result
    # Adversary IOCs must NOT be tokenized
    assert "198.51.100.44" in result
    assert "c2-attacker.com" in result
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in result


def test_restore_replies_without_active_case():
    """Anonymizing and restoring text must work cleanly even when case_dir is None."""
    sample = "Host CORP\\analyst connected to 10.0.0.15."
    anon_text = anonymize_text(sample, case_dir=None)
    assert "CORP\\analyst" not in anon_text
    assert "10.0.0.15" not in anon_text

    # Model reply referencing tokenized identifiers
    model_reply = f"The activity involves {anon_text}."
    restored = restore_text(model_reply, case_dir=None)
    assert "CORP\\analyst" in restored
    assert "10.0.0.15" in restored
