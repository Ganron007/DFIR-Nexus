"""Bearer token auth for HTTP mode + password-based approval authentication.

Approval auth: every approve/reject requires password via getpass (no echo).
This is the key structural human-in-the-loop enforcement — blocks both
AI-via-Bash AND expect-style terminal automation from approving findings.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PBKDF2_ITERATIONS = 600_000
_MAX_ATTEMPTS = 3
_LOCKOUT_SECONDS = 900  # 15 minutes
_MIN_PASSWORD_LENGTH = 8
_PASSWORDS_DIR = Path.home() / ".nexus" / "passwords"
_LOCKOUT_FILE = Path.home() / ".nexus" / ".approval_lockout"


def verify_bearer_token(token: str, expected: str) -> bool:
    if not expected:
        return True
    return hmac.compare_digest(token, expected)


# =============================================================================
# Approval Password Auth
# =============================================================================

def _password_file(analyst: str) -> Path:
    return _PASSWORDS_DIR / f"{analyst}.json"


def has_password(analyst: str) -> bool:
    """Check if analyst has a password configured."""
    entry = _load_password_entry(analyst)
    return entry is not None


def _load_password_entry(analyst: str) -> dict | None:
    path = _password_file(analyst)
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict) and "hash" in data and "salt" in data:
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return None


def _save_password_entry(analyst: str, entry: dict) -> None:
    _PASSWORDS_DIR.mkdir(parents=True, exist_ok=True)
    path = _password_file(analyst)
    fd, tmp = tempfile.mkstemp(dir=str(_PASSWORDS_DIR), suffix=".tmp")
    try:
        os.close(fd)
        with open(tmp, "w") as f:
            json.dump(entry, f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def setup_password(analyst: str, password: str) -> dict:
    """Set up a new password for an examiner."""
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters")
    salt = secrets.token_hex(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS).hex()
    entry = {"hash": pw_hash, "salt": salt, "iterations": PBKDF2_ITERATIONS, "created": time.time()}
    _save_password_entry(analyst, entry)
    return {"status": "ok", "analyst": analyst}


def verify_password(analyst: str, password: str) -> bool:
    """Verify password against stored hash. Returns True/False."""
    entry = _load_password_entry(analyst)
    if not entry:
        return False
    stored_hash = entry["hash"]
    salt = entry["salt"]
    computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS).hex()
    return hmac.compare_digest(computed, stored_hash)


def check_lockout(analyst: str) -> bool:
    """Check if analyst is locked out (too many failed attempts)."""
    if not _LOCKOUT_FILE.exists():
        return False
    try:
        data = json.loads(_LOCKOUT_FILE.read_text())
        failures = data.get(analyst, [])
        recent = [t for t in failures if time.time() - t < _LOCKOUT_SECONDS]
        if len(recent) >= _MAX_ATTEMPTS:
            return True
    except (OSError, json.JSONDecodeError):
        pass
    return False


def record_failure(analyst: str) -> None:
    """Record a failed password attempt."""
    data = {}
    if _LOCKOUT_FILE.exists():
        try:
            data = json.loads(_LOCKOUT_FILE.read_text())
        except (OSError, json.JSONDecodeError):
            pass
    failures = data.get(analyst, [])
    failures.append(time.time())
    data[analyst] = failures
    _LOCKOUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LOCKOUT_FILE.write_text(json.dumps(data))


def clear_failures(analyst: str) -> None:
    """Clear failure count on successful auth."""
    if not _LOCKOUT_FILE.exists():
        return
    try:
        data = json.loads(_LOCKOUT_FILE.read_text())
        data.pop(analyst, None)
        _LOCKOUT_FILE.write_text(json.dumps(data))
    except (OSError, json.JSONDecodeError):
        pass


def reset_password(analyst: str, old_password: str, new_password: str) -> dict:
    """Reset password. Verifies old password, then re-HMACs all ledger entries
    for this analyst with the new key. Reuses the existing PBKDF2 salt
    (old salt stored alongside the hash) so the HMAC key derivation path
    stays stable during the rotation.

    Returns dict with status and count of re-signed ledger entries.
    """
    if not verify_password(analyst, old_password):
        return {"status": "error", "message": "Current password is incorrect"}

    if len(new_password) < _MIN_PASSWORD_LENGTH:
        return {"status": "error", "message": f"New password must be at least {_MIN_PASSWORD_LENGTH} characters"}

    # Load old entry for the salt (needed to derive old HMAC key for re-signing)
    entry = _load_password_entry(analyst)
    if not entry:
        return {"status": "error", "message": "No password entry found for this examiner"}

    old_salt = entry.get("salt", "")
    old_key = derive_hmac_key(old_password, old_salt)
    new_salt = secrets.token_hex(32)
    new_key = derive_hmac_key(new_password, new_salt)

    # Save new password
    pw_hash = hashlib.pbkdf2_hmac("sha256", new_password.encode(), new_salt.encode(), PBKDF2_ITERATIONS).hex()
    _save_password_entry(analyst, {"hash": pw_hash, "salt": new_salt, "iterations": PBKDF2_ITERATIONS, "created": time.time()})

    # Re-HMAC all ledger entries for this examiner
    re_signed = 0
    for ledger_file in VERIFICATION_DIR.glob("*.jsonl"):
        case_id = ledger_file.stem
        entries = read_verification_ledger(case_id)
        updated = []
        for entry in entries:
            if entry.get("approved_by") != analyst:
                updated.append(entry)
                continue
            desc = entry.get("content_snapshot", "")
            expected = compute_hmac(old_key, desc)
            actual = entry.get("hmac", "")
            if hmac.compare_digest(expected, actual):
                entry["hmac"] = compute_hmac(new_key, desc)
                re_signed += 1
            updated.append(entry)

        from nexus.auth import VERIFICATION_DIR as VD
        path = VD / f"{case_id}.jsonl"
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            os.close(fd)
            with open(tmp, "w") as f:
                for entry in updated:
                    f.write(json.dumps(entry) + "\n")
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    return {"status": "ok", "analyst": analyst, "re_signed": re_signed}


# =============================================================================
# HMAC Verification Ledger
# =============================================================================

VERIFICATION_DIR = Path.home() / ".nexus" / "verification"


def _validate_case_id(case_id: str) -> None:
    if not case_id:
        raise ValueError("Case ID cannot be empty")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID: {case_id}")


def derive_hmac_key(password: str, salt: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS)


def compute_hmac(derived_key: bytes, content: str) -> str:
    return hmac.new(derived_key, content.encode("utf-8"), hashlib.sha256).hexdigest()


def write_verification_entry(case_id: str, entry: dict) -> None:
    """Append HMAC verification entry to ledger."""
    _validate_case_id(case_id)
    VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)
    path = VERIFICATION_DIR / f"{case_id}.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_verification_ledger(case_id: str) -> list[dict]:
    """Read all entries from verification ledger."""
    _validate_case_id(case_id)
    path = VERIFICATION_DIR / f"{case_id}.jsonl"
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        if line.strip():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def verify_hmac_entries(case_id: str, password: str, salt: str, examiner: str) -> list[dict]:
    """Verify HMAC for all items belonging to examiner. Returns verification results."""
    derived_key = derive_hmac_key(password, salt)
    entries = read_verification_ledger(case_id)
    results = []
    for entry in entries:
        if entry.get("approved_by") != examiner:
            continue
        expected = compute_hmac(derived_key, entry.get("content_snapshot", ""))
        actual = entry.get("hmac", "")
        results.append({
            "finding_id": entry["finding_id"],
            "type": entry.get("type", "finding"),
            "verified": hmac.compare_digest(expected, actual),
        })
    return results
