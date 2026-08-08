"""Case audit chain secret management."""

from __future__ import annotations

import contextlib
import logging
import os
import secrets
from pathlib import Path

from nexus.utils.constants import ENV_AUDIT_SECRET

log = logging.getLogger(__name__)

_PERSISTED_SECRET_PATH = Path.home() / ".nexus" / "audit_secret"


def get_audit_secret() -> bytes:
    """Return HMAC secret for audit chains.

    Set ``NEXUS_AUDIT_SECRET`` in production. When unset, a per-install
    random secret is generated on first use and persisted to
    ``~/.nexus/audit_secret`` (0600). This prevents the chain from being
    forgeable across different installs.
    """
    raw = os.environ.get(ENV_AUDIT_SECRET, "").strip()
    if raw:
        return raw.encode("utf-8")

    if _PERSISTED_SECRET_PATH.exists():
        try:
            stored = _PERSISTED_SECRET_PATH.read_text().strip()
            if stored:
                log.debug("Using persisted per-install audit secret")
                return stored.encode("utf-8")
        except OSError:
            pass

    log.warning(
        "%s not set — generating per-install audit secret at %s. "
        "For production multi-user deploys, set %s explicitly.",
        ENV_AUDIT_SECRET, _PERSISTED_SECRET_PATH, ENV_AUDIT_SECRET,
    )
    generated = secrets.token_hex(32)
    try:
        _PERSISTED_SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = __import__("tempfile").mkstemp(
            dir=str(_PERSISTED_SECRET_PATH.parent), suffix=".tmp"
        )
        os.close(fd)
        with open(tmp, "w") as f:
            f.write(generated)
        os.replace(tmp, _PERSISTED_SECRET_PATH)
        with contextlib.suppress(OSError):
            os.chmod(_PERSISTED_SECRET_PATH, 0o600)
    except OSError as exc:
        log.error("Failed to persist audit secret: %s", exc)
    return generated.encode("utf-8")
