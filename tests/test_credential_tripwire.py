"""WO-5 canary: prove the session tripwire fires on a protected-path write.

Skipped by default — it deliberately writes into the real ``~/.nexus`` and
leaves the file behind so the tripwire has a created-file to report:

    $env:NEXUS_TRIPWIRE_CANARY = "1"
    python -m pytest tests/test_credential_tripwire.py -q
    # -> the session fails, listing ~/.nexus/tripwire-canary.txt

Cleanup after the demonstration:

    Remove-Item "$env:USERPROFILE\\.nexus\\tripwire-canary.txt"
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.environ.get("NEXUS_TRIPWIRE_CANARY") != "1",
    reason="canary: set NEXUS_TRIPWIRE_CANARY=1 to prove the tripwire fires",
)
def test_tripwire_canary():
    target = Path.home() / ".nexus" / "tripwire-canary.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "canary: this file should make the session tripwire fail\n",
        encoding="utf-8",
    )


def test_rag_bundle_download_is_blocked_in_tests():
    """Isolation: no test path may pull the 128 MB GitHub release asset."""
    from nexus.tools import rag as rag_mod

    with pytest.raises(RuntimeError, match="blocked in tests"):
        rag_mod._download_asset(
            "https://example.invalid/rag-index.tar.zst", Path("x")
        )
    with pytest.raises(RuntimeError, match="blocked in tests"):
        rag_mod._fetch_latest_release()
