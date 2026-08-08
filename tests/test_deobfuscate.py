"""Tests for payload deobfuscation — base64 PowerShell decoding."""

from __future__ import annotations

import base64

from nexus.ingest.deobfuscate import (
    deobfuscate_artifacts,
    deobfuscate_command,
)
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity


class TestDeobfuscation:
    def test_encoded_command_decoded(self) -> None:
        """PowerShell -EncodedCommand base64 UTF-16LE decoded."""
        payload = "Get-Process"
        encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -EncodedCommand {encoded}"
        results = deobfuscate_command(cmd)
        assert len(results) == 1
        assert results[0].decoded is not None
        assert "Get-Process" in results[0].decoded
        assert results[0].technique == "PowerShell -EncodedCommand (base64 UTF-16LE)"
        assert results[0].confidence == "high"

    def test_short_encoded_command_ignored(self) -> None:
        """Too-short encoded commands not flagged."""
        cmd = "powershell.exe -enc ABC"
        results = deobfuscate_command(cmd)
        assert len(results) == 0

    def test_from_base64string_decoded(self) -> None:
        """[Convert]::FromBase64String decoded."""
        payload = "Invoke-Mimikatz -DumpCreds"
        encoded = base64.b64encode(payload.encode("utf-8")).decode()
        cmd = f'$x = [Convert]::FromBase64String("{encoded}")'
        results = deobfuscate_command(cmd)
        assert len(results) >= 1
        assert any("Mimikatz" in r.decoded for r in results if r.decoded)

    def test_no_obfuscation_no_results(self) -> None:
        """Clean command → no deobfuscation."""
        results = deobfuscate_command("powershell.exe -Command Get-Process")
        assert len(results) == 0

    def test_deobfuscate_artifacts(self) -> None:
        """Scans artifact command_line fields."""
        payload = "Invoke-Mimikatz"
        encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
        artifact = Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.PROCESS,
            source=ArtifactSource.EVTX,
            timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            severity=Severity.HIGH,
            command_line=f"powershell.exe -enc {encoded}",
        )
        results = deobfuscate_artifacts([artifact])
        assert len(results) == 1
        assert results[0].artifact_id == artifact.id

    def test_to_dict(self) -> None:
        payload = "test"
        encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
        cmd = f"powershell -enc {encoded}"
        results = deobfuscate_command(cmd)
        if results:
            d = results[0].to_dict()
            assert "original" in d
            assert "decoded" in d
            assert "technique" in d
