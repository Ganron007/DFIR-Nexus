"""Importer registry: dispatches a file/dir to the right importer.

All importer classes are registered. Multiple importers may share one
``ArtifactSource`` (e.g. Suricata/SocRates/Sysdig all map to SURICATA);
the first registered class for a source is the primary, and
``resolve()`` disambiguates at import time via ``can_handle()``.
Importers that require optional binary dependencies (python-evtx,
python-registry, regipy, lnkfile, etc.) gracefully degrade when their
deps are missing — they log a warning and yield zero artifacts rather
than crashing.
"""

from __future__ import annotations

import logging
from pathlib import Path

from nexus.ingest.base import Importer, ImportResult
from nexus.ingest.schemas import ArtifactSource

log = logging.getLogger(__name__)


def _safe_import(module_path: str, class_name: str) -> type[Importer] | None:
    """Import an importer class, returning None if optional deps are missing."""
    try:
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except (ImportError, AttributeError) as exc:
        log.debug("Could not load %s.%s: %s", module_path, class_name, exc)
        return None


class ImporterRegistry:
    """Maps source types to concrete importer classes.

    Several importers may share one ``ArtifactSource`` (shared lanes such as
    SURICATA for Suricata/SocRates/Sysdig, or GENERIC_JSONL for
    JSONL/Email/Archive). The first class registered for a source is the
    primary; ``resolve()`` picks the best candidate for a concrete path via
    ``can_handle()`` so shared lanes do not clobber each other.
    """

    def __init__(self) -> None:
        self._importers: dict[ArtifactSource, type[Importer]] = {}
        self._candidates: dict[ArtifactSource, list[type[Importer]]] = {}
        self._autodetect_order: list[type[Importer]] = []

    def register(self, importer_cls: type[Importer]) -> type[Importer]:
        """Register an importer class. Returns it (decorator-friendly)."""
        source = importer_cls.source_class()
        self._candidates.setdefault(source, []).append(importer_cls)
        if source not in self._importers:
            self._importers[source] = importer_cls
        self._autodetect_order.append(importer_cls)
        return importer_cls

    def get(self, source: ArtifactSource) -> type[Importer]:
        """Get the primary importer class for a source enum."""
        if source not in self._importers:
            raise KeyError(f"No importer registered for {source}")
        return self._importers[source]

    def candidates(self, source: ArtifactSource) -> list[type[Importer]]:
        """All importer classes registered for a source (registration order)."""
        return list(self._candidates.get(source, []))

    def resolve(self, source: ArtifactSource, path: Path) -> type[Importer]:
        """Pick the best importer for a source + concrete path.

        Prefers the first candidate whose ``can_handle(path)`` is True;
        falls back to the primary (first registered) importer.
        """
        cands = self._candidates.get(source, [])
        if not cands:
            raise KeyError(f"No importer registered for {source}")
        if len(cands) == 1:
            return cands[0]
        for cls in cands:
            try:
                if cls.can_handle(path):
                    return cls
            except Exception:  # noqa: BLE001
                continue
        return cands[0]

    def all_sources(self) -> list[ArtifactSource]:
        """Return all registered source types."""
        return list(self._importers.keys())

    def autodetect(self, path: Path) -> type[Importer] | None:
        """Return the first importer that can handle the given path."""
        for cls in self._autodetect_order:
            try:
                if cls.can_handle(path):
                    return cls
            except Exception:
                continue
        return None

    def import_path(
        self, path: Path, source: ArtifactSource | None = None
    ) -> ImportResult:
        """Import a path using the specified or auto-detected importer."""
        path = Path(path)
        if not path.exists():
            result = ImportResult(source=source or ArtifactSource.UNKNOWN)
            result.errors.append(f"Path does not exist: {path}")
            return result

        if source is not None:
            importer_cls: type[Importer] | None = self.resolve(source, path)
        else:
            importer_cls = self.autodetect(path)

        if importer_cls is None:
            result = ImportResult(source=source or ArtifactSource.UNKNOWN)
            result.errors.append(
                f"Could not auto-detect importer for {path}. "
                f"Known sources: {[s.value for s in self.all_sources()]}"
            )
            return result

        importer = importer_cls()
        result = importer.ingest(path)
        return result


_ALL_IMPORTERS: list[tuple[str, str]] = [
    ("nexus.ingest.generic.jsonl", "JSONLImporter"),
    ("nexus.ingest.generic.csv", "CSVImporter"),
    ("nexus.ingest.cloud.azure", "AzureImporter"),
    ("nexus.ingest.cloud.cloudtrail", "CloudTrailImporter"),
    ("nexus.ingest.df.amcache", "AmCacheImporter"),
    ("nexus.ingest.df.browser_history", "BrowserHistoryImporter"),
    ("nexus.ingest.df.evtx", "EVTXImporter"),
    ("nexus.ingest.df.hayabusa", "HayabusaImporter"),
    ("nexus.ingest.df.kape", "KAPEImporter"),
    ("nexus.ingest.df.lnkfile", "LNKFileImporter"),
    ("nexus.ingest.df.plaso", "PlasoImporter"),
    ("nexus.ingest.df.registry", "WindowsRegistryImporter"),
    ("nexus.ingest.df.scheduled_tasks", "ScheduledTasksImporter"),
    ("nexus.ingest.df.services", "WindowsServicesImporter"),
    ("nexus.ingest.df.thehive", "TheHiveImporter"),
    ("nexus.ingest.df.velociraptor", "VelociraptorImporter"),
    ("nexus.ingest.df.volatility", "VolatilityImporter"),
    ("nexus.ingest.df.wmi_subscriptions", "WMISubscriptionsImporter"),
    ("nexus.ingest.linux.auditd", "AuditdImporter"),
    ("nexus.ingest.linux.authlog", "AuthLogImporter"),
    ("nexus.ingest.linux.bash_history", "BashHistoryImporter"),
    ("nexus.ingest.linux.syslog", "SyslogImporter"),
    ("nexus.ingest.network.suricata", "SuricataImporter"),
    ("nexus.ingest.network.wireshark", "WiresharkImporter"),
    ("nexus.ingest.network.zeek", "ZeekImporter"),
    ("nexus.ingest.siem.elastic", "ElasticImporter"),
    ("nexus.ingest.siem.splunk", "SplunkImporter"),
    ("nexus.ingest.ti.abuseipdb", "AbuseIPDBImporter"),
    ("nexus.ingest.ti.misp", "MISPImporter"),
    ("nexus.ingest.ti.otx", "OTXImporter"),
    ("nexus.ingest.ti.threatfox", "ThreatFoxImporter"),
    ("nexus.ingest.ti.virustotal", "VirusTotalImporter"),
    ("nexus.ingest.siem.security_onion", "SecurityOnionImporter"),
    ("nexus.ingest.siem.socrates", "SocRatesImporter"),
    ("nexus.ingest.df.cybertriage", "CyberTriageImporter"),
    ("nexus.ingest.cloud.m365", "M365Importer"),
    ("nexus.ingest.network.sysdig", "SysdigImporter"),
    ("nexus.ingest.siem.wazuh", "WazuhImporter"),
    ("nexus.ingest.df.iris", "IRISImporter"),
    ("nexus.ingest.generic.email_import", "EmailImporter"),
    ("nexus.ingest.linux.journald", "JournaldImporter"),
    ("nexus.ingest.df.sandbox", "SandboxImporter"),
    ("nexus.ingest.generic.archive", "ArchiveImporter"),
]


_registry: ImporterRegistry | None = None


def get_registry() -> ImporterRegistry:
    """Get or create the global importer registry with all importers."""
    global _registry
    if _registry is None:
        _registry = ImporterRegistry()
        registered = 0
        skipped = 0
        for module_path, class_name in _ALL_IMPORTERS:
            cls = _safe_import(module_path, class_name)
            if cls is not None:
                _registry.register(cls)
                registered += 1
            else:
                skipped += 1
        log.info(
            "Importer registry: %d registered, %d skipped (missing optional deps)",
            registered, skipped,
        )
    return _registry
