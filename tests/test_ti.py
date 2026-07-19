"""Smoke test for the ported threat-intel module.

Run with:
    python tests/test_ti.py
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field

sys.path.insert(0, "src")

from nexus.ti import TIRouter, infer_ioc_type
from nexus.ti.constants import CORE_TI_PROVIDERS, OPTIONAL_TI_PROVIDERS
from nexus.ti.enrich import collect_iocs, enrich_artifacts
from nexus.ti.schemas import IOCType, ProviderMode, TIResult


@dataclass
class MockArtifact:
    """Test-only artifact implementing the duck-typed interface used by enrich."""

    iocs: list[str] = field(default_factory=list)
    source_ip: str | None = None
    dest_ip: str | None = None
    file_hash_md5: str | None = None
    file_hash_sha1: str | None = None
    file_hash_sha256: str | None = None


passed = 0
failed = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {label}" + (f" - {detail}" if detail else ""))
    else:
        failed += 1
        print(f"  FAIL: {label}" + (f" - {detail}" if detail else ""))


# Schemas
result = TIResult(provider="threatfox", ioc_type="domain", value="evil.example", status="ok")
check("TIResult creation", result.provider == "threatfox")
check("TIResult to_dict has provider", result.to_dict()["provider"] == "threatfox")


check("IOCType.HASH exists", IOCType.HASH == "hash")
check("ProviderMode.MOCK exists", ProviderMode.MOCK == "mock")


# Provider constants
check("CORE_TI_PROVIDERS includes abuse.ch + MISP", set(CORE_TI_PROVIDERS) == {
    "threatfox", "malware_bazaar", "urlhaus", "yaraify", "misp",
})
check("OPTIONAL_TI_PROVIDERS includes otx", "otx" in OPTIONAL_TI_PROVIDERS)


# IOC inference
check("infer IP", infer_ioc_type("192.168.1.1") == IOCType.IP)
check("infer URL", infer_ioc_type("https://evil.example") == IOCType.URL)
check("infer domain", infer_ioc_type("evil.example") == IOCType.DOMAIN)
check("infer email", infer_ioc_type("bad@evil.example") == IOCType.EMAIL)
check("infer hash", infer_ioc_type("a" * 64) == IOCType.HASH)


# Router
async def _run_async_tests() -> None:
    router = TIRouter(force_mock=True)

    providers = router.list_providers()
    check("list_providers returns 10", len(providers) == 10)
    check("all providers in mock mode", all(p.mode == ProviderMode.MOCK for p in providers))
    check("5 core providers", sum(1 for p in providers if p.tier == "core") == 5)
    check("5 optional providers", sum(1 for p in providers if p.tier == "optional") == 5)

    payload = await router.lookup("evil.example")
    check("default lookup is core tier", payload["tier"] == "core")
    check("threatfox queried by default", "threatfox" in payload["providers_queried"])
    check("misp queried by default", "misp" in payload["providers_queried"])
    check("optional providers not auto-included", "otx" not in payload["providers_queried"])

    fanout = await router.fanout("evil.example")
    check("fanout returns abuse.ch providers", fanout["providers_queried"] == [
        "threatfox", "malware_bazaar", "urlhaus", "yaraify",
    ])

    otx = await router.query_provider("otx", "evil-c2.example")
    check("explicit optional otx works", otx["provider"] == "otx" and otx["status"] == "ok")

    shodan = await router.query_provider("shodan", "10.0.0.1", ioc_type="ip")
    check("explicit optional shodan works", shodan["provider"] == "shodan" and shodan["status"] == "ok")


asyncio.run(_run_async_tests())


# Enrich helpers
artifact = MockArtifact(
    iocs=["evil-c2.example"],
    dest_ip="10.0.0.5",
)
check("collect_iocs gathers iocs + dest_ip", collect_iocs([artifact]) == ["evil-c2.example", "10.0.0.5"])

payload = enrich_artifacts([artifact], max_iocs=2)
check("enrich_artifacts returns lookups", "lookups" in payload)
check("enrich_artifacts malicious_count is int", isinstance(payload["malicious_count"], int))
check("enrich_artifacts never includes optional", all(
    "otx" not in lookup.get("providers_queried", [])
    for lookup in payload["lookups"]
))


print()
print(f"=== {passed} PASSED, {failed} FAILED (out of {passed + failed}) ===")
sys.exit(0 if failed == 0 else 1)
