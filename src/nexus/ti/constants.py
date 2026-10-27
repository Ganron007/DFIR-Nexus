"""TI provider constants — core (default loop) vs optional (explicit + API key)."""

from __future__ import annotations

import os
from dataclasses import dataclass

ENV_TI_MOCK = "NEXUS_TI_MOCK"
ENV_ABUSECH_KEY = "NEXUS_TI_ABUSECH_API_KEY"
ENV_MISP_URL = "NEXUS_TI_MISP_URL"
ENV_MISP_API_KEY = "NEXUS_TI_MISP_API_KEY"
ENV_OTX_API_KEY = "NEXUS_TI_OTX_API_KEY"
ENV_SHODAN_API_KEY = "NEXUS_TI_SHODAN_API_KEY"
ENV_VIRUSTOTAL_API_KEY = "NEXUS_TI_VIRUSTOTAL_API_KEY"
ENV_ABUSEIPDB_API_KEY = "NEXUS_TI_ABUSEIPDB_API_KEY"
ENV_CROWDSTRIKE_CLIENT_ID = "NEXUS_TI_CROWDSTRIKE_CLIENT_ID"
ENV_CROWDSTRIKE_CLIENT_SECRET = "NEXUS_TI_CROWDSTRIKE_CLIENT_SECRET"

ABUSE_CH_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
ABUSE_CH_MALWARE_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
# URL lookup route: https://urlhaus-api.abuse.ch/ (read 2026-10-27).
ABUSE_CH_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
# The API host, per https://yaraify.abuse.ch/api/ (checked 2026-10-14); yaraify.abuse.ch/api/v1/
# answered 404 for every lookup.
ABUSE_CH_YARAIFY_URL = "https://yaraify-api.abuse.ch/api/v1/"
# Published form request contracts: https://bazaar.abuse.ch/api/ and
# https://urlhaus-api.abuse.ch/ (read 2026-10-27). ThreatFox/YARAify use JSON.
ABUSE_CH_FORM_URLS = frozenset({ABUSE_CH_MALWARE_BAZAAR_URL, ABUSE_CH_URLHAUS_URL})
# Neutral API outcomes are distinct from failed/auth/invalid replies.
ABUSE_CH_NO_RESULT_STATUSES = frozenset({"no_result", "no_results", "hash_not_found"})
OTX_API_BASE = "https://otx.alienvault.com/api/v1"
CROWDSTRIKE_API_BASE = "https://api.crowdstrike.com"

# Fanout = the abuse.ch set (explicit call). Default ti_lookup auto-includes
# every CONFIGURED provider that supports the IOC type (free tiers included:
# abuse.ch, OTX, Shodan, VirusTotal), falling back to the core set when none
# are configured.
FANOUT_PROVIDERS = ("threatfox", "malware_bazaar", "urlhaus", "yaraify")
CORE_TI_PROVIDERS = FANOUT_PROVIDERS + ("misp",)

# Support slots: keyed APIs that participate automatically once configured.
# Operator keyed set: virustotal / abuse.ch / otx / shodan; abuseipdb and
# crowdstrike are supported-but-optional (the rest runs without their keys).
OPTIONAL_TI_PROVIDERS = (
    "otx",
    "shodan",
    "virustotal",
    "abuseipdb",
    "crowdstrike",
)

ALL_TI_PROVIDERS = CORE_TI_PROVIDERS + OPTIONAL_TI_PROVIDERS

# Back-compat alias used in tests/docs for the mandatory set.
ALLOWED_TI_PROVIDERS = ALL_TI_PROVIDERS


def ti_mock_enabled() -> bool:
    return os.environ.get(ENV_TI_MOCK, "").lower() in ("1", "true", "yes")


# Existing HTTP lookup timeout, unchanged. Scheduling never raises it.
TI_LOOKUP_TIMEOUT_SECONDS = 30.0
# Internal resource bound, independent of a provider's requests/time quota.
TI_IOC_WORKERS = 4


@dataclass(frozen=True)
class ProviderPolicy:
    requests: int | None
    period_seconds: float | None
    rate_source: str
    read_date: str
    retry_limit: int = 0
    backoff_factor: float | None = None
    retry_statuses: tuple[int, ...] = ()
    retry_source: str = ""


# The sole runtime owner of provider rate/retry values and their evidence.
# A missing numeric rate means unpublished, never unlimited. The proposed
# single-flight fallback with one header-driven retry is operator-approved.
TI_PROVIDER_POLICIES = {
    "otx": ProviderPolicy(
        requests=10_000, period_seconds=3600.0,
        rate_source="https://www.levelblue.com/blogs/levelblue-blog/the-upgraded-alienvault-otx-api-ways-to-score-swag",
        read_date="2026-10-27", retry_limit=5, backoff_factor=1.0,
        retry_statuses=(429, 500, 502, 503, 504),
        retry_source="https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/OTXv2.py",
    ),
    "shodan": ProviderPolicy(
        requests=1, period_seconds=1.0,
        rate_source="https://github.com/achillean/shodan-python/blob/master/shodan/client.py",
        read_date="2026-10-27",
    ),
    "threatfox": ProviderPolicy(None, None, "https://threatfox.abuse.ch/api/", "2026-10-27"),
    "malware_bazaar": ProviderPolicy(None, None, "https://bazaar.abuse.ch/api/", "2026-10-27"),
    "urlhaus": ProviderPolicy(None, None, "https://urlhaus.abuse.ch/api/", "2026-10-27"),
    "yaraify": ProviderPolicy(None, None, "https://yaraify.abuse.ch/api/", "2026-10-27"),
}
