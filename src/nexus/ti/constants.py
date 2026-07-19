"""TI provider constants — core (default loop) vs optional (explicit + API key)."""

from __future__ import annotations

import os

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
ABUSE_CH_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"
ABUSE_CH_YARAIFY_URL = "https://yaraify.abuse.ch/api/v1/"
OTX_API_BASE = "https://otx.alienvault.com/api/v1"
CROWDSTRIKE_API_BASE = "https://api.crowdstrike.com"

# Default fanout / ti_lookup (no explicit providers=) — abuse.ch + self-hosted MISP only.
FANOUT_PROVIDERS = ("threatfox", "malware_bazaar", "urlhaus", "yaraify")
CORE_TI_PROVIDERS = FANOUT_PROVIDERS + ("misp",)

# Optional: free-tier or commercial APIs — never in fanout or default lookup; require explicit tool/provider + env key.
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
