"""AI-input anonymization — reversible tokenization of sensitive identifiers.

Replaces IPs, usernames, hostnames, domains, emails, and file paths in text
with deterministic tokens (e.g. ``{{IP_1}}``) before sending to an LLM.
A token dictionary maps every original value to its token so the response can
be de-anonymized.

Adversary IOCs (IPs, domains, hashes) can be preserved via a configurable
allowlist so the LLM sees them verbatim.

Pure/deterministic — no AI, no network calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Regex patterns (ordered by precedence — more specific first)
# ---------------------------------------------------------------------------

# Email (must come before plain domain to avoid partial matches)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# IPv4
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

# Windows account: DOMAIN\user
_DOMAIN_USER_RE = re.compile(
    r"\b([A-Za-z0-9_.-]+)\\([A-Za-z0-9_.$-]+)\b"
)

# UNC path: \\server\share\...
_UNC_PATH_RE = re.compile(
    r"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+(?:\\[^\s:*?\"<>|\r\n]+)*"
)

# Windows drive path: C:\...
_WIN_PATH_RE = re.compile(
    r"[A-Za-z]:\\(?:[^\\\s:*?\"<>|\r\n]+\\)*[^\\\s:*?\"<>|\r\n]+"
)

# Unix absolute path: /usr/bin/...
_UNIX_PATH_RE = re.compile(
    r"(?:/[^/\s:*?\"<>|\r\n]+){2,}"
)

# Hostname (labels separated by dots, at least two labels — avoids common words)
_HOSTNAME_RE = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9]))+)\b"
)

# SHA-256 / SHA-1 / MD5 hex strings
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


@dataclass
class Anonymizer:
    """Reversible tokenization engine for sensitive identifiers.

    Parameters
    ----------
    allowlist:
        A set of values (IPs, domains, hashes, etc.) that should NOT be
        anonymized — typically adversary-controlled IOCs that the LLM must
        see verbatim to reason about the threat.
    """

    allowlist: set[str] = field(default_factory=set)

    # Internal state (reset on each anonymize call)
    _token_dict: dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _reverse_dict: dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _counters: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def _is_allowed(self, value: str) -> bool:
        """Check if a value is in the allowlist (case-insensitive for hashes)."""
        lower = value.lower()
        return any(allowed.lower() == lower for allowed in self.allowlist)

    def _make_token(self, kind: str, original: str) -> str:
        """Return the token for *original*, creating a new one if needed."""
        key = f"{kind}:{original}"
        if key in self._token_dict:
            return self._token_dict[key]

        self._counters[kind] = self._counters.get(kind, 0) + 1
        token = f"{{{{{kind}_{self._counters[kind]}}}}}"
        self._token_dict[key] = token
        self._reverse_dict[token] = original
        return token

    def _get_token(self, kind: str, original: str) -> str:
        """Look up or create a token."""
        key = f"{kind}:{original}"
        return self._token_dict.get(key) or self._make_token(kind, original)

    def anonymize(self, text: str) -> tuple[str, dict[str, str]]:
        """Anonymize *text*, returning the tokenized version and the dictionary.

        Parameters
        ----------
        text:
            Raw text containing sensitive identifiers.

        Returns
        -------
        tuple[str, dict[str, str]]
            ``(tokenized_text, token_dict)`` where *token_dict* maps
            original values to their tokens (e.g.
            ``{"10.0.0.1": "{{IP_1}}"}``).
        """
        # Reset per-call state
        self._token_dict.clear()
        self._reverse_dict.clear()
        self._counters.clear()

        result = text

        # --- Pass 1: Emails (before hostnames to avoid partial match) ---
        def _replace_email(m: re.Match[str]) -> str:
            val = m.group(0)
            if self._is_allowed(val):
                return val
            return self._get_token("EMAIL", val)
        result = _EMAIL_RE.sub(_replace_email, result)

        # --- Pass 2: UNC paths (before hostnames and plain paths) ---
        def _replace_unc(m: re.Match[str]) -> str:
            val = m.group(0)
            if self._is_allowed(val):
                return val
            return self._get_token("PATH", val)
        result = _UNC_PATH_RE.sub(_replace_unc, result)

        # --- Pass 3: Windows paths ---
        def _replace_win_path(m: re.Match[str]) -> str:
            val = m.group(0)
            if self._is_allowed(val):
                return val
            return self._get_token("PATH", val)
        result = _WIN_PATH_RE.sub(_replace_win_path, result)

        # --- Pass 4: Unix paths ---
        def _replace_unix_path(m: re.Match[str]) -> str:
            val = m.group(0)
            if self._is_allowed(val):
                return val
            return self._get_token("PATH", val)
        result = _UNIX_PATH_RE.sub(_replace_unix_path, result)

        # --- Pass 5: IPv4 addresses ---
        def _replace_ip(m: re.Match[str]) -> str:
            val = m.group(0)
            if self._is_allowed(val):
                return val
            return self._get_token("IP", val)
        result = _IPV4_RE.sub(_replace_ip, result)

        # --- Pass 6: DOMAIN\user accounts ---
        def _replace_account(m: re.Match[str]) -> str:
            full = m.group(0)
            if self._is_allowed(full):
                return full
            return self._get_token("ACCT", full)
        result = _DOMAIN_USER_RE.sub(_replace_account, result)

        # --- Pass 7: Hashes ---
        def _replace_hash(m: re.Match[str]) -> str:
            val = m.group(0)
            if self._is_allowed(val):
                return val
            return self._get_token("HASH", val)
        result = _HASH_RE.sub(_replace_hash, result)

        # --- Pass 8: Hostnames (last — most likely to over-match) ---
        # Only replace hostnames that look like FQDNs (contain at least one
        # dot and the TLD is >= 2 chars) and are not already tokenized.
        def _replace_hostname(m: re.Match[str]) -> str:
            val = m.group(1)
            # Skip if it's inside an already-tokenized region ({{...}})
            start = m.start()
            preceding = result[max(0, start - 10):start]
            if "{{" in preceding:
                return m.group(0)
            if self._is_allowed(val):
                return m.group(0)
            # Skip common non-hostname strings
            common = {"windows.com", "microsoft.com", "google.com",
                      "amazonaws.com", "github.com", "example.com",
                      "example.org", "localhost.localdomain"}
            if val.lower() in common:
                return m.group(0)
            token = self._get_token("HOST", val)
            return token

        # We need to run hostname replacement on the partially-anonymized
        # result but avoid matching inside tokens.  Use a callback that
        # checks surrounding context.
        result = _HOSTNAME_RE.sub(_replace_hostname, result)

        # Build the public token dict (original -> token)
        token_dict: dict[str, str] = {}
        for key, token in self._token_dict.items():
            kind, original = key.split(":", 1)
            token_dict[original] = token

        return result, token_dict


def deanonymize(text: str, token_dict: dict[str, str]) -> str:
    """Reverse tokenization, restoring original values.

    Parameters
    ----------
    text:
        Tokenized text containing ``{{KIND_N}}`` placeholders.
    token_dict:
        The dictionary returned by :meth:`Anonymizer.anonymize`.

    Returns
    -------
    str
        The original text with all known tokens replaced.
    """
    result = text
    # Sort by token length descending so longer tokens are replaced first
    # (avoids partial replacement if tokens share prefixes).
    for original, token in sorted(token_dict.items(), key=lambda kv: -len(kv[1])):
        result = result.replace(token, original)
    return result
