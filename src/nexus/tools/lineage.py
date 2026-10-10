"""Tool lineage: what binary produced this row (WO-A4 / WP 13.4).

A finding that cites a CSV row is only reproducible if we know **which build of
which tool** wrote that CSV and what it was given. Today nothing captures the
version: the audit entry says argv and inputs, the lane ledger says OK/FAIL,
and neither says "this was Volatility 2.26.2 on this host".

This module answers that with stdlib only:

* Windows PE binaries - the real file/product version out of the version
  resource, via ``ctypes`` (no shelling out, no new dependency).
* Scripts - their own SHA-256 plus the interpreter that would run them.
* Everything else - the hash alone, with ``version_source: "sha256-only"``:
  never a guess.
* SIFT-side tools - the tool's own ``--version`` output where it has one, cached
  per host session, and ``"undeclared"`` where it does not.

Results are cached per ``(path, mtime, size)``: the lane calls this once per
tool per run, and a forensic run must not pay for the same hash twice.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import Any

__all__ = [
    "binary_lineage",
    "clear_lineage_cache",
    "interpreter_for",
    "tool_version_lineage",
    "version_lineage",
]

SCRIPT_SUFFIXES = {
    ".ps1": "powershell",
    ".py": "python",
    ".pl": "perl",
    ".rb": "ruby",
    ".sh": "sh",
}

# SIFT-side tools that declare their own version. Anything not here is
# "undeclared" - a version is never inferred from a file name.
VERSION_FLAG_TOOLS = {
    "vol": ("vol", "--version"),
    "volatility": ("vol", "--version"),
    "plaso": ("log2timeline.py", "--version"),
    "log2timeline": ("log2timeline.py", "--version"),
    "psort": ("psort.py", "--version"),
    "fls": ("fls", "-V"),
    "mmls": ("mmls", "-V"),
    "bulk_extractor": ("bulk_extractor", "-V"),
}

_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}
_VERSION_CACHE: dict[tuple[str, str], str] = {}


#: Tools whose findings depend on a rule set, and the rules checkout under tools/windows (WO-TA item 8).
RULE_SETS = {"hayabusa": "hayabusa/rules"}


def _git_head_commit(repo: Path) -> str:
    """The commit HEAD resolves to in a git checkout, read from its files (no git process)."""
    git_dir = repo / ".git"
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if not head.startswith("ref: "):
        return head
    ref = head[5:].strip()
    ref_file = git_dir / ref
    if ref_file.is_file():
        return ref_file.read_text(encoding="utf-8").strip()
    packed = git_dir / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    return ""


def rules_lineage(tool: str, tools_root: Path | None = None) -> dict[str, str]:
    """``rules_version`` for a tool with a rule set: the commit of its rules checkout ('' if unreadable).

    A tool without a rule set returns nothing, so its lineage is unchanged.
    """
    rel = RULE_SETS.get(tool)
    if not rel:
        return {}
    root = tools_root or (Path(__file__).resolve().parents[3] / "tools" / "windows")
    repo = root / rel
    commit = _git_head_commit(repo) if repo.is_dir() else ""
    return {"rules_version": f"git:{commit}" if commit else ""}


def clear_lineage_cache() -> None:
    """Drop both caches (tests, and long-lived sessions that changed a binary)."""
    _CACHE.clear()
    _VERSION_CACHE.clear()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Windows PE version resource (ctypes; stdlib only)
# --------------------------------------------------------------------------

def _fixed_version(buffer: Any, version: Any) -> tuple[str, str]:
    """Numeric version from VS_FIXEDFILEINFO, when there is no string table.

    Plenty of shipping binaries (python.exe among them) carry only the fixed
    info block. Reporting no version for those would be the wrong answer: the
    numbers are in the resource, just not in the string table.
    """
    try:
        import ctypes

        sub_block = ctypes.c_void_p()
        sub_len = ctypes.c_uint(0)
        if not version.VerQueryValueW(
            buffer, "\\", ctypes.byref(sub_block), ctypes.byref(sub_len)
        ):
            return "", ""
        if not sub_len.value or sub_len.value < 52:
            return "", ""
        # VS_FIXEDFILEINFO is an array of DWORDs (52 of them), not one value.
        count = int(sub_len.value)
        values = list(
            ctypes.cast(sub_block, ctypes.POINTER(ctypes.c_uint * count)).contents
        )[:count]
        file_ms, file_ls = values[8], values[9]
        prod_ms, prod_ls = values[10], values[11]

        def fmt(ms: int, ls: int) -> str:
            return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"

        return fmt(file_ms, file_ls), fmt(prod_ms, prod_ls)
    except (OSError, ValueError, TypeError):  # pragma: no cover - defensive
        return "", ""


def _pe_version(path: Path) -> tuple[str, str, str]:
    """``(file_version, product_version, version_source)`` from the PE resource."""
    if sys.platform != "win32":  # pragma: no cover - Windows-only path
        return "", "", "not-pe"
    try:
        import ctypes
        from ctypes import wintypes

        version = ctypes.WinDLL("version", use_last_error=True)
        target = str(path)
        handle = wintypes.DWORD(0)
        size = version.GetFileVersionInfoSizeW(target, ctypes.byref(handle))
        if not size:
            return "", "", "no-version-resource"
        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(target, 0, size, buffer):
            return "", "", "no-version-resource"

        # 1. the string table, when the resource has one
        sub_block = ctypes.c_void_p()
        sub_len = ctypes.c_uint(0)
        translations: list[int] = []
        if version.VerQueryValueW(
            buffer, "\\VarFileInfo\\Translation",
            ctypes.byref(sub_block), ctypes.byref(sub_len),
        ):
            # The translation block is an array of WORDs (language, codepage)
            # and `puIntLen` counts WORDS, not DWORDs - reading it as DWORDs
            # walks past the block and prints the neighbouring resource bytes.
            words = int(sub_len.value)
            translations = [
                w for w in ctypes.cast(
                    sub_block, ctypes.POINTER(ctypes.c_ushort * words)
                ).contents[:words]
            ]
        if len(translations) % 2:  # pragma: no cover - malformed resource
            translations.append(0x04B0)

        def _string(name: str) -> str:
            value = ctypes.c_void_p()
            value_len = ctypes.c_uint(0)
            for i in range(0, len(translations), 2):
                prefix = f"\\StringFileInfo\\{translations[i]:04x}{translations[i + 1]:04x}\\"
                if version.VerQueryValueW(
                    buffer, prefix + name, ctypes.byref(value), ctypes.byref(value_len)
                ):
                    raw = ctypes.cast(value, ctypes.c_wchar_p).value
                    return (raw or "").strip()
            return ""

        file_version = _string("FileVersion")
        product_version = _string("ProductVersion")
        if file_version or product_version:
            return file_version, product_version, "pe-version-resource"

        # 2. the numeric block, which is all some binaries carry (python.exe)
        numeric_file, numeric_product = _fixed_version(buffer, version)
        if numeric_file or numeric_product:
            return numeric_file, numeric_product, "pe-version-resource-fixed"
        return "", "", "no-version-resource"
    except (OSError, AttributeError, ValueError):  # pragma: no cover - defensive
        return "", "", "pe-read-failed"


def _format_version_tuple(parts: tuple[int, ...]) -> str:
    return ".".join(str(p) for p in parts)


# --------------------------------------------------------------------------
# interpreters
# --------------------------------------------------------------------------

def interpreter_for(path: str | Path) -> str:
    """The interpreter that would run this script (``""`` when not a script)."""
    suffix = Path(path).suffix.lower()
    kind = SCRIPT_SUFFIXES.get(suffix)
    if not kind:
        return ""
    if kind == "python":
        return sys.executable
    names = {
        "powershell": ["pwsh", "powershell"],
        "perl": ["perl"],
        "ruby": ["ruby"],
        "sh": ["sh", "bash"],
    }.get(kind, [])
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return ""


def version_lineage(binary_path: str | Path) -> tuple[str, str, str]:
    """``(file_version, product_version, version_source)`` for one path."""
    path = Path(binary_path)
    if not path.is_file():
        return "", "", "missing"
    file_version, product_version, source = _pe_version(path)
    if file_version or product_version:
        return file_version, product_version, source
    suffix = path.suffix.lower()
    if suffix in SCRIPT_SUFFIXES:
        interpreter = interpreter_for(path)
        if interpreter and interpreter != str(path):
            i_file, _i_product, _src = version_lineage(interpreter)
            if i_file or _i_product:
                return i_file, "", "script+interpreter"
        return "", "", "script-hash"
    # Linux ELF, a container image, a Python wheel - the hash is the identity
    # WO-TA item 8: a version probe was tried here and REMOVED. It ran the
    # tool with --version / -V / no arguments and searched the output for a
    # version token. Measured on this host against the four sha256-only tools
    # the lane actually runs - Get-InjectedThreadEx, INDXRipper, capa and
    # chainsaw - it returned empty for all four: Hayabusa answers --version
    # with a usage error and writes its banner to the console handle rather
    # than stdout, so a pipe sees nothing, and the others behave the same way.
    # A probe that cannot read a version is worse than no probe, because it
    # looks like the gap is closed. The honest fix is the fetch manifest: the
    # fetch script already knows the exact version and URL it installed, so the
    # lane should read the version from there instead of from the binary.
    return "", "", "sha256-only"


# --------------------------------------------------------------------------
# the public entry point
# --------------------------------------------------------------------------

def binary_lineage(path: str | Path, *, cache: bool = True) -> dict[str, Any]:
    """Everything we can say about the binary that produced a row.

    Never raises: a tool that cannot be described is still a tool that ran, and
    a lineage failure must not fail the lane row it describes.
    """
    target = Path(path)
    key: tuple[Any, ...] = (str(target),)
    if cache:
        try:
            stat = target.stat()
            key = (str(target), stat.st_mtime_ns, stat.st_size)
        except OSError:
            key = (str(target), 0, 0)
        cached = _CACHE.get(key)
        if cached is not None:
            return dict(cached)

    result: dict[str, Any] = {
        "binary_path": str(target),
        "binary_sha256": "",
        "file_version": "",
        "product_version": "",
        "version_source": "undeclared",
        "interpreter": "",
    }
    try:
        if target.is_file():
            result["binary_sha256"] = _sha256(target)
            file_version, product_version, source = version_lineage(target)
            result["file_version"] = file_version
            result["product_version"] = product_version
            result["version_source"] = source
            interpreter = interpreter_for(target)
            if interpreter:
                result["interpreter"] = interpreter
        else:
            result["version_source"] = "missing"
    except OSError as exc:  # pragma: no cover - defensive
        result["version_source"] = f"error: {exc.strerror or exc}"

    if cache:
        _CACHE[key] = dict(result)
    return result


# --------------------------------------------------------------------------
# SIFT-side tools: the tool's own version flag, never a guess
# --------------------------------------------------------------------------

def tool_version_lineage(
    tool: str,
    *,
    host: str = "",
    runner: Any = None,
    cache: bool = True,
) -> dict[str, Any]:
    """Version of a remote tool from its own ``--version`` output.

    ``runner(command) -> str`` runs the command on the SIFT host and returns its
    output; the lane supplies one. A tool with no declared version flag, or a
    runner that fails, returns ``"undeclared"`` - a version is never inferred.
    """
    entry = VERSION_FLAG_TOOLS.get(str(tool).lower())
    if not entry or runner is None:
        return {"tool": tool, "file_version": "", "version_source": "undeclared"}
    argv, flag = entry
    command = f"{argv} {flag}"
    key = (host or "local", command)
    if cache and key in _VERSION_CACHE:
        text = _VERSION_CACHE[key]
    else:
        try:
            text = str(runner(command) or "").strip().splitlines()
            text = text[0].strip() if text else ""
        except Exception as exc:  # noqa: BLE001 - a probe must not break a run
            text = f"error: {exc}"
        if cache:
            _VERSION_CACHE[key] = text
    if not text or text.startswith("error:"):
        return {
            "tool": tool,
            "file_version": "",
            "version_source": "undeclared",
            "probe_error": text if text else "no output",
        }
    return {"tool": tool, "file_version": text[:200], "version_source": "tool-version-flag"}


def _env_lineage(name: str) -> dict[str, Any]:  # pragma: no cover - helper
    return {"name": name, "value": os.environ.get(name, "")}