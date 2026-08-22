"""Locate Stage 0 binaries (KAPE, Kansa, DFIR-ORC, UAC, AVML, WinPmem) without PATH search."""

from __future__ import annotations

import os
from pathlib import Path

from nexus.config import settings

_REPO_ROOT = Path(__file__).resolve().parents[3]


def repo_tools_windows() -> Path:
    return _REPO_ROOT / "Tools" / "windows"


def repo_tools_linux() -> Path:
    return _REPO_ROOT / "Tools" / "linux"


def _first_file(candidates: list[Path]) -> Path | None:
    for p in candidates:
        if p.is_file():
            return p
    return None


def _first_dir(candidates: list[Path]) -> Path | None:
    for p in candidates:
        if p.is_dir():
            return p
    return None


def extra_search_roots() -> list[Path]:
    roots: list[Path] = []
    for raw in settings.tool_paths:
        p = Path(raw)
        if p.exists():
            roots.append(p)
    env = os.environ.get("NEXUS_TOOL_PATHS", "")
    if env:
        parts = env.split(";") if os.name == "nt" and ";" in env else env.split(os.pathsep)
        for raw in parts:
            p = Path(raw.strip())
            if p.exists() and p not in roots:
                roots.append(p)
    win = repo_tools_windows()
    if win.is_dir() and win not in roots:
        roots.append(win)
    linux = repo_tools_linux()
    if linux.is_dir() and linux not in roots:
        roots.append(linux)
    return roots


def kape_home() -> Path | None:
    env = (os.environ.get("NEXUS_KAPE_HOME") or "").strip()
    if env:
        p = Path(env)
        if p.is_dir():
            return p
    for root in extra_search_roots():
        for cand in (root / "kape", root):
            if (cand / "kape.exe").is_file() or (cand / "gkape.exe").is_file():
                return cand
    return None


def kape_exe() -> Path | None:
    home = kape_home()
    if not home:
        return None
    return _first_file([home / "kape.exe", home / "gkape.exe"])


def kape_list(kind: str = "targets") -> list[dict[str, str]]:
    """List compound + leaf KAPE targets or modules next to kape.exe."""
    home = kape_home()
    if not home:
        return []
    folder = "Targets" if kind.lower().startswith("target") else "Modules"
    base = home / folder
    if not base.is_dir():
        return []
    glob = "*.tkape" if folder == "Targets" else "*.mkape"
    rows: list[dict[str, str]] = []
    for f in sorted(base.rglob(glob)):
        if "!Disabled" in f.parts:
            continue
        rows.append({
            "name": f.stem,
            "file": f.name,
            "rel": str(f.relative_to(base)).replace("\\", "/"),
        })
    return rows


def kansa_ps1() -> Path | None:
    env = (os.environ.get("NEXUS_KANSA_HOME") or "").strip()
    candidates: list[Path] = []
    if env:
        p = Path(env)
        candidates.extend([p if p.suffix.lower() == ".ps1" else p / "kansa.ps1", p / "Kansa.ps1"])
    for root in extra_search_roots():
        candidates.extend([
            root / "kansa" / "kansa.ps1",
            root / "kansa" / "Kansa.ps1",
            root / "Kansa" / "kansa.ps1",
        ])
    return _first_file(candidates)


def winpmem_exe() -> Path | None:
    names = ("winpmem.exe", "winpmem_mini_x64.exe", "winpmem_mini_x86.exe")
    for root in extra_search_roots():
        for n in names:
            hit = _first_file([
                root / "memory" / n,
                root / n,
                root / "winpmem" / n,
            ])
            if hit:
                return hit
    return None


def uac_home() -> Path | None:
    env = (os.environ.get("NEXUS_UAC_HOME") or "").strip()
    if env:
        p = Path(env)
        if p.is_dir():
            return p
        if p.is_file() and p.name.lower().startswith("uac"):
            return p.parent
    for root in extra_search_roots():
        d = _first_dir([root / "uac", root / "UAC"])
        if d is not None and ((d / "uac").is_file() or any(d.glob("uac*"))):
            return d
        for f in root.glob("uac-*/uac"):
            if f.is_file():
                return f.parent
    return None


def avml_exe() -> Path | None:
    env = (os.environ.get("NEXUS_AVML") or "").strip()
    if env and Path(env).is_file():
        return Path(env)
    for root in extra_search_roots():
        hit = _first_file([root / "avml", root / "memory" / "avml", root / "avml" / "avml"])
        if hit:
            return hit
    return None


def orc_exe() -> Path | None:
    """Prefer a ToolEmbed-ready capsule, else the GitHub DFIR-ORC.exe."""
    names = ("DFIR-ORC-ready.exe", "DFIR-ORC.exe", "DFIR-Orc.exe")
    for root in extra_search_roots():
        for n in names:
            hit = _first_file([
                root / "orc" / n,
                root / "dfir-orc" / n,
                root / n,
            ])
            if hit:
                return hit
    env = (os.environ.get("NEXUS_ORC") or "").strip()
    if env and Path(env).is_file():
        return Path(env)
    return None


def _glob_exe(root: Path, prefixes: tuple[str, ...]) -> Path | None:
    if not root.is_dir():
        return None
    hits: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        low = p.name.lower()
        if low.endswith(".exe") or p.suffix == "":
            if any(low.startswith(pref) for pref in prefixes):
                hits.append(p)
    if not hits:
        return None
    exact = [h for h in hits if h.stem.lower() in prefixes]
    return (exact or hits)[0]


def hayabusa_exe() -> Path | None:
    env = (os.environ.get("NEXUS_HAYABUSA") or "").strip()
    if env and Path(env).is_file():
        return Path(env)
    for root in extra_search_roots():
        hit = _first_file([
            root / "hayabusa" / "hayabusa.exe",
            root / "hayabusa.exe",
        ]) or _glob_exe(root / "hayabusa", ("hayabusa",))
        if hit:
            return hit
    return None


def suzaku_exe() -> Path | None:
    env = (os.environ.get("NEXUS_SUZAKU") or "").strip()
    if env and Path(env).is_file():
        return Path(env)
    for root in extra_search_roots():
        hit = _first_file([
            root / "suzaku" / "suzaku.exe",
            root / "suzaku.exe",
        ]) or _glob_exe(root / "suzaku", ("suzaku",))
        if hit:
            return hit
    return None


def chainsaw_home() -> Path | None:
    for root in extra_search_roots():
        for cand in (root / "extra" / "chainsaw", root / "chainsaw"):
            if (cand / "chainsaw.exe").is_file() or (cand / "chainsaw").is_file():
                return cand
    return None


def chainsaw_exe() -> Path | None:
    home = chainsaw_home()
    if not home:
        return None
    return _first_file([home / "chainsaw.exe", home / "chainsaw"])


def chainsaw_mapping() -> Path | None:
    home = chainsaw_home()
    if not home:
        return None
    return _first_file([
        home / "mappings" / "sigma-event-logs-all.yml",
        home / "sigma-event-logs-all.yml",
    ])


def chainsaw_sigma() -> Path | None:
    home = chainsaw_home()
    if not home:
        return None
    for cand in (home / "sigma", home / "rules"):
        if cand.is_dir() and any(cand.rglob("*.yml")):
            return cand
    return None


def sysinternals_exe(name: str) -> Path | None:
    """Locate autorunsc / handle / tcpvcon / listdlls (64-bit preferred)."""
    stem = name.lower().replace(".exe", "")
    names = (f"{stem}64.exe", f"{stem}.exe", f"{stem[0].upper() + stem[1:]}64.exe", f"{stem[0].upper() + stem[1:]}.exe")
    for root in extra_search_roots():
        for folder in (root / "sysinternals", root / "orc" / "config" / "tools", root):
            for n in names:
                hit = _first_file([folder / n])
                if hit:
                    return hit
            if folder.is_dir():
                for p in folder.glob("*"):
                    if p.is_file() and p.stem.lower().replace("64", "") == stem:
                        return p
    return None


def persistencesniper_psm1() -> Path | None:
    for root in extra_search_roots():
        hit = _first_file([
            root / "orc" / "config" / "tools" / "PersistenceSniper.psm1",
            root / "persistencesniper" / "PersistenceSniper.psm1",
            root / "PersistenceSniper.psm1",
        ])
        if hit:
            return hit
        if (root / "orc" / "config" / "tools").is_dir():
            found = next((root / "orc" / "config" / "tools").rglob("PersistenceSniper.psm1"), None)
            if found:
                return found
    return None


def velociraptor_exe() -> Path | None:
    env = (os.environ.get("NEXUS_VELOCIRAPTOR") or "").strip()
    if env and Path(env).is_file():
        return Path(env)
    names = ("velociraptor.exe", "velociraptor-windows.exe", "velociraptor")
    for root in extra_search_roots():
        for n in names:
            hit = _first_file([
                root / "velociraptor" / n,
                root / n,
            ])
            if hit:
                return hit
        hit = _glob_exe(root / "velociraptor", ("velociraptor",))
        if hit:
            return hit
    return None


def kansa_home() -> Path | None:
    ps1 = kansa_ps1()
    return ps1.parent if ps1 else None


def tool_inventory() -> dict[str, object]:
    kh = kape_home()
    cs_sigma = chainsaw_sigma()
    return {
        "profile_default": "disk",
        "kape_home": str(kh) if kh else "",
        "kape_exe": str(kape_exe() or ""),
        "kape_targets": [r["name"] for r in kape_list("targets") if r["name"].startswith("!")],
        "kape_modules_compound": [
            r["name"] for r in kape_list("modules") if r["name"].startswith("!")
        ],
        "kansa_ps1": str(kansa_ps1() or ""),
        "kansa_builtin": True,
        "winpmem": str(winpmem_exe() or ""),
        "dfir_orc": str(orc_exe() or ""),
        "uac_home": str(uac_home() or ""),
        "uac_profiles": ["full", "ir_triage"],
        "avml": str(avml_exe() or ""),
        "linux_builtin": True,
        "hayabusa": str(hayabusa_exe() or ""),
        "suzaku": str(suzaku_exe() or ""),
        "chainsaw": str(chainsaw_exe() or ""),
        "chainsaw_mapping": str(chainsaw_mapping() or ""),
        "chainsaw_sigma": str(cs_sigma or ""),
        "autorunsc": str(sysinternals_exe("autorunsc") or ""),
        "handle": str(sysinternals_exe("handle") or ""),
        "tcpvcon": str(sysinternals_exe("tcpvcon") or ""),
        "listdlls": str(sysinternals_exe("listdlls") or ""),
        "pslist": str(sysinternals_exe("pslist") or ""),
        "psloggedon": str(sysinternals_exe("psloggedon") or ""),
        "logonsessions": str(sysinternals_exe("logonsessions") or ""),
        "pipelist": str(sysinternals_exe("pipelist") or ""),
        "persistencesniper": str(persistencesniper_psm1() or ""),
        "velociraptor_exe": str(velociraptor_exe() or ""),
    }
