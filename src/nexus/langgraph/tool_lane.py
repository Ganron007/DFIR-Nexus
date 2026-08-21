"""Deterministic MCP tool lane — mandatory parser pass for all pipeline modes.

Every host-triage tool whose artifact is **present on this evidence** is
scheduled, executed via MCP (``run_windows_command`` / ``run_command``),
and recorded in a ledger (OK / FAIL / SKIP + reason).

Presence comes from knowledge YAML locations
(``src/nexus/data/knowledge/artifacts/windows/*.yaml``) plus well-known
paths. Argv stays here (YAML ``quick_start`` is not structured enough).

  tools     — this lane only; no RAG, no LLM. SKIP = artifact absent.
  coverage  — this lane, then RAG+LLM interpret. FAIL does not abort interpret.
  design    — this lane first, then ReAct may **add** corroboration tools.

The LLM does **not** choose whether mandatory parsers run.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shlex
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class ToolJob:
    host: str  # "windows" | "sift"
    tool: str
    argv: list[str]
    purpose: str
    timeout: int = 600
    status: str = "PENDING"  # PENDING | OK | FAIL | SKIP
    reason: str = ""
    audit_id: str = ""
    output_saved_to: str = ""
    output_files: list[dict] = field(default_factory=list)


def timeout_for_bytes(
    nbytes: int,
    *,
    base: int = 600,
    per_mb: int = 30,
    cap: int = 3600,
) -> int:
    """Scale a parser timeout from input size. Floor ``base``, ceiling ``cap``.

    Large RDP ``Cache0000.bin`` files and dirty ESE DBs must not share the
    default 600s with a 4 KB prefetch CSV.
    """
    try:
        n = max(0, int(nbytes))
    except (TypeError, ValueError):
        n = 0
    mb = n // (1024 * 1024)
    return min(cap, max(base, base + mb * per_mb))


def _copy_ese_siblings(src_dir: Path, work: Path, prefixes: tuple[str, ...]) -> None:
    """Copy ESE database + log siblings onto a writable local workdir."""
    work.mkdir(parents=True, exist_ok=True)
    prefs = tuple(p.upper() for p in prefixes)
    for src in src_dir.iterdir():
        if not src.is_file():
            continue
        if not any(src.name.upper().startswith(p) for p in prefs):
            continue
        dst = work / src.name
        shutil.copy2(src, dst)
        with contextlib.suppress(OSError):
            os.chmod(dst, 0o666)


def _esentutl_repair(work: Path, *, db_name: str, log_bases: tuple[str, ...]) -> None:
    """Soft-fail ESE recovery + repair. Missing esentutl is a warning, not SKIP."""
    try:
        for base in log_bases:
            subprocess.run(
                ["esentutl.exe", "/r", base, "/i"],
                cwd=str(work),
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        subprocess.run(
            ["esentutl.exe", "/p", db_name, "/o"],
            cwd=str(work),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("esentutl repair skipped for %s: %s", db_name, exc)


def find_windows_root(evidence: Path) -> Path | None:
    """Locate a Windows image root (directory containing Windows/System32)."""
    if not evidence.exists():
        return None
    if (evidence / "Windows" / "System32").is_dir():
        return evidence
    if evidence.is_file():
        return None
    try:
        for candidate in evidence.iterdir():
            if candidate.is_dir() and (candidate / "Windows" / "System32").is_dir():
                return candidate
    except OSError:
        return None
    # one more level
    try:
        for candidate in evidence.rglob("System32"):
            if candidate.is_dir() and candidate.parent.name == "Windows":
                return candidate.parent.parent
            if len(candidate.parts) > 8:
                break
    except OSError:
        return None
    return None


def plan_windows_triage(
    evidence_path: str,
    extractions: Path,
    sample_files: list[str] | None = None,
    extras: list[str] | None = None,
) -> list[ToolJob]:
    """Build Windows host-triage jobs from YAML discovery + all user profiles."""
    from nexus.langgraph.artifact_map import user_profile_dirs

    jobs: list[ToolJob] = []
    root = find_windows_root(Path(evidence_path))
    if root is None:
        jobs.append(ToolJob(
            host="windows",
            tool="(discovery)",
            argv=[],
            purpose="locate Windows root",
            status="SKIP",
            reason=f"No Windows/System32 under evidence path: {evidence_path}",
        ))
        return jobs

    users = user_profile_dirs(root)
    logs_dir = root / "Windows/System32/winevt/Logs"
    prefetch = root / "Windows/Prefetch"
    amcache = root / "Windows/AppCompat/Programs/Amcache.hve"
    system_hive = root / "Windows/System32/config/SYSTEM"
    software_hive = root / "Windows/System32/config/SOFTWARE"
    srum = root / "Windows/System32/sru/SRUDB.dat"
    mft = root / "$MFT"
    recycle = root / "$Recycle.Bin"
    config_dir = root / "Windows/System32/config"

    def add(tool: str, argv: list[str], purpose: str, timeout: int = 600) -> None:
        jobs.append(ToolJob(
            host="windows",
            tool=tool,
            argv=argv,
            purpose=purpose,
            timeout=timeout,
        ))

    def skip(tool: str, reason: str) -> None:
        jobs.append(ToolJob(
            host="windows",
            tool=tool,
            argv=[],
            purpose="",
            status="SKIP",
            reason=reason,
        ))

    evtx_files = list(logs_dir.glob("*.evtx")) if logs_dir.is_dir() else []
    if evtx_files:
        hay_dir = extractions / "hayabusa"
        hay_dir.mkdir(parents=True, exist_ok=True)
        add(
            "hayabusa",
            [
                "hayabusa", "dfir-timeline", "-d", str(logs_dir),
                "-o", str(hay_dir / "evtx-timeline.csv"),
                "-w", "-C", "-Q",
            ],
            f"EVTX timeline ({len(evtx_files)} logs)",
            1800,
        )
        ev_dir = extractions / "evtxecmd"
        ev_dir.mkdir(parents=True, exist_ok=True)
        add(
            "evtxecmd",
            ["evtxecmd", "-d", str(logs_dir), "--csv", str(ev_dir)],
            f"Parse all EVTX ({len(evtx_files)} logs)",
            1800,
        )
    else:
        skip("hayabusa", f"no *.evtx under {logs_dir}")
        skip("evtxecmd", f"no *.evtx under {logs_dir}")

    if prefetch.is_dir():
        d = extractions / "pecmd"
        d.mkdir(parents=True, exist_ok=True)
        add(
            "pecmd",
            ["pecmd", "-d", str(prefetch), "--csv", str(d), "--csvf", "prefetch.csv"],
            "Prefetch execution evidence",
            600,
        )
    else:
        skip("pecmd", f"missing {prefetch}")

    if amcache.is_file():
        d = extractions / "amcache"
        d.mkdir(parents=True, exist_ok=True)
        add(
            "amcacheparser",
            ["amcacheparser", "-f", str(amcache), "--csv", str(d), "--csvf", "amcache.csv"],
            "Amcache application execution",
            300,
        )
    else:
        skip("amcacheparser", f"missing {amcache}")

    if system_hive.is_file():
        d = extractions / "appcompat"
        d.mkdir(parents=True, exist_ok=True)
        add(
            "appcompatcacheparser",
            [
                "appcompatcacheparser", "-f", str(system_hive),
                "--csv", str(d), "--csvf", "appcompat.csv",
            ],
            "Shimcache / AppCompat",
            300,
        )
    else:
        skip("appcompatcacheparser", f"missing {system_hive}")

    if srum.is_file():
        d = extractions / "srum"
        d.mkdir(parents=True, exist_ok=True)
        work = d / "workdir"
        try:
            _copy_ese_siblings(srum.parent, work, ("SRU",))
            _esentutl_repair(work, db_name="SRUDB.dat", log_bases=("sru",))
            srum_target = work / "SRUDB.dat"
            argv = ["srumecmd", "-f", str(srum_target), "--csv", str(d)]
            if software_hive.is_file():
                argv.extend(["-r", str(software_hive)])
            add("srumecmd", argv, "SRUM database (repaired copy)", 600)
        except OSError as exc:
            skip("srumecmd", f"could not stage SRUDB copy: {exc}")
    else:
        skip("srumecmd", f"missing {srum}")

    quick = os.environ.get("NEXUS_TOOL_LANE_QUICK", "").strip() in ("1", "true", "yes")
    if mft.is_file() and not quick:
        d = extractions / "mftecmd"
        d.mkdir(parents=True, exist_ok=True)
        add(
            "mftecmd",
            ["mftecmd", "-f", str(mft), "--csv", str(d), "--csvf", "mft.csv"],
            "MFT parse (CSV)",
            1800,
        )
        body_dir = extractions / "mftecmd-body"
        body_dir.mkdir(parents=True, exist_ok=True)
        add(
            "mftecmd",
            ["mftecmd", "-f", str(mft), "--body", str(body_dir), "--bdl", "C"],
            "MFT bodyfile for mactime (FOR508)",
            1800,
        )
    elif mft.is_file() and quick:
        skip("mftecmd", "skipped (NEXUS_TOOL_LANE_QUICK=1)")
    else:
        skip("mftecmd", f"missing {mft}")

    usn = None
    for cand in (
        root / "$Extend" / "$J",
        root / "$J",
        root / "$Extend" / "$UsnJrnl:$J",
    ):
        try:
            if cand.is_file() and cand.stat().st_size >= 4096:
                usn = cand
                break
        except OSError:
            continue
    if usn is None:
        ext = root / "$Extend"
        if ext.is_dir():
            try:
                for p in ext.iterdir():
                    try:
                        if (
                            p.is_file()
                            and p.stat().st_size >= 4096
                            and (
                                p.name in ("$J", "$UsnJrnl")
                                or "usn" in p.name.lower()
                            )
                        ):
                            usn = p
                            break
                    except OSError:
                        continue
            except OSError:
                pass
    if usn is not None and usn.is_file() and not quick:
        d = extractions / "mftecmd-usn"
        d.mkdir(parents=True, exist_ok=True)
        add(
            "mftecmd",
            ["mftecmd", "-f", str(usn), "--csv", str(d), "--csvf", "usn.csv"],
            "USN Journal ($J)",
            1800,
        )
    elif quick:
        skip("mftecmd-usn", "skipped (NEXUS_TOOL_LANE_QUICK=1)")
    else:
        skip("mftecmd-usn", "no usable $J (Samba $UsnJrnl is often 0 bytes)")

    if recycle.is_dir():
        d = extractions / "rbcmd"
        d.mkdir(parents=True, exist_ok=True)
        add(
            "rbcmd",
            ["rbcmd", "-d", str(recycle), "--csv", str(d)],
            "Recycle Bin ($I)",
            300,
        )
    else:
        skip("rbcmd", "no $Recycle.Bin")

    lecmd_n = jlecmd_n = sbecmd_n = wxtcmd_n = sqlecmd_n = 0
    for user in users:
        uname = user.name
        recent = user / "AppData/Roaming/Microsoft/Windows/Recent"
        if recent.is_dir():
            d = extractions / "lecmd"
            d.mkdir(parents=True, exist_ok=True)
            add(
                "lecmd",
                [
                    "lecmd", "-d", str(recent),
                    "--csv", str(d), "--csvf", f"{uname}-recent-lnk.csv",
                ],
                f"Recent LNK files ({uname})",
                300,
            )
            lecmd_n += 1
        auto_jl = recent / "AutomaticDestinations"
        custom_jl = recent / "CustomDestinations"
        jl_dir = auto_jl if auto_jl.is_dir() else custom_jl
        if jl_dir.is_dir():
            d = extractions / "jlecmd"
            d.mkdir(parents=True, exist_ok=True)
            add(
                "jlecmd",
                [
                    "jlecmd", "-d", str(jl_dir),
                    "--csv", str(d), "--csvf", f"{uname}-jumplist.csv",
                ],
                f"Jump lists ({uname})",
                300,
            )
            jlecmd_n += 1
        usrclass = user / "AppData/Local/Microsoft/Windows/UsrClass.dat"
        if usrclass.is_file():
            d = extractions / "sbecmd"
            d.mkdir(parents=True, exist_ok=True)
            add(
                "sbecmd",
                [
                    "sbecmd", "-f", str(usrclass),
                    "--csv", str(d), "--csvf", f"{uname}-shellbags.csv",
                ],
                f"Shellbags UsrClass.dat ({uname})",
                600,
            )
            sbecmd_n += 1
        cdp = user / "AppData/Local/ConnectedDevicesPlatform"
        if cdp.is_dir():
            for act in cdp.rglob("ActivitiesCache.db"):
                if act.is_file():
                    d = extractions / "wxtcmd"
                    d.mkdir(parents=True, exist_ok=True)
                    add(
                        "wxtcmd",
                        ["wxtcmd", "-f", str(act), "--csv", str(d)],
                        f"ActivitiesCache ({uname})",
                        300,
                    )
                    wxtcmd_n += 1
                    break
        sql_targets: list[tuple[Path, str]] = [
            (
                user / "AppData/Local/Google/Chrome/User Data/Default/History",
                f"{uname}-chrome-history",
            ),
            (
                user / "AppData/Local/Microsoft/Edge/User Data/Default/History",
                f"{uname}-edge-history",
            ),
        ]
        ff_root = user / "AppData/Roaming/Mozilla/Firefox/Profiles"
        if ff_root.is_dir():
            for places in ff_root.glob("*/places.sqlite"):
                sql_targets.append((places, f"{uname}-firefox-places"))
        d_sql = extractions / "sqlecmd"
        for db, label in sql_targets:
            if db.is_file():
                d_sql.mkdir(parents=True, exist_ok=True)
                add(
                    "sqlecmd",
                    ["sqlecmd", "-f", str(db), "--csv", str(d_sql)],
                    f"Browser SQLite ({label})",
                    300,
                )
                sqlecmd_n += 1

    if not users:
        skip("lecmd", "no user profile")
        skip("jlecmd", "no user profile")
        skip("sbecmd", "no user profile")
        skip("wxtcmd", "no user profile")
        skip("sqlecmd", "no user profile")
    else:
        if not lecmd_n:
            skip("lecmd", "no Users/*/Recent directory")
        if not jlecmd_n:
            skip("jlecmd", "no AutomaticDestinations/CustomDestinations")
        if not sbecmd_n:
            skip("sbecmd", "no UsrClass.dat")
        if not wxtcmd_n:
            skip("wxtcmd", "no ActivitiesCache.db")
        if not sqlecmd_n:
            skip("sqlecmd", "no Chrome/Edge/Firefox history databases")

    batch = _find_recmd_batch()
    if batch and config_dir.is_dir() and software_hive.is_file():
        d = extractions / "recmd"
        d.mkdir(parents=True, exist_ok=True)
        add(
            "recmd",
            ["recmd", "-d", str(config_dir), "--bn", str(batch), "--csv", str(d)],
            f"Registry batch ({batch.name})",
            900,
        )
        user_batch = _find_recmd_user_batch() or batch
        for user in users:
            ntuser = user / "NTUSER.DAT"
            if ntuser.is_file():
                ud = d / "user" / user.name
                ud.mkdir(parents=True, exist_ok=True)
                add(
                    "recmd",
                    [
                        "recmd", "-f", str(ntuser),
                        "--bn", str(user_batch), "--csv", str(ud),
                    ],
                    f"NTUSER.DAT ({user.name}, {user_batch.name})",
                    600,
                )
    elif not batch:
        skip("recmd", "RECmd .reb batch not found under tools/windows")
    else:
        skip("recmd", f"missing software hive / config dir under {root}")

    _plan_gap_parsers(
        root, users, extractions, add, skip, quick,
        sample_files=sample_files,
    )
    _plan_n2_extras(root, users, extractions, add, skip, extras or [])
    return jobs


def _windows_tool_available(key: str) -> bool:
    """True when the catalog binary is on this analysis host (Tools/windows or PATH)."""
    try:
        from nexus.tools.windows import _WIN_CATALOG, _find_binary
    except Exception:
        return False
    info = _WIN_CATALOG.get(key) or {}
    for cand in (key, str(info.get("name") or "")):
        if cand and _find_binary(cand) is not None:
            return True
    return False


def _copy_text(extractions: Path, rel: str, src: Path) -> None:
    """Stage a plain-text artifact into extractions. Not a parser.

    Skip if already staged (leftover re-run). KAPE/VHDX sources are often
    ReadOnly; chmod the dest so later overwrite does not PermissionError.
    """
    dest = extractions / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file():
        return
    try:
        shutil.copy2(src, dest)
        with contextlib.suppress(OSError):
            os.chmod(dest, 0o666)
    except OSError as exc:
        log.warning("stage %s failed: %s", dest, exc)


def _plan_n2_extras(
    root: Path,
    users: list[Path],
    extractions: Path,
    add,
    skip,
    extras: list[str],
) -> None:
    """Examiner-gated parsers. Default lane stays Default-profile / setupapi copy."""
    wanted = {e.strip().lower() for e in extras if e.strip()}
    if not wanted:
        return

    if "chrome_profiles" in wanted:
        n = 0
        d_sql = extractions / "sqlecmd"
        for user in users:
            chrome_ud = user / "AppData/Local/Google/Chrome/User Data"
            if not chrome_ud.is_dir():
                continue
            for prof in chrome_ud.iterdir():
                if not prof.is_dir():
                    continue
                if prof.name.lower() in {"default", "system profile", "guest profile"}:
                    continue
                hist = prof / "History"
                if not hist.is_file():
                    continue
                d_sql.mkdir(parents=True, exist_ok=True)
                label = f"{user.name}-{prof.name}-chrome-history"
                add(
                    "sqlecmd",
                    ["sqlecmd", "-f", str(hist), "--csv", str(d_sql)],
                    f"Browser SQLite extra profile ({label})",
                    300,
                )
                n += 1
        if not n:
            skip("chrome_profiles", "no Chrome Profile*/History besides Default")

    if "drivefs" in wanted:
        n = 0
        for user in users:
            gdfs = user / "AppData/Local/Google/DriveFS"
            if not gdfs.is_dir():
                continue
            dest = extractions / "drivefs" / user.name
            dest.mkdir(parents=True, exist_ok=True)
            for logf in list(gdfs.rglob("*.log"))[:20] + list(gdfs.rglob("*.txt"))[:20]:
                if logf.is_file() and logf.stat().st_size < 20 * 1024 * 1024:
                    _copy_text(dest, logf.name, logf)
                    n += 1
        if not n:
            skip("drivefs", "no Google DriveFS logs under user profiles")

    if "email" in wanted:
        n = 0
        dest = extractions / "email"
        for user in users:
            for folder in (
                user / "Documents",
                user / "AppData/Local/Microsoft/Outlook",
                user / "AppData/Roaming/Microsoft/Outlook",
            ):
                if not folder.is_dir():
                    continue
                for pat in ("*.pst", "*.ost"):
                    for mail in folder.glob(pat):
                        if mail.is_file() and mail.stat().st_size < 80 * 1024 * 1024:
                            dest.mkdir(parents=True, exist_ok=True)
                            _copy_text(dest, f"{user.name}-{mail.name}", mail)
                            n += 1
        if not n:
            skip("email", "no PST/OST under Documents/Outlook")

    if "usb_serial" in wanted:
        setupapi = extractions / "setupapi" / "setupapi.dev.log"
        src = setupapi if setupapi.is_file() else root / "Windows/INF/setupapi.dev.log"
        if src.is_file():
            serials = _usb_serials_from_setupapi(src)
            outp = extractions / "usb" / "setupapi-serials.txt"
            outp.parent.mkdir(parents=True, exist_ok=True)
            outp.write_text("\n".join(serials) + ("\n" if serials else ""), encoding="utf-8")
            if not serials:
                skip("usb_serial", "setupapi present but no USBSTOR serial lines")
        else:
            skip("usb_serial", "setupapi.dev.log not present")


def _usb_serials_from_setupapi(path: Path) -> list[str]:
    found: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return found
    for line in text.splitlines():
        low = line.lower()
        if "usbstor" in low or "serial number" in low or "usb\\vid_" in low:
            found.append(line.strip()[:240])
            if len(found) >= 80:
                break
    return found


def _plan_gap_parsers(
    root: Path,
    users: list[Path],
    extractions: Path,
    add,
    skip,
    quick: bool,
    sample_files: list[str] | None = None,
) -> None:
    """Optional host artifacts — only when present AND the parser is installed.

    No strings-on-text. No guessed CLIs. No SKIP spam for live tools or
    absent rare artifacts. Unverified CLIs stay cataloged, not auto-run.
    """
    setupapi = root / "Windows/INF/setupapi.dev.log"
    if setupapi.is_file():
        _copy_text(extractions, "setupapi/setupapi.dev.log", setupapi)

    for user in users:
        for pattern in (
            "Documents/PowerShell_transcript*.txt",
            "Documents/PowerShell/PowerShell_transcript*.txt",
        ):
            parent = user / Path(pattern).parent
            if not parent.is_dir():
                continue
            for txt in sorted(parent.glob(Path(pattern).name))[:8]:
                if txt.is_file():
                    _copy_text(
                        extractions,
                        f"transcripts/{user.name}/{txt.name}",
                        txt,
                    )
        hist = (
            user / "AppData/Roaming/Microsoft/Windows/PowerShell"
            / "PSReadLine/ConsoleHost_history.txt"
        )
        if hist.is_file():
            _copy_text(
                extractions,
                f"psreadline/{user.name}-ConsoleHost_history.txt",
                hist,
            )

    def add_installed(key: str, argv: list[str], purpose: str, timeout: int = 600) -> bool:
        if not _windows_tool_available(key):
            skip(key, f"{key} not installed — run tools/fetch-windows-tools.ps1 then nexus doctor")
            return False
        add(key, argv, purpose, timeout)
        return True

    # Known CLIs only. Thumbcache Viewer CMD and LogFileParser stay
    # cataloged until their argv is verified on a real binary.
    bmc_jobs: list[tuple[Path, Path, list[Path]]] = []
    for user in users:
        cache = user / "AppData/Local/Microsoft/Terminal Server Client/Cache"
        if not cache.is_dir():
            continue
        try:
            tiles = [
                p for p in cache.iterdir()
                if p.is_file() and p.suffix.lower() in {".bmc", ".bin"}
            ]
        except OSError:
            continue
        if tiles:
            bmc_jobs.append((user, cache, tiles))
    if bmc_jobs:
        if not _windows_tool_available("bmc-tools"):
            skip("bmc-tools", "bmc-tools not installed — run tools/fetch-windows-tools.ps1 then nexus doctor")
        else:
            for user, _cache, tiles in bmc_jobs:
                usable: list[Path] = []
                total = 0
                for p in tiles:
                    try:
                        sz = p.stat().st_size
                    except OSError:
                        continue
                    if sz > 0:
                        usable.append(p)
                        total += sz
                if not usable:
                    skip(
                        "bmc-tools",
                        f"RDP cache present for {user.name} but all tiles are 0 bytes",
                    )
                    continue
                src_dir = extractions / "bmc-tools" / user.name / "src"
                out = extractions / "bmc-tools" / user.name / "tiles"
                src_dir.mkdir(parents=True, exist_ok=True)
                out.mkdir(parents=True, exist_ok=True)
                try:
                    for p in usable:
                        dst = src_dir / p.name
                        shutil.copy2(p, dst)
                        with contextlib.suppress(OSError):
                            os.chmod(dst, 0o666)
                except OSError as exc:
                    skip("bmc-tools", f"could not stage RDP cache for {user.name}: {exc}")
                    continue
                add(
                    "bmc-tools",
                    ["bmc-tools", "-s", str(src_dir), "-d", str(out)],
                    (
                        f"RDP bitmap cache ({user.name}, {len(usable)} files, "
                        f"{total} bytes staged)"
                    ),
                    timeout_for_bytes(total),
                )

    downloader = root / "ProgramData/Microsoft/Network/Downloader"
    qmgr = None
    for name in ("qmgr.db", "qmgr0.dat", "qmgr1.dat"):
        cand = downloader / name
        if cand.is_file():
            qmgr = cand
            break
    if qmgr is not None:
        if not _windows_tool_available("bitsparser"):
            skip(
                "bitsparser",
                "bitsparser not installed — run tools/fetch-windows-tools.ps1 then nexus doctor",
            )
        else:
            work = extractions / "bitsparser" / "workdir"
            out = extractions / "bitsparser"
            out.mkdir(parents=True, exist_ok=True)
            try:
                _copy_ese_siblings(qmgr.parent, work, ("QMGR", "EDB"))
                _esentutl_repair(work, db_name=qmgr.name, log_bases=("edb", "qmgr"))
                staged = work / qmgr.name
                if not staged.is_file():
                    skip("bitsparser", f"staged {qmgr.name} missing after copy")
                else:
                    sz = staged.stat().st_size
                    add(
                        "bitsparser",
                        ["bitsparser", "-i", str(staged), "-o", str(out / "bits.json")],
                        f"BITS job queue ({qmgr.name}, repaired copy)",
                        timeout_for_bytes(sz),
                    )
            except OSError as exc:
                skip("bitsparser", f"could not stage qmgr: {exc}")

    sum_dir = root / "Windows/System32/LogFiles/SUM"
    mdbs = sorted(sum_dir.glob("*.mdb")) if sum_dir.is_dir() else []
    if mdbs:
        if not _windows_tool_available("kstrike"):
            skip("kstrike", "KStrike not installed — run tools/fetch-windows-tools.ps1 then nexus doctor")
        else:
            for mdb in mdbs[:4]:
                add("kstrike", ["kstrike", str(mdb)], f"UAL ESE ({mdb.name})", 600)

    i30_files = [p for p in (root / "$I30", root / "FileSystem" / "$I30") if p.is_file()]
    if i30_files and not quick:
        out = extractions / "mftecmd-i30"
        out.mkdir(parents=True, exist_ok=True)
        for i30 in i30_files[:3]:
            add(
                "mftecmd",
                ["mftecmd", "-f", str(i30), "--csv", str(out), "--csvf", f"{i30.name}.csv"],
                f"NTFS $I30 ({i30.name})",
                600,
            )

    samples = list(sample_files or [])
    env_samples = os.environ.get("NEXUS_SAMPLE_FILES", "").strip()
    if env_samples:
        samples.extend(
            p.strip() for p in env_samples.replace(";", ",").split(",") if p.strip()
        )
    seen: set[str] = set()
    uniq: list[str] = []
    for s in samples:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    samples = uniq[:10]
    yara_rules = os.environ.get("NEXUS_YARA_RULES", "").strip()
    if samples:
        present = [Path(s) for s in samples if Path(s).is_file()]
        missing = [s for s in samples if not Path(s).is_file()]
        for s in missing:
            skip("capa", f"sample_files path missing: {s}")
        if present:
            capa_ok = _windows_tool_available("capa")
            dens_ok = _windows_tool_available("densityscout")
            yara_ok = bool(yara_rules) and _windows_tool_available("yara")
            if not capa_ok:
                skip("capa", "capa not installed — fetch with Tools/fetch-windows-tools.ps1")
            if not dens_ok:
                skip("densityscout", "densityscout not installed — fetch with Tools/fetch-windows-tools.ps1")
            if yara_rules and not yara_ok:
                skip("yara", "yara not installed — fetch with Tools/fetch-windows-tools.ps1")
            for p in present:
                if capa_ok:
                    add("capa", ["capa", str(p)], f"capa ({p.name})", 600)
                if dens_ok:
                    add("densityscout", ["densityscout", str(p)], f"densityscout ({p.name})", 120)
                if yara_ok:
                    add("yara", ["yara", yara_rules, str(p)], f"yara ({p.name})", 300)

    live = os.environ.get("NEXUS_LIVE_RESPONSE", "").strip().lower() in ("1", "true", "yes")
    if live:
        add_installed(
            "autorunsc",
            ["autorunsc", "-accepteula", "-a", "*", "-c"],
            "Live autoruns CSV",
            300,
        )
        add_installed("handle", ["handle", "-accepteula"], "Live open handles", 120)
        add_installed("get_injectedthreadex", ["get_injectedthreadex"], "Live injected-thread scan", 300)
        mem = os.environ.get("NEXUS_LIVE_ACQUIRE_MEMORY", "").strip().lower() in ("1", "true", "yes")
        if mem:
            out = extractions / "memory"
            out.mkdir(parents=True, exist_ok=True)
            add_installed(
                "winpmem",
                ["winpmem", str(out / "physical.raw")],
                "Live physical memory (operator-gated)",
                3600,
            )


def _repo_root() -> Path:
    # .../src/nexus/langgraph/tool_lane.py → repo root
    return Path(__file__).resolve().parents[3]


def _find_recmd_batch() -> Path | None:
    root = _repo_root()
    for rel in (
        # DFIRBatch.reb fails this RECmd build (HiveType 'User' not in enum).
        "tools/windows/zimmerman/net9/RECmd/BatchExamples/Kroll_Batch.reb",
        "tools/windows/zimmerman/net9/RECmd/BatchExamples/RECmd_Batch_MC.reb",
        "tools/windows/kape/Modules/bin/RECmd/RECmd_Batch_MC.reb",
        "tools/windows/zimmerman/net9/RECmd/BatchExamples/BasicSystemInfo.reb",
        "tools/windows/zimmerman/net9/RECmd/BatchExamples/DFIRBatch.reb",
    ):
        p = root / rel
        if p.is_file():
            return p
    return None


def _find_recmd_user_batch() -> Path | None:
    root = _repo_root()
    for rel in (
        "tools/windows/zimmerman/net9/RECmd/BatchExamples/UserActivity.reb",
        "tools/windows/kape/Modules/bin/RECmd/BatchExamples/UserActivity.reb",
        "tools/windows/zimmerman/net9/RECmd/BatchExamples/DFIRBatch.reb",
    ):
        p = root / rel
        if p.is_file():
            return p
    return None


def _job_reuse_key(host: str, tool: str, purpose: str) -> tuple[str, str, str]:
    return (host, tool, purpose)


def apply_prior_ok(jobs: list[ToolJob], case_dir: Path) -> int:
    """Reuse prior OK ledger rows so leftover re-runs do not re-parse Hayabusa/MFT.

    Match on host+tool+purpose (argv changes when cases_root moves).
    ``NEXUS_TOOL_LANE_RERUN=1`` disables reuse.
    """
    import json

    if os.environ.get("NEXUS_TOOL_LANE_RERUN", "").strip().lower() in ("1", "true", "yes"):
        return 0
    paths = [
        Path(case_dir) / "extractions" / "_tool_lane_ledger.json",
        Path(case_dir) / "ledger" / "_tool_lane_ledger.json",
    ]
    prior: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(loaded, list):
            prior = loaded
            break
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in prior:
        if row.get("status") != "OK":
            continue
        key = _job_reuse_key(
            str(row.get("host") or ""),
            str(row.get("tool") or ""),
            str(row.get("purpose") or ""),
        )
        index.setdefault(key, row)
    reused = 0
    for job in jobs:
        if job.status != "PENDING":
            continue
        old = index.get(_job_reuse_key(job.host, job.tool, job.purpose))
        if not old:
            continue
        job.status = "OK"
        job.audit_id = str(old.get("audit_id") or "")
        job.output_saved_to = str(old.get("output_saved_to") or "")
        job.output_files = list(old.get("output_files") or [])
        job.reason = "reused prior OK (already in case extractions)"
        reused += 1
    return reused


def plan_sift_triage(
    sift_evidence_root: str,
    triage_root: str | None = None,
    memory_file: str | None = None,
) -> list[ToolJob]:
    """Build SIFT jobs when a Linux-visible evidence root is configured.

    ``run_command`` denies shells (bash/sh) and shell metacharacters — only
    direct binaries with simple argv are scheduled.

    Default pack for KAPE triage testing: **Volatility against memory only**.
    Full E01 / ``fls`` is opt-in via explicit ``NEXUS_SIFT_E01`` (not assumed).
    """
    jobs: list[ToolJob] = []
    root = (sift_evidence_root or "").strip().rstrip("/")
    if not root:
        jobs.append(ToolJob(
            host="sift",
            tool="(discovery)",
            argv=[],
            purpose="SIFT evidence root",
            status="SKIP",
            reason=(
                "No SIFT evidence root — set NEXUS_SIFT_EVIDENCE_ROOT or "
                "case_context.sift_evidence_root for memory/disk tools"
            ),
        ))
        return jobs

    # Memory: env / intake, then a conventional file under the named root.
    mem = (memory_file or "").strip() or os.environ.get("NEXUS_SIFT_MEMORY_FILE", "").strip()
    if not mem:
        if "rocba" in root.lower():
            mem = f"{root}/memory/Rocba-Memory.raw"
        else:
            mem = f"{root}/memory/rd01-memory.img"
    for plugin, timeout in (
        ("windows.info", 1800),
        ("windows.pslist", 3600),
        ("windows.cmdline", 3600),
    ):
        jobs.append(ToolJob(
            host="sift",
            tool="vol",
            argv=["vol", "-f", mem, plugin],
            purpose=f"Volatility3 {plugin}",
            timeout=timeout,
        ))

    # Filesystem timeline: MFTECmd --body (Windows) → TSK mactime (SIFT),
    # injected in run_tool_lane after the bodyfile is pushed. Full-tree
    # log2timeline is opt-in (SIFT disk often cannot hold a multi-GB store).
    plaso = os.environ.get("NEXUS_SIFT_PLASO", "").strip().lower() in ("1", "true", "yes")
    if plaso:
        store = f"{root}/plaso.plaso"
        jobs.append(ToolJob(
            host="sift",
            tool="log2timeline",
            argv=["log2timeline", "--storage-file", store, root],
            purpose="Plaso super-timeline (NEXUS_SIFT_PLASO=1 — large disk required)",
            timeout=7200,
        ))
        jobs.append(ToolJob(
            host="sift",
            tool="psort",
            argv=["psort", "-o", "l2tcsv", "-w", f"{root}/plaso.csv", store],
            purpose="psort Plaso store to CSV",
            timeout=3600,
        ))

    # E01 / fls only when the operator explicitly points at an image.
    # KAPE triage on Windows (H:\) already covers filesystem artifacts.
    e01 = os.environ.get("NEXUS_SIFT_E01", "").strip()
    if e01:
        jobs.append(ToolJob(
            host="sift",
            tool="fls",
            argv=["fls", "-p", e01],
            purpose=f"fls root listing on E01 ({e01})",
            timeout=300,
        ))
    return jobs


def sift_jobs_for_lane(
    sift_root: str,
    *,
    has_sift_mcp: bool,
    triage_root: str | None = None,
    memory_file: str | None = None,
) -> list[ToolJob]:
    """Schedule SIFT jobs only when a root is named or a SIFT MCP exists.

    Windows-only stdio (no ``run_command``, no root) must not emit a SKIP
    row — that looked like a coverage hole on a KAPE host-image run.
    If SIFT MCP is connected but the root is unset, keep the honest SKIP.
    """
    root = (sift_root or "").strip()
    if not root and not has_sift_mcp:
        return []
    return plan_sift_triage(
        root,
        triage_root=triage_root,
        memory_file=memory_file,
    )


async def run_tool_lane(
    *,
    tools: dict[str, Any],
    evidence_path: str,
    case_id: str,
    case_context: dict[str, str] | None = None,
    parse_result: Callable[[Any], dict],
    skip_rag: bool = True,
    pipeline_mode: str = "",
    strict: bool | None = None,
) -> dict[str, Any]:
    """Execute the planned triage lane via MCP tools. Returns ledger + audit_ids.

    RAG does not belong in this lane (``skip_rag=True``). Coverage/design load
    RAG in ``ensure_rag`` / interpret. Strict FAIL→error is **tools mode only**.
    """
    from nexus.config import settings

    ctx = dict(case_context or {})
    case_dir = settings.cases_root / case_id
    try:
        from nexus.langgraph.query_pack import load_case_intake

        for key, val in load_case_intake(case_dir).items():
            if val and not str(ctx.get(key) or "").strip():
                ctx[key] = val
    except Exception as exc:  # noqa: BLE001
        log.warning("case intake merge skipped: %s", exc)
    extractions = case_dir / "extractions"
    extractions.mkdir(parents=True, exist_ok=True)

    win_tool = tools.get("run_windows_command")
    sift_tool = tools.get("run_command")
    rag_tool = None if skip_rag else tools.get("forensic_rag_search")

    rag_notes: list[str] = []
    if rag_tool:
        try:
            rag = parse_result(await rag_tool.ainvoke({
                "query": (
                    "Windows host forensic triage methodology: event logs, "
                    "prefetch, amcache, shimcache, SRUM, MFT, browser history, "
                    "memory volatility process list cmdline"
                ),
            }))
            snippet = str(rag.get("answer") or rag.get("results") or rag)[:800]
            if snippet:
                rag_notes.append(snippet)
        except Exception as exc:  # noqa: BLE001
            rag_notes.append(f"RAG error: {exc}")

    jobs = plan_windows_triage(
        evidence_path,
        extractions,
        sample_files=[
            p.strip()
            for p in str(ctx.get("sample_files") or "").replace(";", ",").split(",")
            if p.strip()
        ],
        extras=[
            p.strip()
            for p in str(ctx.get("extras") or "").replace(";", ",").split(",")
            if p.strip()
        ],
    )
    try:
        import json as _json

        from nexus.langgraph.artifact_map import (
            completeness_table,
            discover_windows_artifacts,
        )

        win_root = find_windows_root(Path(evidence_path))
        if win_root is not None:
            scheduled = {j.tool for j in jobs if j.status == "PENDING"}
            table = completeness_table(
                discover_windows_artifacts(win_root), scheduled,
            )
            (extractions / "_artifact_completeness.json").write_text(
                _json.dumps(table, indent=2), encoding="utf-8",
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("artifact completeness table failed: %s", exc)
    sift_root = (
        str(ctx.get("sift_evidence_root") or "").strip()
        or os.environ.get("NEXUS_SIFT_EVIDENCE_ROOT", "").strip()
    )
    jobs.extend(sift_jobs_for_lane(
        sift_root,
        has_sift_mcp=sift_tool is not None,
        triage_root=str(ctx.get("sift_triage_root") or "").strip() or None,
        memory_file=str(ctx.get("sift_memory_file") or "").strip() or None,
    ))
    reused = apply_prior_ok(jobs, case_dir)
    if reused:
        log.info("tool_lane reused %s prior OK job(s)", reused)

    audit_ids: list[str] = []
    ledger: list[dict[str, Any]] = []

    async def _run_one(job: ToolJob) -> None:
        if job.status in ("SKIP", "OK"):
            ledger.append(asdict(job))
            return
        if job.host == "windows":
            if not win_tool:
                job.status = "SKIP"
                job.reason = "run_windows_command not available on MCP"
                ledger.append(asdict(job))
                return
            try:
                raw = await win_tool.ainvoke({
                    "command": job.argv,
                    "purpose": job.purpose,
                    "timeout": job.timeout,
                    "save_output": True,
                })
                result = parse_result(raw)
            except Exception as exc:  # noqa: BLE001
                job.status = "FAIL"
                job.reason = str(exc)
                ledger.append(asdict(job))
                return
        else:
            if not sift_tool:
                job.status = "SKIP"
                job.reason = "run_command not available on MCP"
                ledger.append(asdict(job))
                return
            cmd = " ".join(shlex.quote(a) for a in job.argv)
            try:
                raw = await sift_tool.ainvoke({
                    "command": cmd,
                    "purpose": job.purpose,
                    "timeout": job.timeout,
                })
                result = parse_result(raw)
            except Exception as exc:  # noqa: BLE001
                job.status = "FAIL"
                job.reason = str(exc)
                ledger.append(asdict(job))
                return

        aid = str(result.get("audit_id") or "")
        job.audit_id = aid
        job.output_saved_to = str(result.get("output_saved_to") or "")
        job.output_files = list(result.get("output_files") or [])
        if result.get("success") is False or result.get("error"):
            job.status = "FAIL"
            job.reason = str(result.get("error") or result.get("stderr") or "tool failed")[:500]
        elif result.get("exit_code") not in (None, 0, "0") and result.get("success") is not True:
            code = result.get("exit_code")
            job.status = "FAIL"
            job.reason = f"exit_code={code}: {(result.get('stderr') or '')[:300]}"
        else:
            job.status = "OK"
            soft = _soft_fail_reason(result)
            if soft:
                job.status = "FAIL"
                job.reason = soft[:500]
        if aid:
            audit_ids.append(aid)
        ledger.append(asdict(job))
        log.info(
            "tool_lane %s/%s -> %s audit_id=%s saved=%s",
            job.host, job.tool, job.status, aid, job.output_saved_to or "-",
        )

    win_jobs = [j for j in jobs if j.host == "windows"]
    sift_jobs = [j for j in jobs if j.host != "windows"]
    for job in win_jobs:
        await _run_one(job)

    bodyfiles = sorted(extractions.rglob("*.body"))
    if bodyfiles and sift_tool:
        remote_body = f"/tmp/nexus-{case_id}.body"
        try:
            from nexus.case.sift_sync import push_file

            pushed = push_file(bodyfiles[0], remote_body)
        except Exception as exc:  # noqa: BLE001
            pushed = False
            log.warning("bodyfile push failed: %s", exc)
        # Default: do not run mactime. A full-MFT bodyfile is hundreds of MB;
        # mactime -d writes a multi-GB CSV to stdout, fills the MCP pipe, and
        # deadlocks until timeout. The bodyfile itself is the examiner artifact.
        mactime_on = os.environ.get("NEXUS_SIFT_MACTIME", "").strip().lower() in (
            "1", "true", "yes",
        )
        if mactime_on and pushed:
            sift_jobs.append(ToolJob(
                host="sift",
                tool="mactime",
                argv=["mactime", "-b", remote_body, "-d", "-z", "UTC"],
                purpose="TSK mactime from MFTECmd bodyfile (NEXUS_SIFT_MACTIME=1)",
                timeout=1800,
            ))
        elif mactime_on and not pushed:
            log.warning("NEXUS_SIFT_MACTIME=1 but bodyfile push failed; not FAIL")

    for job in sift_jobs:
        await _run_one(job)

    ok = sum(1 for j in ledger if j.get("status") == "OK")
    fail = sum(1 for j in ledger if j.get("status") == "FAIL")
    skip = sum(1 for j in ledger if j.get("status") == "SKIP")
    summary = f"Tool lane complete: OK={ok} FAIL={fail} SKIP={skip} (case={case_id})"
    log.info(summary)

    # Dual-MCP: SIFT audit_ids live on the SIFT host. Bridge them into the
    # examiner case audit log so FD-001 provenance validates on Windows.
    bridged = _bridge_remote_audits(case_dir, ledger)
    if bridged:
        summary = f"{summary}; bridged {bridged} remote audit_ids"

    # Persist ledger into case for examiners / report
    try:
        import json
        out = extractions / "_tool_lane_ledger.json"
        out.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    except OSError as exc:
        log.warning("Could not write tool lane ledger: %s", exc)

    try:
        import json as _json
        from nexus.langgraph.artifact_map import (
            apply_ledger_to_completeness,
            completeness_table,
            discover_windows_artifacts,
        )

        dest = extractions / "_artifact_completeness.json"
        win_root = find_windows_root(Path(evidence_path))
        if win_root is not None:
            table = completeness_table(
                discover_windows_artifacts(win_root),
                {j.tool for j in jobs if j.status == "PENDING"},
                ledger=ledger,
            )
            dest.write_text(_json.dumps(table, indent=2), encoding="utf-8")
        elif dest.is_file():
            rows = _json.loads(dest.read_text(encoding="utf-8"))
            dest.write_text(
                _json.dumps(apply_ledger_to_completeness(rows, ledger), indent=2),
                encoding="utf-8",
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("artifact completeness refresh failed: %s", exc)

    # Pull SIFT extractions onto examiner case (scp) so LLM + report see them
    try:
        from nexus.case.sift_sync import pull_sift_extractions

        pulled = pull_sift_extractions(case_id, case_dir)
        if pulled:
            summary = f"{summary}; sift_pull={pulled}"
    except Exception as exc:  # noqa: BLE001
        log.warning("SIFT pull failed: %s", exc)
        summary = f"{summary}; sift_pull_error={exc}"

    try:
        from nexus.langgraph.snippets import write_snippets

        snip = write_snippets(case_dir, ledger)
        summary = f"{summary}; snippets={snip}"
    except Exception as exc:  # noqa: BLE001
        log.warning("snippet write failed: %s", exc)

    step_log = [summary]
    # Strict abort is tools-mode only. Coverage/design record FAILs in the
    # ledger and continue to interpret OK families.
    if strict is None:
        env_strict = os.environ.get("NEXUS_TOOL_LANE_STRICT", "1").strip().lower() in (
            "1", "true", "yes",
        )
        strict = bool(pipeline_mode == "tools" and env_strict)
    out: dict[str, Any] = {
        "tool_run_ledger": ledger,
        "evidence_audit_ids": audit_ids,
        "rag_notes": rag_notes,
        "step_log": step_log,
    }
    if strict and fail:
        fails = [
            f"{r.get('host')}/{r.get('tool')}: {r.get('reason', '')[:120]}"
            for r in ledger if r.get("status") == "FAIL"
        ]
        out["error"] = (
            f"Tool lane FAIL={fail} (strict mode). "
            + "; ".join(fails[:6])
        )
        step_log.append(out["error"])
    return out


def _soft_fail_reason(result: dict[str, Any]) -> str:
    """Detect tools that exit 0 but print a hard failure into stdout/stderr."""
    blob = "\n".join(
        str(result.get(k) or "")
        for k in ("stdout", "stderr", "preview", "message", "error")
    )
    saved = str(result.get("output_saved_to") or "")
    if saved and Path(saved).is_file():
        with contextlib.suppress(OSError):
            blob += "\n" + Path(saved).read_text(encoding="utf-8", errors="replace")[:8000]
    markers = (
        "Error processing file!",
        "Error reading image file",
        "Cannot access file, the file is locked",
        "EsentFileAccessDenied",
        "Traceback (most recent call last)",
    )
    for m in markers:
        if m in blob:
            # Partial EvtxECmd record errors still often produce a usable CSV —
            # if output_files or a sibling .csv exists, do not soft-fail.
            outs = result.get("output_files") or []
            if outs and "Error processing record" in blob and "Error processing file!" not in blob:
                continue
            idx = blob.find(m)
            return blob[idx:idx + 240].replace("\n", " ")
    return ""


def _bridge_remote_audits(case_dir: Path, ledger: list[dict[str, Any]]) -> int:
    """Write remote (SIFT) audit_id rows into the examiner case audit jsonl."""
    import json
    from datetime import UTC, datetime

    audit_path = case_dir / "audit" / "nexus.jsonl"
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return 0

    existing: set[str] = set()
    if audit_path.is_file():
        try:
            for line in audit_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    existing.add(str(json.loads(line).get("audit_id") or ""))
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass

    written = 0
    try:
        with audit_path.open("a", encoding="utf-8") as fh:
            for row in ledger:
                if row.get("host") != "sift" or row.get("status") != "OK":
                    continue
                aid = str(row.get("audit_id") or "")
                if not aid or aid in existing:
                    continue
                entry = {
                    "ts": datetime.now(UTC).isoformat(),
                    "mcp": "nexus",
                    "tool": f"remote_{row.get('tool') or 'run_command'}",
                    "audit_id": aid,
                    "examiner": "system",
                    "case_id": case_dir.name,
                    "source": "mcp",
                    "params": {
                        "remote_host": "sift",
                        "purpose": row.get("purpose", ""),
                        "output_saved_to": row.get("output_saved_to", ""),
                    },
                    "result_summary": {
                        "status": "OK",
                        "bridged": True,
                        "output_files": row.get("output_files") or [],
                    },
                }
                fh.write(json.dumps(entry, default=str) + "\n")
                existing.add(aid)
                written += 1
    except OSError as exc:
        log.warning("Remote audit bridge failed: %s", exc)
        return written
    return written
