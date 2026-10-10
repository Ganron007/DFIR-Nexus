"""MemProcFS lane job (WO-TA item 6).

Runs MemProcFS 5.19 **through its Python API**, in forensic mode, on the
registered memory image in place. **No mount, no Dokany driver** - the
operator's condition, proven on SC1's `rd01-memory.img` (5 GB raw): the VMM
initialises, `process_list()` returns 160 processes and the kernel build reads
22000, in about 11 seconds, with no filesystem mounted.

The FindEvil YARA rules need `-license-accept-elastic-license-2-0`. That flag
is **not** passed: it is the operator's decision, and MemProcFS says so itself
when it starts ("Built-in Yara rules from Elastic are disabled"). Forensic mode
still initialises and its own outputs are still produced.

What is written, one file per table, so the case indexer indexes each as a row
under family `memprocfs`:

  processes.csv    /pid/  - one row per process
  processmap.csv   /name/ - the name -> pid mapping
  net.csv          /sys/net/netstat.txt
  sysinfo.csv      the /sys/ scalar files (build, computername, boot time ...)
  modules.csv      per-process /pid/<pid>/modules.txt
  threads.csv      per-process /pid/<pid>/threads.txt
  handles.csv      per-process /pid/<pid>/handles.txt
  forensic.json    the /forensic/ control outputs, for the record

Only MemProcFS's own paths are read. Nothing is guessed: every path below was
listed from the live VFS on SC1's image.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def _vfs_list(vfs, path: str) -> list[str]:
    try:
        return list(vfs.list(path).keys())
    except Exception:  # noqa: BLE001 - a missing branch is simply absent
        return []


def _vfs_read(vfs, path: str) -> str:
    try:
        return vfs.read(path).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - control files are write-only
        return ""


def _write_csv(path: Path, header: list[str], rows: list[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="registered memory image")
    parser.add_argument("--out", required=True, help="extractions output directory")
    parser.add_argument("--forensic", type=int, default=1,
                        help="1 = forensic mode (in-memory sqlite). Default 1.")
    args = parser.parse_args()

    image = Path(args.image)
    if not image.is_file():
        print(f"memprocfs: image not found: {image}", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    try:
        import memprocfs
    except ImportError as exc:
        print(f"memprocfs: the Python API is not installed ({exc})", file=sys.stderr)
        return 3

    # The binding takes the same argv as the exe, so the path goes through
    # -device. A bare path raises "Illegal argument"; this was verified on the
    # real image rather than assumed.
    argv = ["-device", str(image.resolve())]
    if args.forensic:
        argv += ["-forensic", str(args.forensic)]
    try:
        vmm = memprocfs.Vmm(argv)
    except Exception as exc:  # noqa: BLE001 - the gate must see the reason
        print(f"memprocfs: Vmm initialisation failed: {exc}", file=sys.stderr)
        return 4

    vfs = vmm.vfs
    written: dict[str, int] = {}

    # --- processes -------------------------------------------------------
    pids = _vfs_list(vfs, "/pid/")
    rows = []
    for pid in pids:
        base = f"/pid/{pid}/"
        rows.append({
            "pid": pid,
            "name": _vfs_read(vfs, base + "name.txt").strip(),
            "ppid": _vfs_read(vfs, base + "ppid.txt").strip(),
            "state": _vfs_read(vfs, base + "state.txt").strip(),
            "dtb": _vfs_read(vfs, base + "dtb.txt").strip(),
            "path": _vfs_read(vfs, base + "path.txt").strip(),
            "cmdline": _vfs_read(vfs, base + "cmdline.txt").strip(),
            "user": _vfs_read(vfs, base + "user.txt").strip(),
            "create_time": _vfs_read(vfs, base + "create-time.txt").strip(),
            "exit_time": _vfs_read(vfs, base + "exit-time.txt").strip(),
        })
    written["processes.csv"] = _write_csv(
        out / "processes.csv",
        ["pid", "name", "ppid", "state", "dtb", "path", "cmdline", "user",
         "create_time", "exit_time"],
        rows,
    )

    # --- name -> pid map --------------------------------------------------
    names = _vfs_list(vfs, "/name/")
    written["processmap.csv"] = _write_csv(
        out / "processmap.csv",
        ["name_pid", "pid", "name"],
        [
            {
                "name_pid": entry,
                "pid": entry.rsplit("-", 1)[-1],
                "name": entry.rsplit("-", 1)[0],
            }
            for entry in names
        ],
    )

    # --- network ----------------------------------------------------------
    net = _vfs_read(vfs, "/sys/net/netstat.txt")
    net_rows = []
    for line in net.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            net_rows.append({
                "proto": parts[0], "state": parts[1],
                "local": parts[2], "remote": parts[3],
                "pid": parts[4] if len(parts) > 4 else "",
            })
    written["net.csv"] = _write_csv(
        out / "net.csv", ["proto", "state", "local", "remote", "pid"], net_rows
    )

    # --- system scalars ---------------------------------------------------
    sys_files = _vfs_list(vfs, "/sys/")
    sys_rows = [
        {"file": name, "value": _vfs_read(vfs, f"/sys/{name}").strip()}
        for name in sys_files
    ]
    written["sysinfo.csv"] = _write_csv(out / "sysinfo.csv", ["file", "value"], sys_rows)

    # --- per-process tables (modules / threads / handles) -----------------
    # The paths and column layouts below were read from the live VFS on SC1's
    # image, not guessed: MemProcFS keeps each under its own subdirectory
    # (/pid/<pid>/threads/threads.txt) and prints its own header plus a dashed
    # separator, which must not become rows.
    for label, vfs_path, columns in (
        ("modules", "modules/modules.txt",
         ["index", "pid", "pages", "range_start", "range_end", "description"]),
        ("threads", "threads/threads.txt",
         ["index", "pid", "tid", "ethread", "status", "wait_reason", "prio",
          "exit_st", "start_address", "win32_start_address"]),
        ("handles", "handles/handles.txt",
         ["index", "pid", "handle", "object_address", "access", "type",
          "description"]),
    ):
        table_rows = []
        for pid in pids:
            for line in _vfs_read(vfs, f"/pid/{pid}/{vfs_path}").splitlines():
                stripped = line.strip()
                # MemProcFS's own header and separator are not data.
                if not stripped or stripped.startswith("#") or set(stripped) <= {"-"}:
                    continue
                parts = stripped.split()
                row = {"pid": pid}
                for field, value in zip(columns, parts, strict=False):
                    if field == "pid":
                        continue
                    row[field] = value
                # the range column is one token "start-end" in the source
                if "range_start" in columns and len(parts) >= 4:
                    bounds = parts[3].split("-", 1)
                    row["range_start"] = bounds[0]
                    row["range_end"] = bounds[1] if len(bounds) > 1 else ""
                    row["description"] = " ".join(parts[4:])
                table_rows.append(row)
        if table_rows:
            written[f"{label}.csv"] = _write_csv(
                out / f"{label}.csv", columns, table_rows
            )

    # --- the forensic control outputs, kept for the record ----------------
    forensic_entries = _vfs_list(vfs, "/forensic/")
    (out / "forensic.json").write_text(
        json.dumps(
            {
                "entries": forensic_entries,
                "readme": _vfs_read(vfs, "/forensic/readme.txt"),
                "elastic_yara": "disabled - -license-accept-elastic-license-2-0 "
                                "not passed (operator decision)",
                "processes": len(rows),
                "image": str(image),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    total = sum(v for v in written.values())
    print(
        "memprocfs: " + " ".join(f"{k}={v}" for k, v in written.items())
        + f" rows={total}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
