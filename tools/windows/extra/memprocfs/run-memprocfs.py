"""MemProcFS lane job (WO-TA item 6, D68).

Runs MemProcFS 5.19 through its Python API, in forensic mode, on the registered memory image in
place. No mount and no Dokany driver: the VMM initialises and serves its virtual file system
without one.

Forensic mode finishes after Vmm() returns. Its outputs appear while MemProcFS works through
progress, and /forensic/progress_percent.txt reads 100 when it is done. Measured on
rd01-memory.img: 0 -> 100 in about 25 s, with 38 CSV files and the timelines in place. The earlier
wrapper read /forensic/ straight after Vmm() returned, found nothing, and recorded no timeline and
no FindEvil (D68). This one waits for progress 100 and for the listing to settle, then copies.

The FindEvil YARA rules need -license-accept-elastic-license-2-0. That flag is not passed: it is
the operator's decision, and MemProcFS itself reports the Elastic rules as disabled. Forensic mode
still runs and writes its own outputs.

Written under --out:
  processes.csv, processmap.csv, net.csv, sysinfo.csv, modules.csv, threads.csv, handles.csv
      the process and system tables (one family, memprocfs)
  forensic/<folder>/<file>
      MemProcFS's own forensic outputs, copied once each
  forensic.json
      the wait, every file copied with its row count, and every file skipped with its reason

Duplicates are not copied twice. MemProcFS writes the same timeline three ways: csv/timeline_*.csv,
timeline/timeline_*.txt and json/timeline.json, and csv/timeline_all.csv is the union of the
per-source CSVs. A duplicate is skipped only when its row count matches its pair, and that check is
recorded in forensic.json. A duplicate that does not match is copied.

Exit status: 0 when forensic mode reached 100 and its listing settled; 5 when it did not finish
within the wait (the outputs copied so far are kept, and the lane job fails, so the gate shows it).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from pathlib import Path

FORENSIC = "/forensic/"
PROGRESS = "/forensic/progress_percent.txt"
FORENSIC_WAIT_S = 1800
FORENSIC_QUIET_S = 10
CHUNK = 0x00100000
# Boilerplate, scripts, and binaries whose parsed text is already copied (prefetch .pf -> .pf.txt).
SKIP_NAMES = ("readme.txt", "database.txt", "forensic_enable.txt", "progress_percent.txt")
SKIP_SUFFIXES = (".ps1", ".pf")


def _listing(vfs, path: str) -> dict:
    try:
        return dict(vfs.list(path))
    except Exception:  # noqa: BLE001 - a missing branch is simply absent
        return {}


def _read_text(vfs, path: str) -> str:
    try:
        return vfs.read(path, 64, 0).decode("ascii", "replace").strip()
    except Exception:  # noqa: BLE001
        return ""


_WINDOWS_BAD = re.compile(r'[<>:"|?*]')
_NTFS_VOLUME = re.compile(r"ntfs/\d+/")


def _safe_dest(root: Path, rel: str) -> Path:
    """A destination under ``root`` whose every part is a legal Windows file name."""
    return root.joinpath(*[_WINDOWS_BAD.sub("_", part) for part in rel.split("/")])


def _tree(vfs, path: str = FORENSIC, out: list | None = None) -> list[tuple[str, int]]:
    out = [] if out is None else out
    for name, meta in sorted(_listing(vfs, path).items()):
        full = path + name
        if meta.get("f_isdir"):
            _tree(vfs, full + "/", out)
        else:
            out.append((full, int(meta.get("size") or 0)))
    return out


def _wait_for_forensic(vfs) -> dict:
    """Wait for MemProcFS to report progress 100, then for the output listing to stop changing."""
    started = time.time()
    history: list[tuple[float, str]] = []
    progress = ""
    while True:
        # Read at least once, so the record says where forensic mode was when the wait ended.
        progress = _read_text(vfs, PROGRESS)
        if not history or history[-1][1] != progress:
            history.append((round(time.time() - started, 1), progress))
        if progress == "100" or time.time() - started >= FORENSIC_WAIT_S:
            break
        time.sleep(3)
    settled = False
    if progress == "100":
        before = tuple(_tree(vfs))
        time.sleep(FORENSIC_QUIET_S)
        settled = tuple(_tree(vfs)) == before
    return {
        "progress": progress,
        "progress_history": history,
        "settled": settled,
        "waited_s": round(time.time() - started, 1),
    }


def _stream(vfs, src: str, size: int, dst: Path) -> tuple[int, int]:
    """Copy one virtual file to ``dst`` in chunks. Returns (bytes written, newline-terminated rows)."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    rows = 0
    last = b""
    with dst.open("wb") as handle:
        offset = 0
        while offset < size:
            chunk = vfs.read(src, CHUNK, offset)
            if not chunk:
                break
            handle.write(chunk)
            rows += chunk.count(b"\n")
            last = chunk[-1:]
            written += len(chunk)
            offset += len(chunk)
    if written and last != b"\n":
        rows += 1  # a final line without its newline is still a row
    return written, rows


def _copy_forensic(vfs, out: Path, wait: dict) -> tuple[list[dict], list[dict]]:
    """Copy MemProcFS's forensic outputs. Returns (copied, skipped), each a list of dicts."""
    copied: list[dict] = []
    skipped: list[dict] = []
    failures: list[dict] = []
    # Whole trees and boilerplate are skipped in bulk: one entry per group, with its file count,
    # bytes and a few examples. One entry per file would run to hundreds of thousands of rows
    # (files/ROOT alone holds the image's file system). Duplicates keep their own entry below.
    groups: dict[str, dict] = {}

    def _group(key: str, rel: str, size: int, reason: str) -> None:
        entry = groups.setdefault(key, {"group": f"forensic/{key}", "files": 0, "bytes": 0,
                                        "reason": reason, "examples": []})
        entry["files"] += 1
        entry["bytes"] += size
        if len(entry["examples"]) < 5:
            entry["examples"].append(f"forensic/{rel}")

    files = _tree(vfs)
    root = out / "forensic"
    deferred: list[tuple[str, int]] = []

    # Pass 1: everything that is not a deferred duplicate. The CSVs are copied here, so their
    # row counts are known for the duplicate checks in pass 2.
    csv_rows: dict[str, int] = {}
    for path, size in files:
        rel = path[len(FORENSIC):]
        base = rel.rsplit("/", 1)[-1]
        if base.lower() in SKIP_NAMES or base.lower().endswith(SKIP_SUFFIXES):
            _group("boilerplate-script-binary", rel, size,
                   "boilerplate, script or binary (its parsed text is copied)")
            continue
        if rel.startswith("files/ROOT/"):
            _group("files/ROOT", rel, size, "the file-system view of the image (files/ROOT, NTFS names "
                   "included); its table is copied as files/files.txt")
            continue
        volume = _NTFS_VOLUME.match(rel)
        if volume:
            _group(volume.group(0).rstrip("/"), rel, size, "a raw file of the image served per NTFS volume "
                   "(ntfs/<n>/); the table is copied as ntfs/ntfs_files.txt")
            continue
        if rel.startswith("timeline/") or rel in ("csv/timeline_all.csv", "json/timeline.json"):
            deferred.append((path, size))
            continue
        dst = _safe_dest(root, rel)
        try:
            written, rows = _stream(vfs, path, size, dst)
        except (OSError, RuntimeError) as exc:
            dst.unlink(missing_ok=True)
            failures.append({"file": f"forensic/{rel}", "reason": f"copy failed: {exc}"})
            continue
        copied.append({"file": f"forensic/{rel}", "bytes": written, "rows": rows})
        if rel.startswith("csv/"):
            csv_rows[base] = rows

    # Pass 2: the duplicates. A copy is kept only if its rows do not match its pair.
    # Each csv/timeline_*.csv has one header, so its data rows are its count minus one.
    per_source = {name: count for name, count in csv_rows.items()
                  if name.startswith("timeline_") and name != "timeline_all.csv"}
    union_data = sum(max(0, count - 1) for count in per_source.values())
    for path, size in deferred:
        rel = path[len(FORENSIC):]
        base = rel.rsplit("/", 1)[-1]
        dst = root / rel
        tmp = dst.with_name(dst.name + ".tmp")
        try:
            written, rows = _stream(vfs, path, size, tmp)
        except (OSError, RuntimeError) as exc:
            tmp.unlink(missing_ok=True)
            failures.append({"file": f"forensic/{rel}", "reason": f"copy failed: {exc}"})
            continue
        if rel == "csv/timeline_all.csv":
            expected = union_data + 1  # with its header
            reason = f"the union of the {len(per_source)} csv/timeline_*.csv sources ({union_data} data rows)"
        elif rel == "json/timeline.json":
            expected = union_data  # JSON lines, no header
            reason = f"the JSON form of the union of the {len(per_source)} csv/timeline_*.csv sources"
        elif base == "timeline_all.txt":
            expected = union_data  # text lines, no header
            reason = f"the text form of the union of the {len(per_source)} csv/timeline_*.csv sources"
        else:
            # timeline/timeline_<source>.txt holds the data rows of csv/timeline_<source>.csv
            pair_name = base[:-4] + ".csv"
            pair = csv_rows.get(pair_name)
            expected = (pair - 1) if pair else -1
            reason = f"the text form of csv/{pair_name} (its data rows)"
        if expected >= 0 and rows == expected:
            tmp.unlink(missing_ok=True)
            skipped.append({"file": f"forensic/{rel}", "reason": f"duplicate: {reason}; {rows} rows match"})
        else:
            os.replace(tmp, dst)
            copied.append({"file": f"forensic/{rel}", "bytes": written, "rows": rows,
                           "note": f"kept: {rows} rows, expected {expected}"})
    skipped.extend(failures)
    skipped.extend(groups.values())
    return copied, skipped


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

    # --- forensic outputs (D68) -------------------------------------------
    wait = _wait_for_forensic(vfs)
    copied, skipped = _copy_forensic(vfs, out, wait)
    forensic_root = sorted(_listing(vfs, FORENSIC).keys())
    (out / "forensic.json").write_text(
        json.dumps(
            {
                "image": str(image),
                "processes": len(rows),
                "wait": wait,
                "root": forensic_root,
                "readme": _vfs_read(vfs, FORENSIC + "readme.txt")[:2000],
                "elastic_yara": "disabled - -license-accept-elastic-license-2-0 "
                                "not passed (operator decision)",
                "copied": copied,
                "skipped": skipped,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    total = sum(v for v in written.values())
    print(
        "memprocfs: " + " ".join(f"{k}={v}" for k, v in written.items())
        + f" forensic_files={len(copied)} forensic_skipped={len(skipped)}"
        + f" forensic_progress={wait['progress']} settled={wait['settled']} rows={total}"
    )
    if wait["progress"] != "100" or not wait["settled"]:
        print("memprocfs: forensic mode did not finish (progress "
              f"{wait['progress']!r}, settled {wait['settled']})", file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
