"""Import source-checked NTFS timestomp facts from pinned MFTECmd and Microsoft docs."""
from __future__ import annotations

import argparse
import hashlib
import html
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SNAPSHOT_ROOT = HERE / "pinned" / "timestomp"
OUT = REPO / "src" / "nexus" / "data" / "knowledge" / "sources" / "timestomp.yaml"

# TA-Z (2026-10-24): the source of the MFTECmd release the lane runs, 2026.10.2 (.NET 10, pinned in
# devtools/runbook/zimmerman-net10.json). The earlier pin, b76bfec (2026.5.0), stays under pinned/ for its history.
MFTE_VERSION = "2919ded0738d1533c8ab6b627a5aed2c9f67859c"
MFTE_PRODUCT = "2026.10.2"
MS_VERSION = "656e9656bfaef34dd29cd7ee9e1146aec17e924c"
MFTE_FILES = {
    "README.md": "f514338e24f9b16d4448c9fd1ecdfc2861ba7a76a4b8fbc871b1a8c931c778a6",
    "MFTECmd/MFTRecordOut.cs": "cc0d23c73668225f2630cd9c94f2d02de7be36378e60c16f5541872a0cd7eaf6",
    "MFTECmd/Program.cs": "20121c4e82e58dd8a572f4645544d0f698a36e940be2d4d10be27bca14345869",
    "MFTECmd/MFTECmd.csproj": "e8a859efdab2038757fef9a8f3200ae43f021888fc6b7b704c290794c5e7b659",
}
MS_FILE = "winioctl/ns-winioctl-usn_record_v2.md"
MS_SHA256 = "e677d73106d449fc11666bb668bc029871a63d54a5e52b508433396cce31fdb0"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot(repo: str, version: str, rel_path: str, expected_sha256: str) -> tuple[Path, str]:
    path = SNAPSHOT_ROOT / repo / version / rel_path
    if not path.is_file():
        raise ValueError(f"pinned source is missing: {path}")
    actual = _sha256(path)
    if actual != expected_sha256:
        raise ValueError(f"pinned source hash changed: {rel_path}: {actual}")
    return path, path.read_text(encoding="utf-8-sig")


def _need(text: str, fragment: str, source_key: str) -> None:
    if fragment not in text:
        raise ValueError(f"pinned source no longer supports {source_key}: missing {fragment!r}")


def _plain(text: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", text)).split())


def build() -> dict[str, Any]:
    mfte: dict[str, tuple[Path, str]] = {}
    for rel_path, digest in MFTE_FILES.items():
        mfte[rel_path] = _snapshot("mftecmd", MFTE_VERSION, rel_path, digest)
    ms_path, ms_raw = _snapshot("sdk-api", MS_VERSION, MS_FILE, MS_SHA256)

    readme = mfte["README.md"][1]
    record_out = mfte["MFTECmd/MFTRecordOut.cs"][1]
    program = mfte["MFTECmd/Program.cs"][1]
    project = mfte["MFTECmd/MFTECmd.csproj"][1]
    version = ET.fromstring(project).findtext(".//Version") or ""
    if version != MFTE_PRODUCT:
        raise ValueError(f"pinned MFTECmd source version changed: expected {MFTE_PRODUCT}, got {version!r}")
    _need(readme, "Parses the NTFS metadata files `$MFT`, `$J` (`$UsnJrnl:$J`), `$LogFile`", "MFTECmd README identity")
    readme_flat = " ".join(readme.split())  # the README wraps its sentences at 120 columns
    _need(readme_flat, "`-f $LogFile` exports one row per log record (CSV and/or JSON), ordered by LSN",
          "MFTECmd $LogFile rows")
    _need(readme_flat, "With `-m`, `TargetPath` is the target's path in that $MFT", "MFTECmd $LogFile -m paths")
    _need(readme_flat, "With `-f $J -m $MFT`, the `ParentPath` of each $J record is the path its parent directory had "
                       "when the record was written", "MFTECmd $J -m paths")
    _need(readme_flat, "Without `-m`, `ParentPath` is empty", "MFTECmd $J without -m")
    _need(record_out, "public bool Timestomped { get; set; }", "MFTECmd Timestomped output")
    _need(record_out, "public bool uSecZeros { get; set; }", "MFTECmd uSecZeros output")
    _need(record_out, "public bool Copied { get; set; }", "MFTECmd Copied output")
    _need(program, 'foo.Map(t => t.Timestomped).Index(14).Name("SI<FN")', "MFTECmd SI<FN column")
    _need(program, "mftr.Created0x30.HasValue && mftr.Created0x10?.UtcTicks < mftr.Created0x30.Value.UtcTicks",
          "MFTECmd SI<FN comparator")
    _need(program, "mftr.Created0x10?.Millisecond == 0 || mftr.LastModified0x10?.Millisecond == 0",
          "MFTECmd uSecZeros comparator")
    _need(program, "mftr.Copied = si.ContentModifiedOn < si.CreatedOn;", "MFTECmd Copied comparator")

    ms_doc = _plain(ms_raw)
    _need(ms_doc, "USN_REASON_BASIC_INFO_CHANGE", "Microsoft USN basic-info reason")
    _need(ms_doc, "A user has either changed one or more file or directory attributes", "Microsoft USN reason meaning")
    _need(ms_doc, "or one or more time stamps", "Microsoft USN timestamp meaning")
    _need(ms_doc, "have accumulated in this file or directory journal record since the file or directory opened",
          "Microsoft USN reason accumulation")

    mfte_program = f"https://github.com/EricZimmerman/MFTECmd/blob/{MFTE_VERSION}/MFTECmd/Program.cs"
    mfte_readme = f"https://github.com/EricZimmerman/MFTECmd/blob/{MFTE_VERSION}/README.md"
    ms_url = (f"https://github.com/MicrosoftDocs/sdk-api/blob/{MS_VERSION}/"
              "sdk-api-src/content/winioctl/ns-winioctl-usn_record_v2.md")

    def fact(ident: str, claim: str, source: str, version_sha: str, source_key: str, source_sha: str,
             product_version: str | None = None) -> dict[str, str]:
        row = {
            "id": ident,
            "origin": "external",
            "claim": claim,
            "source": source,
            "source_version": version_sha,
            "source_key": source_key,
            "source_sha256": source_sha,
        }
        if product_version:
            row["product_version"] = product_version
        return row

    program_sha = MFTE_FILES["MFTECmd/Program.cs"]
    return {
        "version": 1,
        "generator": "devtools/knowledge/import_timestomp_sources.py",
        "description": "Source-checked NTFS timestamp field semantics; regenerate from the pinned snapshots.",
        "source_manifest": [
            {
                "source": f"https://github.com/EricZimmerman/MFTECmd/blob/{MFTE_VERSION}/README.md",
                "source_version": MFTE_VERSION,
                "source_key": "README.md",
                "source_sha256": MFTE_FILES["README.md"],
                "product_version": version,
            },
            {
                "source": ms_url,
                "source_version": MS_VERSION,
                "source_key": MS_FILE,
                "source_sha256": _sha256(ms_path),
            },
        ],
        "facts": [
            fact("mftecmd.si_fn",
                 "MFTECmd exports SI<FN as its Timestomped flag and sets it when the same record's $SI Created0x10 UTC ticks precede $FN Created0x30 UTC ticks.",
                 mfte_program, MFTE_VERSION, "MFTECmd/Program.cs#SI<FN", program_sha, version),
            fact("mftecmd.usec_zeros",
                 "MFTECmd sets uSecZeros when $SI Created0x10 or LastModified0x10 Millisecond == 0.",
                 mfte_program, MFTE_VERSION, "MFTECmd/Program.cs#uSecZeros", program_sha, version),
            fact("mftecmd.copied",
                 "MFTECmd sets Copied when $SI ContentModifiedOn < $SI CreatedOn.",
                 mfte_program, MFTE_VERSION, "MFTECmd/Program.cs#Copied", program_sha, version),
            fact("usn.basic_info_change",
                 "Microsoft defines USN_REASON_BASIC_INFO_CHANGE as a change to one or more file or directory attributes or timestamps; this reason does not identify which property changed.",
                 ms_url, MS_VERSION, f"{MS_FILE}#USN_REASON_BASIC_INFO_CHANGE", _sha256(ms_path)),
            fact("usn.reason_accumulates",
                 "Microsoft documents USN reason flags as accumulated changes in a file or directory journal record since that file or directory was opened.",
                 ms_url, MS_VERSION, f"{MS_FILE}#field-Reason", _sha256(ms_path)),
            fact("mftecmd.logfile_rows",
                 "MFTECmd -f $LogFile exports one row per $LogFile log record, ordered by LSN; with -m, TargetPath is the target's path in that $MFT.",
                 mfte_readme, MFTE_VERSION, "README.md#$LogFile", MFTE_FILES["README.md"], version),
            fact("mftecmd.usn_parent_when_written",
                 "With MFTECmd -f $J -m $MFT, a $J record's ParentPath is the path its parent directory had when the record was written; without -m, ParentPath is empty.",
                 mfte_readme, MFTE_VERSION, "README.md#$J paths with an $MFT (-m)", MFTE_FILES["README.md"], version),
        ],
    }


def run(check: bool = False) -> bool:
    payload = build()
    if check:
        if not OUT.is_file():
            print(f"missing generated source facts: {OUT}", file=sys.stderr)
            return False
        current = yaml.safe_load(OUT.read_text(encoding="utf-8")) or {}
        if current != payload:
            print("DRIFT: timestomp.yaml does not match its pinned snapshots", file=sys.stderr)
            return False
        print(f"timestomp source facts match ({len(payload['facts'])} facts)")
        return True
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        "# Generated by devtools/knowledge/import_timestomp_sources.py. Do not edit by hand.\n"
        + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=110),
        encoding="utf-8",
    )
    print(f"wrote {OUT} ({len(payload['facts'])} source-checked facts)")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        return 0 if run(check=args.check) else 1
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"timestomp source import failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
