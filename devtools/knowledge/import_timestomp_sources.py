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

MFTE_VERSION = "b76bfecdf8bafd94c41f0799388a67c703510f67"
MS_VERSION = "656e9656bfaef34dd29cd7ee9e1146aec17e924c"
MFTE_FILES = {
    "README.md": "19c6f36f0e324c6fc881d35067b2d6fa9796f9b342b7731d63c8607691888051",
    "MFTECmd/MFTRecordOut.cs": "d9f6826d1695fcc30d1fa45a4c943f880c14f687e9f02b9ebe0145e926fd6bcd",
    "MFTECmd/Program.cs": "f1679b4070e4cf7b0279d8ca6611ed12c07d3e0e92521ea4ebcb818ea62dd1c6",
    "MFTECmd/MFTECmd.csproj": "ddefe3ad3289472c0f35937149dcd92dfb847db7e23d92b1beb2706921f74d63",
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
    if version != "2026.5.0":
        raise ValueError(f"pinned MFTECmd source version changed: expected 2026.5.0, got {version!r}")
    _need(readme, "MFT parser for NTFS file systems", "MFTECmd README identity")
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
