"""Add the STAGED-evidence families to the population corpus.

The 20 NOT STAGED families come from importer paths. The remaining registry
families have STAGED evidence in MAPPING.md that never goes through an importer - it
is parsed by the tool lane. KM1 item 3 asks for a population profile over
`iter_index_docs`, so the corpus must include that parsed evidence too: those are the
documents the index receives for those families.

Each entry names the first staged location MAPPING.md records.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "Evidence-files" / "ES-Mapping" / "_population"
REPORT = CORPUS / "_staged.json"

#: family -> the staged tool output MAPPING.md records. These are already-parsed rows;
#: the population profile reads them through the same index path.
STAGED: dict[str, tuple[str, str]] = {    "evtxecmd": ("Evidence-files/ES-Mapping/evidence/evtx", "W1 EVTX (EvtxECmd rows)"),
    "hayabusa": ("Evidence-files/ES-Mapping/evidence/evtx", "W1 EVTX"),
    "chainsaw": ("Evidence-files/ES-Mapping/outputs/chainsaw", "W1 EVTX + Sigma"),
    "zircolite": ("Evidence-files/ES-Mapping/outputs/zircolite", "W1 EVTX + rules"),
    "deepbluecli": ("Evidence-files/ES-Mapping/outputs/deepbluecli", "W1 EVTX"),
    "mftecmd": ("Evidence-files/ES-Mapping/evidence/ntfs", "W2 $MFT/$J"),
    "mftecmd-i30": ("Evidence-files/ES-Mapping/evidence/ntfs-i30", "W2 $I30"),
    "logfileparser": ("Evidence-files/ES-Mapping/evidence/ntfs", "W2 $LogFile"),
    "pecmd": ("Evidence-files/ES-Mapping/evidence/prefetch", "W2 Prefetch"),
    "rbcmd": ("Evidence-files/ES-Mapping/evidence/recycle", "W2 $Recycle.Bin"),
    "recmd": ("Evidence-files/ES-Mapping/evidence/registry", "W2 Registry"),
    "sbecmd": ("Evidence-files/ES-Mapping/evidence/registry", "W2 Shellbags"),
    "lecmd": ("Evidence-files/ES-Mapping/evidence/lnk", "W2 LNK"),
    "jlecmd": ("Evidence-files/ES-Mapping/evidence/jumplists", "W2 Jump lists"),
    "wxtcmd": ("Evidence-files/ES-Mapping/evidence/activitiescache", "W2 ActivitiesCache"),
    "sqlecmd": ("Evidence-files/ES-Mapping/evidence/browser", "W2 Browser SQLite"),
    "hindsight": ("Evidence-files/ES-Mapping/evidence/browser/profiles", "W2 Browser profiles"),
    "srumecmd": ("Evidence-files/ES-Mapping/evidence/srumecmd", "W2 SRUM"),
    "vol": ("Evidence-files/ES-Mapping/evidence/vol", "W3 SIFT memory"),
    "plaso": ("Evidence-files/ES-Mapping/evidence/plaso", "W3 super timeline"),
    "capa": ("Evidence-files/ES-Mapping/outputs/capa", "W2s samples"),
    "yara": ("Evidence-files/ES-Mapping/outputs/yara", "W2s samples"),
    "densityscout": ("Evidence-files/ES-Mapping/outputs/densityscout", "W2s samples"),
    "thumbcache": ("Evidence-files/ES-Mapping/evidence/thumbcache", "W2 Thumbcache"),
    "tshark-flows": ("Evidence-files/ES-Mapping/outputs/tshark", "W4n PCAP flows"),
}

#: Characters that must not survive into a destination filename.
_UNSAFE = re.compile(r'[\\/:*?"<>|]')


def _safe(dest: Path, src: Path) -> Path:
    """A collision-free, filesystem-safe target name.

    Filenames from tool output can contain characters that break a destination
    (an ``$I30`` file name is fine, but two parents with the same basename collide),
    so the parent's name is prefixed rather than assumed unique.
    """
    base = _UNSAFE.sub("_", src.name) or "file"
    candidate = dest / base
    n = 1
    while candidate.exists():
        n += 1
        candidate = dest / f"{n}-{base}"
    return candidate


def add() -> dict:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    added: dict[str, list[str]] = {}
    absent: dict[str, str] = {}
    for family, (rel, note) in STAGED.items():
        src = REPO / rel
        if not src.exists():
            absent[family] = f"staged output not present: {rel} ({note})"
            continue
        files = [f for f in sorted(src.rglob("*")) if f.is_file()][:40]
        if not files:
            absent[family] = f"no files under {rel}"
            continue
        dest = CORPUS / family
        dest.mkdir(parents=True, exist_ok=True)
        copied = []
        for f in files:
            target = _safe(dest, f)
            try:
                shutil.copy2(f, target)
            except PermissionError:
                absent[family] = f"permission denied copying {f.name}"
                continue
            copied.append(str(target))
        if copied:
            added[family] = copied
        elif family not in absent:
            absent[family] = f"no readable files under {rel}"

    report["families"].update(added)
    report["staged_count"] = len(report["families"])
    for family, why in absent.items():
        report["absent"][family] = why
    report["absent_count"] = len(report["absent"])
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  added {len(added)} staged families, {len(absent)} absent")
    for family in sorted(added):
        print(f"    {family:16s} {len(added[family]):3d} file(s)")
    for family, why in sorted(absent.items()):
        print(f"    {family:16s} ABSENT - {why}")
    return report


if __name__ == "__main__":
    add()
