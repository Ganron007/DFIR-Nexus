"""IC-6 (Part 9): the positive-control corpus for the stored skill-step and analytic queries.

A stored query is proved on **real rows**: rows that real parsers produced from public or course
evidence, indexed by the same code that indexes a case (`case_index.index_case`). Nothing here is
written by hand (§3Z forbidden item 12), and nothing comes from a case the agents are evaluated on
(CASE-C5B04D31, the CADRE case, the operator's sample sets).

Sources:

* **EVTX** - `Yamato-Security/hayabusa-sample-evtx` (public; EVTX-ATTACK-SAMPLES, YamatoSecurity,
  DeepBlueCLI and EVTX-to-MITRE-Attack), parsed by EvtxECmd with the lane's own argv
  (`evtxecmd -d <dir> --csv <out>`, `tool_lane.py`), the executable resolved as the lane resolves it.
* **Host artefacts** - the ES-Mapping tool outputs (`Evidence-files/ES-Mapping/outputs/<tool>/`): the
  real runs recorded in `Evidence-files/ES-Mapping/RUNS.md` over the SANS 500 course evidence. The
  staged schema samples under `Evidence-files/03-linux`, `05-siem`, `06-cloud` and `09-email-archives`
  are synthetic and are **not** used.

The corpus is laid out as a case folder (`Evidence-files/_controls/IC6-CONTROLS/extractions/<family>/`)
so the real indexer reads it, and every file is recorded with its SHA-256 in
`devtools/knowledge/control-corpus.json`.

    python devtools/knowledge/build_control_corpus.py            # build the folder and the index
    python devtools/knowledge/build_control_corpus.py --no-index # build the folder only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

CONTROL_CASE = "IC6-CONTROLS"
CONTROL_DIR = REPO / "Evidence-files" / "_controls" / CONTROL_CASE
RECORD = Path(__file__).resolve().parent / "control-corpus.json"

SAMPLE_REPO = REPO / "Evidence-files" / "01-windows" / "evtx" / "yamato-hayabusa-sample-evtx"
SAMPLE_DIRS = ("EVTX-ATTACK-SAMPLES", "YamatoSecurity", "DeepBlueCLI", "EVTX-to-MITRE-Attack")

OUTPUTS = REPO / "Evidence-files" / "ES-Mapping" / "outputs"
#: lane family folder -> (ES-Mapping output folder, file globs). The family names are the lane's own
#: (`tool_lane.py` `extractions / "<family>"`), so the indexer assigns the family a case would get.
HOST_OUTPUTS: dict[str, tuple[str, tuple[str, ...]]] = {
    "mftecmd": ("mftecmd", ("mft.csv",)),
    "mftecmd-usn": ("mftecmd", ("usn.csv",)),
    # TA-Z (2026-10-24): MFTECmd 2026.10.2's $LogFile output on the staged $LogFile, -m $MFT (RUNS.md).
    "mftecmd-logfile": ("mftecmd", ("logfile.csv",)),
    "mftecmd-i30": ("mftecmd", ("i30-*.csv",)),
    "pecmd": ("pecmd", ("prefetch.csv",)),
    "rbcmd": ("rbcmd", ("*_RBCmd_Output.csv",)),
    "recmd": ("recmd", ("recmd-*.csv",)),
    "appcompat": ("appcompat", ("appcompat.csv",)),
    "sbecmd": ("sbecmd", ("*.csv",)),
    "lecmd": ("lecmd", ("*.csv",)),
    "jlecmd": ("jlecmd", ("*.csv",)),
    "wxtcmd": ("wxtcmd", ("*_Activity.csv",)),
    "sqlecmd": ("sqlecmd2", ("*.csv",)),
    "hindsight": ("hindsight", ("*.jsonl",)),
    "srum": ("srumecmd/i-drive", ("*.csv",)),
    "hayabusa": ("hayabusa", ("evtx-timeline.csv",)),
    # SIFT-side runs (RUNS.md W3): Volatility 3 over a course memory image, plaso over the staged EVTX,
    # nfdump over a SANS 572 capture, mactime, TSK fls; capa and YARA over sample binaries.
    "vol": ("sift-vol", ("*.json",)),
    "plaso": ("sift-plaso", ("plaso-detailed.csv",)),
    "nfdump": ("sift-nfdump", ("nfdump.csv",)),
    "mactime": ("sift-mactime", ("mactime-head.csv",)),
    "fls": ("sift-tsk", ("fls.txt",)),
    "capa": ("capa", ("*-capa.json",)),
    "yara": ("yara", ("chrome.yar.txt",)),
}

#: Real course logs for the importer families, run through the real importers (`ingest.registry`) into the
#: case's ingest store, as `nexus ingest` does. (source, path relative to Evidence-files, file glob).
IMPORTED: tuple[tuple[str, str, str], ...] = (
    ("cloudtrail", "06-cloud/504-awslogs/CloudTrail", "*.json.gz"),
    ("authlog", "03-linux/608-sift/precooked/triagedata.7z", "logs/secure"),
    ("syslog", "03-linux/608-sift/precooked/triagedata.7z", "logs/messages"),
    ("auditd", "03-linux/608-sift/precooked/triagedata.7z", "logs/audit/audit.log"),
    ("bash_history", "03-linux/608-sift/precooked/triagedata.7z", "history/root_bash_history.txt"),
    ("bash_history", "03-linux/608-sift/precooked/triagedata.7z", "history/rsydow_bash_history.txt"),
    ("wireshark", "04-network/pcap", "tcpreplay-smallFlows.pcap"),  # public (tcpreplay sample captures)
)


def _imported(staging: Path) -> list[dict]:
    """Run each real sample through its importer and append the artifacts to the ingest store."""
    import gzip

    from nexus.ingest.registry import get_registry
    from nexus.ingest.schemas import ArtifactSource
    from nexus.langgraph.timeline_merge import append_ingest_artifacts

    registry = get_registry()
    record: list[dict] = []
    for source, rel, member in IMPORTED:
        src = REPO / "Evidence-files" / rel
        if not src.exists():
            record.append({"source": source, "path": rel, "skipped": "missing"})
            continue
        inputs: list[Path] = []
        if src.suffix == ".7z":
            out = staging / source / Path(member).name
            out.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["7z", "e", "-y", f"-o{out.parent}", str(src), member.replace("/", "\\")],
                           check=True, timeout=600, stdout=subprocess.DEVNULL)
            inputs.append(out)
        elif src.is_dir() and member.endswith(".gz"):
            dest = staging / source
            dest.mkdir(parents=True, exist_ok=True)
            for gz in sorted(src.rglob(member)):
                plain = dest / gz.name[:-3]
                plain.write_bytes(gzip.decompress(gz.read_bytes()))
                inputs.append(plain)
        else:
            inputs.extend(sorted(src.glob(member)))
        for path in inputs:
            result = registry.import_path(path, source=ArtifactSource(source))
            if result.artifacts:
                append_ingest_artifacts(CONTROL_DIR, list(result.artifacts))
        record.append({"source": source, "path": rel, "member": member, "inputs": len(inputs),
                       "sha256": [_sha256(p) for p in inputs][:5]})
    return record


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_head(repo: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                             text=True, check=True, timeout=30)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _evtxecmd(out_dir: Path) -> list[dict]:
    """EvtxECmd over each sample folder, the lane's argv, one output folder per sample folder."""
    from nexus.tools.windows import _find_binary

    exe = _find_binary("evtxecmd")
    if not exe:
        raise SystemExit("EvtxECmd is not installed (Tools/windows); the corpus needs the lane's parser")
    inputs: list[dict] = []
    for name in SAMPLE_DIRS:
        src = SAMPLE_REPO / name
        if not src.is_dir():
            continue
        dest = out_dir / name
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run([exe, "-d", str(src), "--csv", str(dest)], check=True, timeout=3600,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for evtx in sorted(src.rglob("*.evtx")):
            inputs.append({"path": str(evtx.relative_to(REPO)).replace("\\", "/"), "sha256": _sha256(evtx)})
    return inputs


def build(index: bool = True) -> dict:
    if CONTROL_DIR.exists():
        shutil.rmtree(CONTROL_DIR)
    extractions = CONTROL_DIR / "extractions"
    extractions.mkdir(parents=True)
    record: dict = {
        "case": CONTROL_CASE,
        "evtx_source": {"repo": "https://github.com/Yamato-Security/hayabusa-sample-evtx",
                        "commit": _git_head(SAMPLE_REPO), "folders": list(SAMPLE_DIRS)},
        "evtx_inputs": _evtxecmd(extractions / "evtxecmd"),
        "host_source": "Evidence-files/ES-Mapping/outputs (real runs, Evidence-files/ES-Mapping/RUNS.md)",
        "files": [],
    }
    for family, (folder, globs) in HOST_OUTPUTS.items():
        src_dir = OUTPUTS / folder
        for pattern in globs:
            for src in sorted(src_dir.glob(pattern)):
                dest = extractions / family / src.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
    record["imported"] = _imported(CONTROL_DIR / "_staging")
    for path in sorted(extractions.rglob("*")):
        if path.is_file():
            record["files"].append({
                "family": path.relative_to(extractions).parts[0],
                "path": str(path.relative_to(CONTROL_DIR)).replace("\\", "/"),
                "sha256": _sha256(path),
                "bytes": path.stat().st_size,
            })
    store = CONTROL_DIR / "ingest" / "artifacts.jsonl"
    if store.is_file():  # the imported rows: every importer's output, one store
        record["files"].append({"family": "ingest", "path": "ingest/artifacts.jsonl", "sha256": _sha256(store),
                                "bytes": store.stat().st_size})
    if index:
        from nexus.langgraph.case_index import delete_index, index_case

        delete_index(CONTROL_DIR.name)  # a rebuild starts empty: no row of an earlier corpus survives
        result = index_case(CONTROL_DIR)
        record["index"] = {k: result.get(k) for k in ("index", "docs", "families", "errors") if k in result}
    RECORD.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8", newline="\n")
    return record


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--no-index", action="store_true", help="build the folder, do not index it")
    args = ap.parse_args(argv)
    record = build(index=not args.no_index)
    fams: dict[str, int] = {}
    for f in record["files"]:
        fams[f["family"]] = fams.get(f["family"], 0) + 1
    print(f"{len(record['evtx_inputs'])} EVTX inputs; {len(record['files'])} files: {fams}")
    print(json.dumps(record.get("index") or {}, indent=1)[:800])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
