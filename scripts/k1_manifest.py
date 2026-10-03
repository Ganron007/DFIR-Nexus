#!/usr/bin/env python
"""Build a K1 evidence stage + operator manifest (WO-K1).

K1 needs two kinds of case, and they measure different things:

* **AIT-LDS (kind ``aitlds``)** — an enterprise testbed whose ground truth is
  **per-line labels** naming the attack step. Used for technique/entity
  precision, recall and F1.
* **Clean-host baselines (kind ``flat``)** — Nextron `evtx-baseline`, real
  "goodware" event logs. Every file is declared ``role: benign`` and nothing is
  expected, so this is where the **false-positive rate** is measured.

    python scripts/k1_manifest.py --kind aitlds --testbed DIR --stage OUT
    python scripts/k1_manifest.py --kind flat   --testbed DIR --stage OUT

It writes, under ``OUT``::

    evidence/            the curated files, laid out by host (this is what gets registered)
    manifest.json        sha256 -> {role, techniques, labels, host, path}
    mapping.json         the attack-step -> ATT&CK table this run used

**Three rules that are easy to get wrong, and are enforced here:**

1. **The labelling directories are never staged.** `labels/` *is* the answer.
2. **The attacker's own host is never staged.** In AIT-LDS, `gather/attacker_0/`
   holds `attacks.log` (the schedule) and the attacker's tooling output — it is
   the operator's side, not the enterprise's.
3. **"Unlabelled" is not "benign".** AIT-LDS labels only what its rules could
   label; the big unlabelled `suricata/eve.json` files carry real attack
   traffic and are *not* declared clean. So they are left **unlabelled** — no
   expectation either way — and the false-positive rate is measured on the
   genuinely clean baseline instead. Declaring them benign would score a
   correct detection as a false positive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# The attack-step -> ATT&CK mapping.
#
# AIT-LDS labels events with *attack-step names*, not technique IDs, so this
# table is the translation and therefore a judgement call. It is written to
# mapping.json with the manifest so a reviewer can see exactly what ran, and it
# is data - change it here, not in code that consumes it.
# ---------------------------------------------------------------------------
STEP_TECHNIQUES: dict[str, list[str]] = {
    # -- reconnaissance ------------------------------------------------------
    "traceroute": ["T1595"],
    "traceroute_internet": ["T1595"],
    "dns_brute_force": ["T1018"],
    "dns_scan": ["T1018"],
    "host_discover_dmz": ["T1018"],
    "host_discover_local": ["T1018"],
    "network_scan": ["T1018"],
    "recon_networks_finish": ["T1018"],
    "recon_host_finish": ["T1082"],
    "service_scan": ["T1046"],
    "dirb": ["T1595.002"],
    "dirb_scan": ["T1595.002"],
    "wpscan": ["T1595.002"],
    # -- initial access ------------------------------------------------------
    "vpn_connect": ["T1133"],
    "attacker_vpn": ["T1133"],
    "foothold": ["T1190"],
    "upload_rce_shell": ["T1505.003"],
    "webshell_upload": ["T1505.003"],
    "webshell_cmd": ["T1505.003"],
    "attacker_http": ["T1071.001"],
    # -- execution / discovery ----------------------------------------------
    "reverse_shell_listen": ["T1059"],
    "open_reverse_shell": ["T1059"],
    "wait_reverse_shell": ["T1059"],
    "open_pty": ["T1059"],
    "check_whoami": ["T1033"],
    "check_id": ["T1033"],
    "check_user_id": ["T1033"],
    "check_who": ["T1033"],
    "attacker_change_user": ["T1078"],
    "login_user": ["T1078"],
    "read_passwd": ["T1003.008"],
    "read_shadow": ["T1003.008"],
    "list_shadow": ["T1003.008"],
    "read_group": ["T1069.001"],
    "read_fstab": ["T1082"],
    "read_resolv": ["T1082"],
    "check_uname_r": ["T1082"],
    "check_uname_a": ["T1082"],
    "check_uname_ar": ["T1082"],
    "check_release": ["T1082"],
    "check_meminfo": ["T1082"],
    "check_cpuinfo": ["T1082"],
    "check_uptime": ["T1082"],
    "check_date": ["T1082"],
    "check_df": ["T1082"],
    "check_ps_a": ["T1057"],
    "check_ps_aux": ["T1057"],
    "check_netstat_l": ["T1049"],
    "check_netstat_t": ["T1049"],
    "check_netstat_nat": ["T1049"],
    "check_ifconfig": ["T1016"],
    "check_network_config": ["T1016"],
    "list_home": ["T1083"],
    "list_web_dir": ["T1083"],
    "list_www": ["T1083"],
    "check_wp_config": ["T1083"],
    "dump_wp_users": ["T1087.001"],
    "check_last": ["T1087.001"],
    "check_sudo": ["T1548.003"],
    # -- privilege escalation ------------------------------------------------
    "escalate": ["T1548.003"],
    "escalated_command": ["T1548.003"],
    "escalated_sudo_command": ["T1548.003"],
    "escalated_sudo_session": ["T1548.003"],
    "decide_crack_method": ["T1110.002"],
    "crack_passwords": ["T1110.002"],
    "crack_wphash": ["T1110.002"],
    # -- exfiltration --------------------------------------------------------
    "dnsteal": ["T1048", "T1071.004"],
    "dnsteal-received": ["T1048", "T1071.004"],
    "dnsteal-dropped": ["T1048", "T1071.004"],
    "dnsteal_stop": ["T1048", "T1071.004"],
    "exfiltration-service": ["T1048"],
    "clear": ["T1070.003"],
}

#: Labels that name a *role* rather than an action; they carry no technique.
ROLE_ONLY_LABELS = frozenset({"attacker", "victim", "benign"})

#: Never staged into a case: the ground truth, and the attacker's own host.
TRUTH_DIRS = frozenset({"labels", "label", "ground-truth", "groundtruth", "answer_keys"})
TRUTH_FILES = frozenset({"attacks.log", "stage_events.json"})
EXCLUDED_HOSTS = frozenset({"attacker_0"})

#: Noise that dominates the testbed without carrying security signal. Kept out
#: of a *stage* (not out of the dataset) so a case stays tractable; the
#: labelled evidence is always staged regardless of size.
NOISE_PATTERNS = ("suricata/stats.log", "logs/suricata/stats.log")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_labels(testbed: Path) -> dict[str, set[str]]:
    """``relative path under gather/ -> labels`` from the per-line label files."""
    labels_dir = testbed / "labels"
    out: dict[str, set[str]] = {}
    if not labels_dir.is_dir():
        return out
    for path in sorted(labels_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(labels_dir)
        found: set[str] = set()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            for label in record.get("labels") or []:
                found.add(str(label))
        if found:
            out[str(rel).replace("\\", "/")] = found
    return out


def techniques_for_steps(steps: set[str]) -> tuple[set[str], list[str]]:
    """``(techniques, unmapped steps)`` — an unmapped step is reported, not dropped."""
    techniques: set[str] = set()
    unmapped: list[str] = []
    for step in sorted(steps):
        if step in ROLE_ONLY_LABELS:
            continue
        mapped = STEP_TECHNIQUES.get(step)
        if not mapped:
            unmapped.append(step)
            continue
        techniques.update(mapped)
    return techniques, unmapped


#: `T1003-Credential dumping` / `T1059.001-PowerShell` / `T1110.xxx-Brut force`.
_TECHNIQUE_DIR = re.compile(r"^(T\d{4})(?:\.(\d{3}))?(?:[^0-9]|$)")


def technique_from_dir(name: str) -> str:
    """The ATT&CK technique a sample directory names, or "".

    The Yamato `EVTX-to-MITRE-Attack` tree labels each sample by DIRECTORY:
    ``TA0006-Credential Access/T1003-Credential dumping/*.evtx``. The tactic is
    the parent, the technique the leaf. A sub-technique is kept only when it is
    numeric - ``T1110.xxx-Brut force`` is the technique T1110, because `.xxx` is
    prose in the ID slot, not a sub-technique.
    """
    match = _TECHNIQUE_DIR.match(str(name).strip())
    if not match:
        return ""
    base, sub = match.group(1), match.group(2)
    return f"{base}.{sub}" if sub else base


def build_evtx_mitre(testbed: Path, stage: Path, group: str) -> dict:
    """A case from the Yamato EVTX-to-MITRE tree, one tactic group at a time.

    *testbed* is the ``EVTX-to-MITRE-Attack`` directory. *group* selects a tactic
    folder (``TA0006-Credential Access``) or "" for every tactic. Evidence is
    ``role: attack`` with the technique taken from its own directory, so the
    ground truth is a property of the pack rather than a hand-written claim.
    """
    if not testbed.is_dir():
        raise SystemExit(f"no EVTX-to-MITRE-Attack tree at {testbed}")
    roots = [testbed] if not group else [testbed / group]
    for root in roots:
        if not root.is_dir():
            available = sorted(p.name for p in testbed.iterdir() if p.is_dir())
            raise SystemExit(f"no group {group!r}; available: {', '.join(available)}")

    evidence_dir = stage / "evidence"
    entries: list[dict] = []
    counts = Counter()
    total = 0
    unmapped_dirs: list[str] = []

    for root in roots:
        for src in sorted(root.rglob("*")):
            if not src.is_file() or src.suffix.lower() != ".evtx":
                continue
            # The technique is the sample's own directory, under the tactic.
            technique = technique_from_dir(src.parent.name)
            if not technique:
                unmapped_dirs.append(str(src.parent.relative_to(testbed)))
            rel = str(src.relative_to(testbed)).replace("\\", "/")
            stage_file(src, evidence_dir / rel)
            counts["staged"] += 1
            total += src.stat().st_size
            entries.append({
                "sha256": sha256_file(src),
                "role": "attack" if technique else "unlabelled",
                "host": root.name,
                "path": rel,
                "bytes": src.stat().st_size,
                "labels": [src.parent.name],
                "techniques": [technique] if technique else [],
                "label_basis": "content",
            })

    return {
        "kind": "evtx-mitre",
        "testbed": str(testbed),
        "group": group,
        "entries": entries,
        "counts": dict(counts),
        "unmapped_labels": sorted(set(unmapped_dirs)),
        "staged_bytes": total,
        "labelled_hosts": [r.name for r in roots],
    }


def stage_file(src: Path, dest: Path) -> str:
    """Hardlink when possible (same volume, no copy cost), else copy.

    Returns 'link' or 'copy' so the staging is auditable.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return "existing"
    try:
        os.link(src, dest)
        return "link"
    except (OSError, NotImplementedError, AttributeError):
        shutil.copy2(src, dest)
        return "copy"


def build_aitlds(testbed: Path, stage: Path, max_file_mb: float, all_hosts: bool) -> dict:
    labels = read_labels(testbed)
    labelled_hosts = {rel.split("/")[0] for rel in labels}
    gather = testbed / "gather"
    if not gather.is_dir():
        raise SystemExit(f"no gather/ under {testbed}")

    # Unmapped steps and expectations with no staged evidence must be computed
    # from ALL labels read, not from what happened to be staged. Otherwise a
    # label naming a host that is not in gather/ - or one whose evidence was
    # skipped - disappears without a word, and recall reads better than it is.
    every_step = {step for steps in labels.values() for step in steps}

    evidence_dir = stage / "evidence"
    entries: list[dict] = []
    unmapped: set[str] = set()
    counts = Counter()
    total = 0
    staged_rel: set[str] = set()
    label_paths = set(labels)

    for host in sorted(p for p in gather.iterdir() if p.is_dir()):
        if host.name in EXCLUDED_HOSTS:
            counts["skipped_attacker_host"] += 1
            continue
        if not all_hosts and host.name not in labelled_hosts:
            counts["skipped_unlabelled_host"] += 1
            continue

        for src in sorted(f for f in host.rglob("*") if f.is_file()):
            rel_host = str(src.relative_to(gather)).replace("\\", "/")
            parts = src.relative_to(host).parts
            # Logs only: `configs/` are system configuration dumps, not activity.
            if "logs" not in parts:
                counts["skipped_not_a_log"] += 1
                continue
            if any(pattern in rel_host for pattern in NOISE_PATTERNS):
                counts["skipped_noise"] += 1
                continue

            rel_label = str(Path(host.name) / src.relative_to(host)).replace("\\", "/")
            steps = labels.get(rel_label)
            size_mb = src.stat().st_size / 1e6
            # A labelled file is always evidence. Unlabelled files are bounded,
            # so a 400 MB unlabelled capture cannot dominate the case.
            if steps is None and size_mb > max_file_mb:
                counts["skipped_over_cap"] += 1
                continue

            dest = evidence_dir / rel_host
            how = stage_file(src, dest)
            counts[f"staged_{how}"] += 1
            total += src.stat().st_size
            staged_rel.add(rel_label)

            techniques, bad = techniques_for_steps(steps or set())
            unmapped.update(bad)
            role = "attack" if techniques else "unlabelled"
            if steps is not None and not techniques:
                role = "labelled-no-technique"
            # How the label was derived matters. AIT-LDS labels a file by
            # matching its content (a service log), but `monitoring/` is an
            # aggregated metric stream where labels are applied by TIME WINDOW -
            # a CPU graph cannot evidence password cracking. Recorded per entry
            # so a reviewer can exclude the window-derived labels from a score
            # instead of reading a miss as the product's fault.
            basis = "window" if rel_host.startswith("monitoring/") else "content"
            entry = {
                "sha256": sha256_file(src),
                "role": role,
                "host": host.name,
                "path": rel_host,
                "bytes": src.stat().st_size,
                "labels": sorted(steps) if steps else [],
                "techniques": sorted(techniques),
                "label_basis": basis,
            }
            entries.append(entry)
            if role == "attack":
                counts["attack_files"] += 1
            else:
                counts["unlabelled_files"] += 1

    # Labels whose evidence was never staged: an expectation silently dropped.
    dropped = sorted(label_paths - staged_rel)
    # Unmapped steps anywhere in the ground truth, staged or not.
    unmapped.update(techniques_for_steps(every_step)[1])

    return {
        "kind": "aitlds",
        "testbed": str(testbed),
        "entries": entries,
        "counts": dict(counts),
        "unmapped_labels": sorted(unmapped),
        "labels_without_evidence": dropped,
        "staged_bytes": total,
        "labelled_hosts": sorted(labelled_hosts),
    }


def build_flat(testbed: Path, stage: Path) -> dict:
    """Every file declared benign. For clean-host baselines (Nextron)."""
    evidence_dir = stage / "evidence"
    entries: list[dict] = []
    counts = Counter()
    total = 0
    for src in sorted(f for f in testbed.rglob("*") if f.is_file()):
        rel = str(src.relative_to(testbed)).replace("\\", "/")
        stage_file(src, evidence_dir / rel)
        counts["staged"] += 1
        total += src.stat().st_size
        entries.append({
            "sha256": sha256_file(src),
            "role": "benign",
            "host": "baseline",
            "path": rel,
            "bytes": src.stat().st_size,
            "labels": [],
            "techniques": [],
            "label_basis": "content",
        })
    return {
        "kind": "flat",
        "testbed": str(testbed),
        "entries": entries,
        "counts": dict(counts),
        "unmapped_labels": [],
        "staged_bytes": total,
        "labelled_hosts": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("aitlds", "flat", "evtx-mitre"), required=True)
    parser.add_argument("--testbed", required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--group", default="",
                        help="evtx-mitre: one tactic folder, e.g. 'TA0006-Credential Access'")
    parser.add_argument("--max-file-mb", type=float, default=50.0,
                        help="cap for UNLABELLED files (labelled evidence is never capped)")
    parser.add_argument("--all-hosts", action="store_true",
                        help="aitlds: stage unlabelled hosts too (much larger)")
    args = parser.parse_args(argv)

    testbed, stage = Path(args.testbed), Path(args.stage)
    if not testbed.is_dir():
        print(f"no testbed at {testbed}", file=sys.stderr)
        return 2
    if stage.exists() and any(stage.iterdir()):
        print(f"stage {stage} is not empty - remove it or choose another", file=sys.stderr)
        return 2

    if args.kind == "aitlds":
        report = build_aitlds(testbed, stage, args.max_file_mb, args.all_hosts)
    elif args.kind == "evtx-mitre":
        report = build_evtx_mitre(testbed, stage, args.group)
    else:
        report = build_flat(testbed, stage)

    manifest = {
        "version": 1,
        "kind": report["kind"],
        "testbed": report["testbed"],
        **({"group": report["group"]} if report.get("group") else {}),
        # `from_manifest` reads this key; `role` per entry decides benign.
        "entries": report["entries"],
        "counts": report["counts"],
        "staged_bytes": report["staged_bytes"],
        "staged_mb": round(report["staged_bytes"] / 1e6, 1),
        "labels_without_evidence": report.get("labels_without_evidence", []),
        "caveats": [
            "Entries with label_basis='window' are labelled by time window over an "
            "aggregated metric stream (AIT-LDS `monitoring/`), not by matching the "
            "file's content. A technique they name may not be inferable from that "
            "file at all - exclude them from a score before reading a miss as a "
            "product fault.",
            "Unlabelled files are NOT benign: AIT-LDS labels only what its rules "
            "could label, and its network captures carry attack traffic. The "
            "false-positive rate is measured on the clean-host baseline instead.",
            "The attack-step -> ATT&CK mapping in mapping.json is a judgement call.",
        ],
    }
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (stage / "mapping.json").write_text(json.dumps({
        "note": "attack-step -> ATT&CK. A judgement call; review before trusting a score.",
        "step_techniques": STEP_TECHNIQUES,
        "role_only_labels": sorted(ROLE_ONLY_LABELS),
        "unmapped_labels_seen": report["unmapped_labels"],
    }, indent=2, sort_keys=True), encoding="utf-8")

    print(f"kind={report['kind']}  testbed={testbed}")
    print(f"staged {len(report['entries'])} file(s), {manifest['staged_mb']} MB -> {stage}")
    for key, value in sorted(report["counts"].items()):
        print(f"  {key}: {value}")
    if report["labelled_hosts"]:
        print(f"  labelled hosts: {', '.join(report['labelled_hosts'])}")
    if report["unmapped_labels"]:
        print(f"  WARNING unmapped attack-step labels: {', '.join(report['unmapped_labels'])}")
    if report.get("labels_without_evidence"):
        print("  WARNING labels with no staged evidence "
              f"(expectation dropped): {', '.join(report['labels_without_evidence'])}")
    techniques = sorted({t for e in report["entries"] for t in e["techniques"]})
    attack_files = sum(1 for e in report["entries"] if e["role"] == "attack")
    print(f"  expected techniques: {len(techniques)} across {attack_files} attack file(s)")
    print(f"  {techniques}")
    print(f"wrote {stage/'manifest.json'} and {stage/'mapping.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
