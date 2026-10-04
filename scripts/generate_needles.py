#!/usr/bin/env python
"""WO-K4 part 3 — generate needle packs from the synced structured sources.

The hand-curated needle packs are keyword digests with a pack-level `source` and
no date, and `evtx_attack_samples.yaml` was built from an outdated sample corpus
that no longer reflects what the rule engines produce. This script rebuilds a
pack from the **structured** sources we already sync, and — the work order's
requirement — records **a source and a date per term**, so a term can be aged out
or re-verified instead of living forever with no provenance.

Sources, and what each contributes:

| Pack | Shape | Terms taken |
|---|---|---|
| `lolbas.yaml` | `packs[]: binary, mitre[], needles[]` | the abuse arguments (`-urlcache`, ...) |
| `atomic_red_team.yaml` | `packs[]: technique, tests[]` | the artifacts and commands per technique |
| `cisa_kev.yaml` | `cves[]: cve, added_to_kev, needles[]` | the needles, dated by the CVE's own KEV date |
| `ossem_events.yaml` | `events{}: event_id, fields[]` | event ids and field names |
| `behavioral_analytics.yaml` | `packs[]: techniques, dsl` | the `eventid` values its analytics filter on |

    python scripts/generate_needles.py            # write the pack
    python scripts/generate_needles.py --check    # fail if it is stale

The date is the source file's **last git commit date** where the pack itself
carries none. That is a real provenance date and it is reproducible; a wall-clock
timestamp would make every run differ and the check meaningless.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parent.parent
NEEDLES = REPO / "src" / "nexus" / "data" / "knowledge" / "needles"
OUT = NEEDLES / "generated_needles.yaml"

#: `eventid:1102`, `eventid:in:(7045,4697)` -> the ids.
_EVENTID_RE = re.compile(r"eventid:(?:in:\(([^)]*)\)|([0-9]+))", re.IGNORECASE)


def _load(name: str) -> dict[str, Any]:
    path = NEEDLES / name
    if not path.is_file():
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        print(f"  ! {name} unreadable: {exc}", file=sys.stderr)
        return {}


def source_date(name: str) -> str:
    """The source file's last commit date (YYYY-MM-DD), or an empty string.

    Deliberately not the file's mtime: copying the tree rewrites mtimes, so
    mtime is not a provenance date.
    """
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%cs", "--", str(NEEDLES / name)],
            cwd=str(REPO), capture_output=True, text=True, timeout=20, check=False,
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


#: A needle must be a term that would actually appear in parsed output - never a
#: snippet or prose sentence (WO-K4). Measured on the first generated pack: 17 of
#: 44 `command` terms were whole command lines, including a 100-character
#: PowerShell one-liner assigning to a variable. Those are test commands, not
#: needles: nothing searches for `$token = [System.Security.Principal...`.
MAX_NEEDLE_CHARS = 60
MAX_NEEDLE_WORDS = 6
#: Shell syntax that does not survive into a parsed field. A bare `$` is NOT
#: here: `ADMIN$` and `ipc$` are real share names that do appear in parsed
#: output, and an over-broad filter would have dropped them as prose (measured -
#: the first version did exactly that). Only a token that *starts* with `$` is a
#: variable assignment.
_SHELL_SYNTAX = ("|", "&&", "||", ">>", "= \"", "=[", "(`", "')")


def is_needle_shaped(term: str) -> bool:
    """Whether a term is a plausible needle rather than a snippet of a command.

    Rejects the shapes that are not search terms: a command line long enough that
    nothing would match it verbatim, one carrying shell syntax (a pipe, a loop),
    and one containing a variable reference (`$token`) - but not `ADMIN$`, which
    is a share name.
    """
    text = str(term or "").strip()
    if not text:
        return False
    if len(text) > MAX_NEEDLE_CHARS or len(text.split()) > MAX_NEEDLE_WORDS:
        return False
    if any(marker in text for marker in _SHELL_SYNTAX):
        return False
    # A variable reference, quoted or not: `"$token` and `$true` are prose.
    # `ADMIN$`/`ipc$` are share names and must survive.
    return not any(token.lstrip("\"'").startswith("$") for token in text.split())


def needles_from_command(command: str) -> list[str]:
    """The needles inside a test command, instead of the whole command.

    A command is a good source - it names the tool, the flag and the target - but
    only its distinctive pieces are search terms. Long commands are reduced to
    their flags and their binary/API names, which is what a parsed field would
    actually contain.
    """
    text = str(command or "").strip()
    if not text:
        return []
    if is_needle_shaped(text):
        return [text]

    out: list[str] = []
    for token in text.replace('"', " ").replace("'", " ").split():
        token = token.strip(",;(){}[]")
        if not token:
            continue
        low = token.lower()
        if (
            (token.startswith("-") and len(token) > 2)
            or low.endswith(".exe")
            or low.endswith(".dll")
        ):
            out.append(token)
        elif "-" in token and token[0].isalpha() and not token.startswith("\\\\"):
            # a PowerShell cmdlet (Set-MpPreference) or a Windows API name
            out.append(token)
        if len(out) >= 3:
            break
    return [t for t in out if is_needle_shaped(t)]


def _needle_terms() -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    terms: list[dict[str, Any]] = []
    sources: dict[str, dict[str, str]] = {}

    def add(term: str, kind: str, subject: str, source: str, date: str,
            techniques: list[str] | None = None) -> None:
        term = str(term or "").strip()
        if not term:
            return
        terms.append({
            "term": term,
            "kind": kind,
            "subject": subject,
            "source": source,
            "date": date,
            "techniques": [t for t in (techniques or []) if t],
        })

    lolbas = _load("lolbas.yaml")
    lurl = str(lolbas.get("source") or "")
    ldate = source_date("lolbas.yaml")
    sources["lolbas"] = {"url": lurl, "date": ldate}
    for pack in lolbas.get("packs") or []:
        if not isinstance(pack, dict):
            continue
        name = str(pack.get("name") or pack.get("binary") or "")
        mitre = [str(m) for m in (pack.get("mitre") or [])]
        for needle in pack.get("needles") or []:
            add(needle, "lolbin_arg", name, lurl, ldate, mitre)

    atomic = _load("atomic_red_team.yaml")
    aurl = str(atomic.get("source") or "")
    adate = source_date("atomic_red_team.yaml")
    sources["atomic_red_team"] = {"url": aurl, "date": adate}
    for pack in atomic.get("packs") or []:
        if not isinstance(pack, dict):
            continue
        technique = str(pack.get("technique") or "")
        for test in pack.get("tests") or []:
            if not isinstance(test, dict):
                continue
            subject = f"{technique} {test.get('name') or ''}".strip()
            for artifact in test.get("artifacts") or []:
                add(artifact, "artifact", subject, aurl, adate, [technique])
            command = str(test.get("command") or "").strip()
            # WO-K4: a command is a source, not a needle - only its distinctive
            # pieces are search terms.
            for needle in needles_from_command(command):
                add(needle, "command", subject, aurl, adate, [technique])

    kev = _load("cisa_kev.yaml")
    kurl = str(kev.get("source") or "")
    for cve in kev.get("cves") or []:
        if not isinstance(cve, dict):
            continue
        # The CVE carries its own date - the best provenance available here.
        date = str(cve.get("added_to_kev") or source_date("cisa_kev.yaml"))
        subject = f"{cve.get('cve') or ''} {cve.get('name') or ''}".strip()
        for needle in cve.get("needles") or []:
            add(needle, "kev_needle", subject, kurl, date)

    ossem = _load("ossem_events.yaml")
    ourl = str(ossem.get("source") or "")
    odate = source_date("ossem_events.yaml")
    sources["ossem_events"] = {"url": ourl, "date": odate}
    for event, body in (ossem.get("events") or {}).items():
        if not isinstance(body, dict):
            continue
        subject = f"{event} (event {body.get('event_id')})"
        add(str(body.get("event_id") or ""), "event_id", subject, ourl, odate)
        for field in body.get("fields") or []:
            if isinstance(field, dict):
                add(str(field.get("name") or ""), "event_field", subject, ourl, odate)

    behavioural = _load("behavioral_analytics.yaml")
    burl = str(behavioural.get("source") or "")
    bdate = source_date("behavioral_analytics.yaml")
    sources["behavioral_analytics"] = {"url": burl, "date": bdate}
    for pack in behavioural.get("packs") or []:
        if not isinstance(pack, dict):
            continue
        techniques = [str(t) for t in (pack.get("techniques") or [])]
        for group, ids in _EVENTID_RE.findall(str(pack.get("dsl") or "")):
            for eid in [i for i in (group or "").split(",") if i] or [ids]:
                if eid:
                    add(eid, "event_id", str(pack.get("id") or ""), burl, bdate, techniques)

    # Deduplicate on (term, kind, source); keep first occurrence (source order is
    # deliberate: the more specific pack comes first).
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for item in terms:
        key = (item["term"].lower(), item["kind"], item["source"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    unique.sort(key=lambda t: (t["kind"], t["term"].lower()))
    return unique, sources


def build_payload() -> dict[str, Any]:
    terms, sources = _needle_terms()
    generated = datetime.now(UTC).replace(microsecond=0).isoformat()
    return {
        "version": 1,
        "generated": generated,
        # Volatile on purpose is NOT acceptable for a --check, so the checked
        # field set excludes `generated` (see _comparable).
        "generator": "scripts/generate_needles.py",
        "note": (
            "Generated from the synced structured sources. Every term carries its "
            "source and the source's date, so a term can be aged out. Do not edit "
            "by hand - re-run the generator. Supersedes evtx_attack_samples.yaml, "
            "which was built from an outdated sample corpus."
        ),
        "sources": sources,
        # Per-technique packs, shaped like the retired evtx_attack_samples packs so
        # the consumers keep working: name / technique / events[].fields{}.
        "packs": build_technique_packs(terms),
        "terms": terms,
    }


def build_technique_packs(terms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group the generated terms by technique, in the shape app.py consumes."""
    by_technique: dict[str, list[dict[str, Any]]] = {}
    for item in terms:
        for technique in item.get("techniques") or []:
            by_technique.setdefault(technique, []).append(item)

    packs: list[dict[str, Any]] = []
    for technique in sorted(by_technique):
        items = by_technique[technique]
        packs.append({
            "name": f"Generated needles for {technique}",
            "technique": technique,
            "source": sorted({str(i["source"]) for i in items})[:3],
            "date": sorted({str(i["date"]) for i in items if i["date"]})[-1:] or [""],
            "events": [
                {"fields": {"Term": i["term"], "Kind": i["kind"]}}
                for i in items[:40]
            ],
        })
    return packs


def _comparable(payload: dict[str, Any]) -> dict[str, Any]:
    """The payload without the volatile generated-at stamp."""
    return {k: v for k, v in payload.items() if k != "generated"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if the pack on disk is stale (CI/pre-commit)")
    args = parser.parse_args(argv)

    payload = build_payload()
    if not payload["terms"]:
        print("refusing to write: no terms were generated", file=sys.stderr)
        return 2

    if args.check:
        if not OUT.is_file():
            print(f"missing: {OUT.relative_to(REPO)}", file=sys.stderr)
            return 1
        try:
            on_disk = yaml.safe_load(OUT.read_text(encoding="utf-8")) or {}
        except Exception as exc:  # noqa: BLE001
            print(f"unreadable: {exc}", file=sys.stderr)
            return 1
        if _comparable(on_disk) != _comparable(payload):
            print(
                "generated_needles.yaml is stale - re-run scripts/generate_needles.py",
                file=sys.stderr,
            )
            return 1
        print(f"up to date: {len(payload['terms'])} terms")
        return 0

    header = (
        "# GENERATED by scripts/generate_needles.py - do not edit by hand.\n"
        "# Re-run the generator; `--check` fails when this file is stale.\n"
    )
    OUT.write_text(
        header + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True,
                                width=100),
        encoding="utf-8",
    )
    kinds: dict[str, int] = {}
    for item in payload["terms"]:
        kinds[item["kind"]] = kinds.get(item["kind"], 0) + 1
    print(f"wrote {OUT.relative_to(REPO)}: {len(payload['terms'])} terms "
          f"across {len(payload['packs'])} technique packs")
    for kind, count in sorted(kinds.items()):
        print(f"  {kind}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
