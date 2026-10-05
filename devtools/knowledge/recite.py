"""WO-KL2b (design time): re-cite every behavioural analytic to a verified source.

The R0 review found that the CAR pack mapped ids to the wrong analytics, and that
"all 35 CAR-cited analytics inherit these mappings". Rebuilding the pack from the
pinned MITRE snapshot shows it is worse than that: **15 of the 35 cite ids that do
not exist in CAR at all** (CAR-2016-04-012, CAR-2014-11-001, CAR-2016-04-008,
CAR-2016-04-009, CAR-2016-04-014, CAR-2016-04-015, ...). The previous pack was
fabricated, so every one of those citations was an invented fact.

WO-KR2b rule 3 says each analytic cites one of:
  * a **real CAR id** whose logic it expresses;
  * a **Sigma rule id** from the pinned SigmaHQ snapshot;
  * an **ATT&CK detection strategy / analytic id** from `attack_registry.yaml`;
  * `origin: authored`, with its ATT&CK technique and a rationale.

This resolves **strictly**: a CAR analytic is cited only when the analytic's own
primary technique is in the CAR analytic's coverage **and** at least two significant
words of the CAR title appear in the analytic's name/rationale. A near-miss is not
a citation - an over-eager match would rebuild the very defect we are fixing, so
anything that does not clear the bar becomes `origin: authored`, which is honest.

Usage::

    python devtools/knowledge/recite.py            # show the proposal
    python devtools/knowledge/recite.py --write    # apply it
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
ANALYTICS = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "behavioral_analytics.yaml"
CAR = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "car_analytics.yaml"

#: Words too common to be evidence of a match.
_STOP = {
    "the", "a", "an", "and", "or", "of", "for", "to", "in", "on", "with", "from",
    "process", "creation", "event", "events", "detection", "detect", "monitor",
    "monitoring", "windows", "via", "using", "use", "command", "line", "log",
    "logs", "activity", "behaviour", "behavior", "suspicious", "file", "files",
}


def _words(text: str) -> set[str]:
    out: set[str] = set()
    for word in re.findall(r"[a-z0-9]{3,}", str(text or "").lower()):
        if word not in _STOP:
            out.add(word)
    return out


def load() -> tuple[dict[str, Any], dict[str, Any]]:
    analytics = yaml.safe_load(ANALYTICS.read_text(encoding="utf-8")) or {}
    car = yaml.safe_load(CAR.read_text(encoding="utf-8")) or {}
    return analytics, car


def resolve(analytic: dict[str, Any], car_packs: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The CAR analytic this one expresses, or None when none clears the bar."""
    own_tech = {str(t) for t in (analytic.get("techniques") or [])}
    if not own_tech:
        return None
    own_words = _words(str(analytic.get("name") or "") + " " + str(analytic.get("rationale") or ""))
    best: tuple[int, dict[str, Any]] | None = None
    for pack in car_packs:
        car_tech = {str(t) for t in (pack.get("techniques") or [])}
        if not (own_tech & car_tech):
            continue
        # A sub-technique only counts on exact overlap, so T1053 does not ride on
        # a CAR analytic that only covers T1053.005.
        shared = _words(pack.get("name") or "")
        score = len(shared & own_words)
        if score >= 2 and (best is None or score > best[0]):
            best = (score, pack)
    return best[1] if best else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    analytics, car = load()
    car_packs = car.get("packs") or []
    car_version = str(car.get("source_version") or "")

    cited = authored = 0
    rows: list[tuple[str, str, str]] = []
    for pack in analytics.get("packs") or []:
        match = resolve(pack, car_packs)
        if match:
            pack["citation"] = {
                "type": "car",
                "id": match["analytic"],
                "ref": f"https://car.mitre.org/analytics/{match['analytic']}/",
                "title": match["name"],
            }
            cited += 1
            rows.append((pack["id"], match["analytic"], match["name"]))
        else:
            techniques = ", ".join(str(t) for t in (pack.get("techniques") or []))
            pack["citation"] = {
                "type": "authored",
                "id": f"authored:{pack['id']}",
                "ref": "",
                "rationale": (f"Authored for this product: expresses {techniques or 'the technique'} "
                              f"in this pack's logic. Not derived from an external source."),
            }
            authored += 1
            rows.append((pack["id"], "authored", techniques))

    print(f"  CAR snapshot @{car_version[:10]}  ({len(car_packs)} analytics)")
    print(f"  cited a real CAR analytic: {cited}")
    print(f"  origin: authored          : {authored}")
    print()
    for ident, source, detail in rows:
        print(f"  {ident:34s} -> {source:16s} {detail[:56]}")

    if args.write:
        header = [line for line in ANALYTICS.read_text(encoding="utf-8").splitlines()
                  if line.startswith("#")]
        body = yaml.safe_dump(analytics, sort_keys=False, default_flow_style=False,
                              allow_unicode=True, width=1000)
        text = "\n".join(header) + "\n" + body if header else body
        ANALYTICS.write_text(text, encoding="utf-8", newline="\n")
        print(f"\n  written: {ANALYTICS.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
