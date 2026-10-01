"""Frontend style budget guard (WO-U9 / WP 14.9).

Two counts, both of which U8a drives toward zero and U9 refuses to let grow:

* **inline style objects** - ``style={{ ... }}`` in a page or component. A
  migrated page has none: layout and colour belong to CSS Modules and the token
  layer (UD1), not to a style object that no theme and no dark-mode pass can
  reach.
* **hard-coded colours** - hex literals and ``rgb``/``rgba``/``hsl`` calls.
  Colour belongs to the token layer too, which is what makes the dark theme a
  single source instead of a per-page decision.

The baseline is ``Docs/internal/frontend-style-budget.json``. This script
FAILS when any tracked file's count rises above its baseline, and when a NEW
tracked file appears with inline styles or hard-coded colours. Lowering a count
is always allowed - that is the work.

Usage:
    python scripts/frontend_style_budget.py            # verify (CI gate)
    python scripts/frontend_style_budget.py --report   # per-file table + progress
    python scripts/frontend_style_budget.py --rebaseline  # after a migration
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend" / "src"
BASELINE_PATH = ROOT / "Docs" / "internal" / "frontend-style-budget.json"

#: Directories the guard watches. Every page and component the examiner sees.
TRACKED_DIRS = ("pages", "components", "features", "ui", "shell")

# style={{ ... }} and style={cond ? {...} : {...}} - both are inline styles.
INLINE_STYLE_RE = re.compile(r"\bstyle=\{\{")
# A style attribute whose value is a bare object expression, e.g. style={obj}.
INLINE_STYLE_BARE_RE = re.compile(r"\bstyle=\{\s*(?:[A-Za-z_$][\w$]*\s*\??\s*:|\")")
HEX_COLOR_RE = re.compile(r"#[0-9a-fA-F]{3,8}\b")
FUNC_COLOR_RE = re.compile(r"\b(?:rgba?|hsla?)\(")


def _tracked_files() -> list[Path]:
    files: list[Path] = []
    for name in TRACKED_DIRS:
        directory = FRONTEND / name
        if not directory.is_dir():
            continue
        files.extend(
            path
            for path in directory.rglob("*.tsx")
            # the kit gallery is the design system showing itself; its samples
            # demonstrate token values on purpose
            if path.name not in ("KitGallery.tsx",)
            and ".test." not in path.name
            and ".stories." not in path.name
        )
    return sorted(files)


def _strip_comments_and_strings(text: str) -> str:
    """Roughly remove comments so a style example in prose is not counted."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def counts(path: Path) -> dict[str, int]:
    source = _strip_comments_and_strings(path.read_text(encoding="utf-8", errors="replace"))
    inline = len(INLINE_STYLE_RE.findall(source)) + len(INLINE_STYLE_BARE_RE.findall(source))
    colors = len(HEX_COLOR_RE.findall(source)) + len(FUNC_COLOR_RE.findall(source))
    return {"inline": inline, "colors": colors}


def measure() -> dict[str, dict[str, int]]:
    return {
        str(path.relative_to(FRONTEND)).replace("\\", "/"): counts(path)
        for path in _tracked_files()
    }


def load_baseline() -> dict[str, dict[str, int]]:
    if not BASELINE_PATH.is_file():
        return {}
    try:
        data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    files = data.get("files") if isinstance(data, dict) else None
    return files if isinstance(files, dict) else {}


def save_baseline(measured: dict[str, dict[str, int]]) -> None:
    payload = {
        "schema_version": 1,
        "note": (
            "U8a drives these toward zero; U9 fails the build if any count "
            "RISES. Regenerate with scripts/frontend_style_budget.py "
            "--rebaseline after a migration."
        ),
        "files": dict(sorted(measured.items())),
        "totals": {
            "inline": sum(v["inline"] for v in measured.values()),
            "colors": sum(v["colors"] for v in measured.values()),
        },
    }
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )


def _report(measured: dict[str, dict[str, int]], baseline: dict[str, dict[str, int]]) -> None:
    ranked = sorted(measured.items(), key=lambda kv: -kv[1]["inline"])
    print(f"{'file':52} {'inline':>7} {'colors':>7} {'was':>7}")
    print("-" * 78)
    for name, value in ranked:
        previous = baseline.get(name, {}).get("inline")
        was = "-" if previous is None else str(previous)
        print(f"{name:52} {value['inline']:7} {value['colors']:7} {was:>7}")
    clean = [n for n, v in measured.items() if v["inline"] == 0 and v["colors"] == 0]
    print("-" * 78)
    print(
        f"files with zero inline styles AND zero hard-coded colours: "
        f"{len(clean)}/{len(measured)}"
    )
    print(
        f"totals: inline={sum(v['inline'] for v in measured.values())} "
        f"colors={sum(v['colors'] for v in measured.values())}"
    )


def verify(measured: dict[str, dict[str, int]], baseline: dict[str, dict[str, int]]) -> list[str]:
    """Every way this can get worse. Lowering a count is never a failure."""
    problems: list[str] = []
    if not baseline:
        problems.append(
            f"no baseline at {BASELINE_PATH.relative_to(ROOT)} - "
            "run with --rebaseline to create one"
        )
        return problems

    for name, value in measured.items():
        previous = baseline.get(name)
        if previous is None:
            if value["inline"] or value["colors"]:
                problems.append(
                    f"NEW file with inline styles: {name} "
                    f"(inline={value['inline']}, colors={value['colors']}) "
                    "- new components ship with no inline styles"
                )
            continue
        if value["inline"] > previous.get("inline", 0):
            problems.append(
                f"{name}: inline styles rose {previous.get('inline', 0)} -> {value['inline']}"
            )
        if value["colors"] > previous.get("colors", 0):
            problems.append(
                f"{name}: hard-coded colours rose "
                f"{previous.get('colors', 0)} -> {value['colors']}"
            )

    # a file that used to be tracked and has vanished is fine (deletions are
    # progress), but a file that REGAINS styles after being cleaned is caught
    # by the per-file check above
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="print the per-file table")
    parser.add_argument(
        "--rebaseline", action="store_true", help="write today's numbers as the baseline"
    )
    args = parser.parse_args()

    measured = measure()
    baseline = load_baseline()

    if args.rebaseline:
        save_baseline(measured)
        print(f"baseline written: {BASELINE_PATH.relative_to(ROOT)}")
        _report(measured, baseline)
        return 0

    problems = verify(measured, baseline)
    if args.report:
        _report(measured, baseline)
    if problems:
        print("\nSTYLE BUDGET VIOLATIONS:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    if not args.report:
        print(
            f"style budget ok: inline="
            f"{sum(v['inline'] for v in measured.values())} "
            f"colors={sum(v['colors'] for v in measured.values())} "
            f"(none rose)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
