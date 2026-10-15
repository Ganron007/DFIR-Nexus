"""Generate src/nexus/data/schema/hayabusa_fields.yaml from Hayabusa's own rules repository (D232).

A Hayabusa timeline row names its channel by Hayabusa's abbreviation (`Sec`, `Defender`), writes the
event's fields it shows as `Label: value` under a rule's details template, and rewrites some values
into words (`LogonType 0` as `0 - SYSTEM`). Read as written, no row carried its event's channel or
data, so no pinned category or event-data map applied to the rows findings cite most. Everything
needed to read them back is Hayabusa's own data, in the hayabusa-rules repository the lane installs:

- config/channel_abbreviations.txt  channel -> abbreviation
- config/default_details.txt        (provider, event id) -> details template, for rules with none
- config/eventkey_alias.txt         template alias -> event field (`Event.EventData.<Name>`)
- config/data_mapping/*.yaml        (channel, event id) -> field -> original value -> rewritten value
- the rules' own `details:`          rule id -> details template (Hayabusa's own rules)

Everything is read from git at the pinned commit, so the table follows that commit and nothing else.

    python devtools/knowledge/import_hayabusa_fields.py           # regenerate
    python devtools/knowledge/import_hayabusa_fields.py --check   # verify the committed table

The rules are released under the Detection Rule License 1.1 (hayabusa-rules README).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
RULES = REPO / "Tools" / "windows" / "hayabusa" / "rules"
OUT = REPO / "src" / "nexus" / "data" / "schema" / "hayabusa_fields.yaml"
#: The hayabusa-rules commit the lane's Hayabusa 4.1.0 runs (Tools/windows/hayabusa/rules, 2026-10-08).
COMMIT = "04af3d207cae784183e0e5e82c1132ee866bbd67"
HAYABUSA_VERSION = "4.1.0"
_ALIAS = re.compile(r"%([^%\s]+)%")
_rules = [RULES]


def _git(*args: str) -> bytes:
    done = subprocess.run(["git", "-C", str(_rules[0]), *args], capture_output=True, check=False)
    if done.returncode != 0:
        raise SystemExit(f"git {' '.join(args)}: {done.stderr.decode(errors='replace').strip()}")
    return done.stdout


def _read(path: str) -> str:
    return _git("show", f"{COMMIT}:{path}").decode("utf-8-sig")


def _aliases() -> dict[str, str]:
    """Template alias -> the event field it reads. A name the table does not hold is read by Hayabusa as
    the event data field of that name, and is kept as it is."""
    out: dict[str, str] = {}
    for line in _read("config/eventkey_alias.txt").splitlines()[1:]:
        alias, _, path = line.partition(",")
        if alias.strip() and path.strip():
            out[alias.strip()] = path.strip()
    return out


def _field(alias: str, aliases: dict[str, str]) -> str | None:
    """The EventData field an alias names, or None for a System or UserData path."""
    path = aliases.get(alias, f"Event.EventData.{alias}")
    if path.startswith("Event.EventData."):
        return path[len("Event.EventData."):]
    return None


def _template(details: str, aliases: dict[str, str]) -> list[list[str]]:
    """`Label: %Alias% ¦ ...` -> [[label, field], ...] for the pieces whose value is one alias exactly.

    A piece that joins several fields (`%Domain%\\%User%`) is left out: its parts cannot be told apart.
    """
    pairs: list[list[str]] = []
    for piece in str(details).split("¦"):
        label, sep, value = piece.strip().partition(":")
        value = value.strip()
        match = _ALIAS.fullmatch(value)
        if sep and label.strip() and match:
            field = _field(match.group(1), aliases)
            if field:
                pairs.append([label.strip(), field])
    return pairs


def build() -> dict:
    aliases = _aliases()
    channels: dict[str, str] = {}
    for line in _read("config/channel_abbreviations.txt").splitlines()[1:]:
        channel, _, abbreviation = line.rpartition(",")
        if channel.strip() and abbreviation.strip():
            channels[abbreviation.strip()] = channel.strip()

    default_details: dict[str, list[list[str]]] = {}
    for line in _read("config/default_details.txt").splitlines()[1:]:
        parts = [p.strip() for p in line.split(",", 2)]
        if len(parts) == 3 and parts[1].isdigit():
            pairs = _template(parts[2], aliases)
            if pairs:
                default_details[f"{parts[0]}|{parts[1]}"] = pairs

    rule_details: dict[str, list[list[str]]] = {}
    listed = _git("grep", "-l", "-E", "^details:", COMMIT, "--", "*.yml").decode().splitlines()
    for ref in sorted(listed):
        path = ref.split(":", 1)[1]
        rule = yaml.safe_load(_read(path)) or {}
        pairs = _template(rule.get("details") or "", aliases)
        if rule.get("id") and pairs:
            rule_details[str(rule["id"])] = pairs

    rewrites: dict[str, dict[str, dict[str, str]]] = {}
    for path in sorted(_git("ls-tree", "--name-only", COMMIT, "config/data_mapping/").decode().split()):
        doc = yaml.safe_load(_read(path)) or {}
        key = f"{doc.get('Channel')}|{doc.get('EventID')}"
        for field, items in (doc.get("RewriteFieldData") or {}).items():
            back = rewrites.setdefault(key, {}).setdefault(str(field), {})
            for item in items or []:
                for original, written in (item or {}).items():
                    back[str(written)] = str(original)

    return {
        "source": {
            "tool": "hayabusa", "version": HAYABUSA_VERSION,
            "repository": "https://github.com/Yamato-Security/hayabusa-rules", "commit": COMMIT,
            "licence": "Detection Rule License 1.1",
        },
        "channels": dict(sorted(channels.items())),
        "default_details": dict(sorted(default_details.items())),
        "rule_details": dict(sorted(rule_details.items())),
        "rewrites": dict(sorted(rewrites.items())),
    }


def render(doc: dict) -> str:
    head = ("# GENERATED by devtools/knowledge/import_hayabusa_fields.py from hayabusa-rules at the commit below.\n"
            "# Do not edit by hand. How a Hayabusa timeline row's channel, details and values read back as the\n"
            "# event's own (D232).\n")
    return head + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify the committed table instead of writing it")
    parser.add_argument("--rules", type=Path, default=RULES, help="the hayabusa-rules checkout (default: the lane's)")
    args = parser.parse_args(argv)
    _rules[0] = args.rules
    if not (args.rules / ".git").exists():
        print(f"the hayabusa-rules checkout is not at {args.rules}", file=sys.stderr)
        return 2
    text = render(build())
    if args.check:
        same = OUT.is_file() and OUT.read_text(encoding="utf-8") == text
        print("hayabusa_fields.yaml matches hayabusa-rules " + COMMIT[:7] if same else "hayabusa_fields.yaml differs")
        return 0 if same else 1
    OUT.write_text(text, encoding="utf-8", newline="\n")
    doc = yaml.safe_load(text)
    print(f"wrote {OUT.name}: {len(doc['channels'])} channels, {len(doc['default_details'])} default and "
          f"{len(doc['rule_details'])} rule templates, {len(doc['rewrites'])} rewritten events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
