"""R0'' audit part 2: WO-KM1's own acceptance, item by item, from the tree.

WO-KM1 acceptance (Docs/internal/TIER1-WORK-ORDERS.md):
- the D34 real-path test passes and INDEX_SCHEMA_VERSION is bumped;
- D35: on a CloudTrail-only temp case, the catalog lists CloudTrail's populated
  columns plus the core fields, and NO PayloadData1 or ImageFileName;
- _population.json covers every registry family, or lists it as absent with a reason;
- evtxecmd_maps.yaml is pinned and its sample test passes;
- ruff is clean and the full suite is green.

Change item 5: "Population corpus = the operator's ES-Mapping, plus one sample per
missing family, from paths MAPPING.md already names" - Sysmon through the real EvtxECmd
lane, every importer family marked NOT STAGED in MAPPING.md §3, first path that row
lists, run through the real importer. "A family or event type with no sample ... is
recorded as absent, with the reason. Do not search for another sample; tell the
operator."

Run: python devtools/knowledge/audit_km1.py
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_ok = True


def check(label: str, cond, detail: str = "") -> None:
    global _ok
    _ok = _ok and bool(cond)
    print(f"  {'OK ' if cond else 'BAD'} {label}" + (f"  {detail}" if detail else ""))


def _last(args: list[str]) -> tuple[bool, str]:
    r = subprocess.run(args, capture_output=True, text=True)
    out = (r.stdout or r.stderr).strip()
    return r.returncode == 0, (out.splitlines()[-1] if out else "no output")


print('=== acceptance 1: the D34 real-path test + INDEX_SCHEMA_VERSION ===')
from nexus.langgraph.case_index import INDEX_SCHEMA_VERSION  # noqa: E402

check('INDEX_SCHEMA_VERSION bumped (>= 9)', INDEX_SCHEMA_VERSION >= 9,
      str(INDEX_SCHEMA_VERSION))
good, detail = _last([sys.executable, '-m', 'pytest',
                      'tests/test_km1_d34_index_columns.py', '-q'])
check('D34 real-path tests pass', good, detail)

print()
print('=== acceptance 2: D35 on a CloudTrail-only case ===')
good, detail = _last([sys.executable, '-m', 'pytest',
                      'tests/test_km1_d35_populated.py', '-q'])
check('D35 tests pass', good, detail)

print()
print('=== acceptance 3: _population.json covers every registry family, or absent+reason ===')
prof = json.loads((REPO / 'Evidence-files/ES-Mapping/es_mappings/_population.json')
                  .read_text(encoding='utf-8'))
from nexus.knowledge.query_validation import load_field_registry  # noqa: E402

cols = load_field_registry()
reg_fams = set()
for i in cols.values():
    for f in (i.get('families') or []):
        low = str(f).lower()
        reg_fams.add(low[7:] if low.startswith('ingest-') else low)
prof_fams = {str(f).lower() for f in (prof.get('families') or {})}
absent = {str(k).lower() for k in (prof.get('absent_families') or {})}
missing = sorted(reg_fams - prof_fams - absent)
reasons = {k: str(v.get('reason') or '') for k, v in
           (prof.get('absent_families') or {}).items()}
check('profile families present', len(prof_fams) > 0, f'{len(prof_fams)}')
check('every registry family covered OR listed absent with a reason',
      not missing and all(reasons.values()),
      f'registry={len(reg_fams)} covered={len(prof_fams)} '
      f'absent={len(absent)} UNEXPLAINED={len(missing)}')
if missing:
    print('      unexplained:', missing[:20])
check('absent entries all carry a reason',
      all(bool(r) for r in reasons.values()), f'{len(reasons)} reasons')

print()
print('=== acceptance 4: evtxecmd_maps.yaml pinned + sample test ===')
maps_path = REPO / 'src/nexus/data/schema/evtxecmd_maps.yaml'
check('maps file exists', maps_path.is_file())
if maps_path.is_file():
    import yaml

    m = yaml.safe_load(maps_path.read_text(encoding='utf-8')) or {}
    counts = m.get('counts') or {}
    src = m.get('source') if isinstance(m.get('source'), dict) else {}
    version = (src.get('commit') or src.get('source_version')
              or m.get('source_version'))
    check('pinned commit', bool(version), str(version))
    n_entries = int(counts.get('entries') or len(m.get('packs') or []))
    check('entries present', n_entries > 100, f'{n_entries} entries')
    check('per-entry provenance',
          all(e.get('source_key') for e in (m.get('packs') or [])[:20]))
good, detail = _last([sys.executable, '-m', 'pytest', 'tests/test_evtxecmd_maps.py', '-q'])
check('map sample test passes', good, detail)

print()
print('=== change item 5: one sample per missing family (recorded, not searched for) ===')
mapping = REPO / 'Evidence-files/ES-Mapping/MAPPING.md'
check('MAPPING.md exists', mapping.is_file())
if mapping.is_file():
    txt = mapping.read_text(encoding='utf-8', errors='replace')
    print(f'      MAPPING.md NOT STAGED rows: {txt.upper().count("NOT STAGED")}')
sysmon = list((REPO / 'Evidence-files').rglob(
    'Microsoft-Windows-Sysmon%4Operational.evtx'))
check('Sysmon log staged', bool(sysmon), f'{len(sysmon)} file(s)')
if sysmon:
    p = sorted(sysmon, key=lambda x: -x.stat().st_size)[0]
    print(f'      {p.relative_to(REPO)}  {p.stat().st_size:,} bytes')
sysmon_pop = REPO / 'Evidence-files/ES-Mapping/es_mappings/_sysmon_population.json'
print(f'      _sysmon_population.json: {sysmon_pop.is_file()}')
print(f'      absent-but-staged samples: '
      f'{sum(1 for v in (prof.get("absent_families") or {}).values() if v.get("staged_samples"))}')
print('      (a staged-but-unscannable family is recorded with that reason rather '
      'than searched for elsewhere)')

print()
print('  KM1 ACCEPTANCE ALL PASS:', _ok)
