"""R0'' completion audit: each WO's acceptance, against the current state."""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, 'src')
sys.path.insert(0, 'devtools/knowledge')
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = Path('.')
ok = True


def check(label, cond, detail=''):
    global ok
    ok = ok and bool(cond)
    print(f"  {'OK ' if cond else 'BAD'} {label}" + (f"  {detail}" if detail else ''))


print('=== KR2c item 3: the field-population matrix ===')
fp = json.loads((REPO / 'devtools/knowledge/field-population.json').read_text(encoding='utf-8'))
check('matrix exists', bool(fp.get('rows') is not None), f"{len(fp.get('rows') or [])} rows")
check('every row carries a cause', all(r.get('cause') for r in fp['rows'] if r['status'] == 'cannot_match'))
check('families measured', len(fp.get('family_docs') or []) >= 25, f"{len(fp.get('family_docs') or [])}")

print()
print('=== KR2c item 4: the 8 defects, and procedures ===')
import yaml

K = REPO / 'src/nexus/data/knowledge/skills'
STEPS = {
    'execution_chain': 'email_phishing',
    'asset_and_zone_inventory': 'ics_ot_forensics',
    'byte_asymmetry': 'network_session_analysis',
    'process_memory_check': 'linux_compromise',
    'plc_hmi_evidence': 'ics_ot_forensics',
    'capa_capabilities': 'malware_analysis_triage',
    'sam_reg_export': 'credential_access_sam_ntds',
    'persistence_mechanisms': 'linux_compromise',
}
for step, fname in STEPS.items():
    d = yaml.safe_load((K / f'{fname}.yaml').read_text(encoding='utf-8')) or {}
    s = next((x for x in d.get('steps') or [] if x.get('name') == step), None)
    if s is None:
        check(f'{step} present', False)
        continue
    blob = json.dumps(s.get('es') or {})
    checks = []
    if step == 'execution_chain':
        # The R0' fix: the interpreters are the CHILD, the launchers the PARENT.
        # `ParentImage` is the step's own pivot, so interpreters are asserted in the
        # parent column and the launcher (explorer.exe) in a file-name column.
        checks.append(('interpreters in the parent column',
                       'fields.parent_process' in blob))
        checks.append(('launcher in a file-name column',
                       'fields.file_path' in blob))
        checks.append(('explorer.exe present', 'explorer.exe' in blob))
        checks.append(('launchers not in an IP column', 'dest_ip' not in blob))
    elif step == 'asset_and_zone_inventory':
        checks.append(('no dest_ip', 'dest_ip' not in blob))
    elif step == 'byte_asymmetry':
        checks.append(('no source_ip', 'source_ip' not in blob))
        checks.append(('no imploded ip column', 'dest_ip' not in blob))
    elif step == 'process_memory_check':
        checks.append(('no process_name for plugin names', 'fields.process_name' not in blob))
    elif step == 'plc_hmi_evidence':
        checks.append(('no host', '"fields.host' not in blob))
    elif step == 'capa_capabilities':
        checks.append(('no <rule> placeholder', '<rule>' not in blob))
    elif step == 'sam_reg_export':
        checks.append(('the hive is in the term', 'reg save *\\\\' in blob
                       or 'reg save *hklm' in blob.lower()))
    elif step == 'persistence_mechanisms':
        checks.append(('ExecStart not a path', 'fields.file_path' in blob))
        checks.append(('ExecStart in text', 'text.wc' in blob))
    for name, good in checks:
        check(f'{step}: {name}', good)

print()
print('=== the 4 procedure steps ===')
PROCS = {'hash_on_acquire', 'triage_first', 'encryption_check', 'backward_analysis'}
for p in sorted(K.glob('*.yaml')):
    d = yaml.safe_load(p.read_text(encoding='utf-8')) or {}
    for s in d.get('steps') or []:
        if isinstance(s, dict) and s.get('name') in PROCS:
            check(f"{s['name']}: kind=procedure, no es, has reason and drops",
                  s.get('kind') == 'procedure' and 'es' not in s
                  and bool(s.get('procedure_reason')) and bool(s.get('es_dropped')))

print()
print('=== KL2d: the Sigma pack ===')
sp = json.loads((REPO / 'devtools/knowledge/sigma-population.json').read_text(encoding='utf-8'))
counts = sp.get('counts') or {}
by_cause = {}
for r in sp.get('cannot_match') or []:
    by_cause[r.get('cause')] = by_cause.get(r.get('cause'), 0) + 1
check('no rule with no_lane_has_it', by_cause.get('no_lane_has_it', 0) == 0,
      f"corpus_absent={by_cause.get('corpus_absent', 0)}")
check(' fewer than the reviewer count', counts.get('cannot_match', 999) < 966,
      f"{counts.get('cannot_match')} of 966")

print()
print('=== the converters agree with the files ===')
for tool, label in (('devtools/knowledge/convert_to_es.py', 'skills'),
                    ('devtools/knowledge/sigma_import.py', 'sigma')):
    r = subprocess.run([sys.executable, tool, '--check'], capture_output=True, text=True)
    check(f'{label} --check', r.returncode == 0, r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr.strip()[-90:])

print()
print('=== KL2e: the reviewer probes ===')
from nexus.knowledge.skills import skills_for

for fam, want in (('cloudtrail', 'cloud_identity_forensics'),
                  ('zeek', 'network_session_analysis'),
                  ('vol', 'memory_process_analysis'),
                  ('amcache', 'execution_anomaly')):
    got = {str(s.get('skill')) for s in skills_for({fam})}
    check(f'{fam}-only -> {want}', want in got, str(sorted(got)))
for fam in ('evtx', 'security', 'sysmon', 'hayabusa', 'chainsaw'):
    got = {str(s.get('skill')) for s in skills_for({fam})}
    check(f'{fam}-only has no noise', not (got & {'mobile_forensics', 'usb_device_intrusion', 'email_phishing'}), str(sorted(got)))
cov = json.loads((REPO / 'devtools/knowledge/family-coverage.json').read_text(encoding='utf-8'))
check('coverage is a selection test', bool(cov.get('importer_families')))
check('every no-skill family has a reason',
      all(r.get('reason') for r in cov['importer_families'] if r['status'] == 'no_skill'))

print()
print('  ALL ACCEPTANCE CHECKS PASS:', ok)
