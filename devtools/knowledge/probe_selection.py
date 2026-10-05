"""KL2e acceptance: the reviewer's probes, and the noise case that must stay quiet."""
import sys

sys.path.insert(0, 'src')
sys.path.insert(0, 'devtools/knowledge')
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from nexus.knowledge.skills import skills_for

PROBES = [
    ('cloudtrail', 'cloud_identity_forensics'),
    ('zeek', 'network_session_analysis'),
    ('vol', 'memory_process_analysis'),
    ('amcache', 'execution_anomaly'),
]

ok = True
print('  === positive: one primary-family hit must surface the skill ===')
for fam, want in PROBES:
    got = [s.get('skill') for s in skills_for({fam})]
    good = want in got
    ok = ok and good
    print(f"    {'OK ' if good else 'BAD'} {fam:14s} -> {got}")

print()
print('  === negative: an EVTX-only case must select no USB/mobile/email skill ===')
NOISE = {'mobile_forensics', 'usb_device_analysis', 'email_phishing',
         'browser_artifact_analysis'}
for fam in ('evtx', 'security', 'sysmon', 'hayabusa', 'chainsaw'):
    got = [s.get('skill') for s in skills_for({fam})]
    bad = sorted(NOISE & set(got))
    good = not bad
    ok = ok and good
    print(f"    {'OK ' if good else 'BAD'} {fam:14s} -> {got}"
          + (f'   LEAK: {bad}' if bad else ''))

print()
print('  all probes pass:', ok)
