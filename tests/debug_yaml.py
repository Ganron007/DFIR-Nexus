"""Debug YAML data structures to fix loader issues."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pathlib import Path

import yaml

data_dir = Path("src/nexus/data/knowledge")

# 1. confidence.yaml
p = data_dir / "discipline" / "confidence.yaml"
d = yaml.safe_load(p.read_text())
print("=== confidence.yaml ===")
print(f"  top-level keys: {list(d.keys()) if isinstance(d, dict) else 'not a dict'}")

# 2. evidence_standards.yaml
p = data_dir / "discipline" / "evidence_standards.yaml"
d = yaml.safe_load(p.read_text())
print("\n=== evidence_standards.yaml ===")
print(f"  type: {type(d).__name__}")
if isinstance(d, dict):
    print(f"  keys: {list(d.keys())}")

# 3. corroboration.yaml
p = data_dir / "discipline" / "guidance" / "corroboration.yaml"
d = yaml.safe_load(p.read_text())
print("\n=== corroboration.yaml ===")
print(f"  type: {type(d).__name__}")
if isinstance(d, dict):
    print(f"  keys: {list(d.keys())}")

# 4. tool_interpretation.yaml
p = data_dir / "discipline" / "guidance" / "tool_interpretation.yaml"
d = yaml.safe_load(p.read_text())
print("\n=== tool_interpretation.yaml ===")
print(f"  type: {type(d).__name__}")
if isinstance(d, dict):
    print(f"  keys: {list(d.keys())}")

# 5. false_positives.yaml
p = data_dir / "discipline" / "guidance" / "false_positives.yaml"
d = yaml.safe_load(p.read_text())
print("\n=== false_positives.yaml ===")
print(f"  type: {type(d).__name__}")
if isinstance(d, dict):
    print(f"  keys: {list(d.keys())[:5]}")

# 6. Count artifacts
win = list((data_dir / "artifacts" / "windows").glob("*.yaml"))
lin = list((data_dir / "artifacts" / "linux").glob("*.yaml"))
print("\n=== Artifact counts ===")
print(f"  Windows: {len(win)} files")
print(f"  Linux:   {len(lin)} files")
print(f"  Total:   {len(win) + len(lin)} files")

# Check if any don't parse
bad = []
for f in sorted(win) + sorted(lin):
    try:
        yaml.safe_load(f.read_text())
    except Exception as e:
        bad.append((f.name, str(e)))
if bad:
    print(f"  Parse errors: {bad}")
else:
    print("  All parse OK")
