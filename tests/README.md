# Tests

Three suites, all runnable as plain Python scripts. No pytest required.

| Suite | Covers | Count |
|-------|--------|------:|
| `test_knowledge.py` | YAML knowledge base loading, schema, playbook validation, discipline tools | 51 |
| `test_integration.py` | Every MCP tool module end-to-end against a temp case dir | 41 |
| `test_hunt_parser.py` | LangGraph hunt-agent output parser (happy path + fallback + adversarial) | 31 |

**Expected total: 123 passing.**

## Running

The integration suite writes a case directory under `~/.nexus/`. To
keep that out of your real home directory, redirect `USERPROFILE`:

```bash
# Windows (PowerShell)
$env:USERPROFILE = "$PWD/.testhome"
python tests/test_knowledge.py
python tests/test_integration.py
python tests/test_hunt_parser.py

# macOS / Linux
USERPROFILE="$PWD/.testhome" python tests/test_knowledge.py
USERPROFILE="$PWD/.testhome" python tests/test_integration.py
USERPROFILE="$PWD/.testhome" python tests/test_hunt_parser.py
```

Expected output:

- `=== 51 PASSED, 0 FAILED ===`
- `=== 41 PASSED, 0 FAILED ===  Total tools registered: 91` (Windows or Linux; macOS shows fewer because both platform-gated modules sit out).
- `=== 31 PASSED, 0 FAILED ===`

## Why `USERPROFILE`?

`src/nexus/config.py` resolves the data root by reading
`USERPROFILE` (Windows) or `HOME` (POSIX). The tests set
`USERPROFILE` so the same redirect works on every platform — Python's
`Path.home()` honours `USERPROFILE` on POSIX when present, and
the integration tests fall back through that path. Cleanup is
automatic via `tempfile.mkdtemp(prefix="nexus_test_")` for the case
data; only `.testhome/` persists between runs.

## What each suite covers

### `test_knowledge.py`

Loads every YAML under `src/nexus/knowledge/data/`, validates against
the loader schema in `nexus/knowledge/loader.py`, exercises the 14
discipline tools (`get_rules`, `get_playbook`, `get_anti_patterns`,
`get_corroboration_suggestions`, ...), and confirms cache reload
semantics (`clear_cache` then reload).

### `test_integration.py`

Boots `create_server()` against a tempdir-rooted case and walks the
full provenance chain:

1. `case_init` → 2. `evidence_register` → 3. tool execution
(`log_external_action` for cross-platform audit creation) → 4.
`record_finding` (strict FD-005 validation — `interpretation` and
`confidence_justification` required) → 5. `record_timeline_event` →
6. `get_findings` → 7. reporting tools (`list_profiles`,
`generate_report`).

`record_finding` must reject any artifact whose `audit_id` does not
exist in the case audit log; this is enforced as part of the suite.

### `test_hunt_parser.py`

Pure unit tests for `langgraph/hunt_parser.py`. Loads the parser by
file path (not as a package import — the local `langgraph/` directory
shadows the third-party LangGraph package name). Covers:

- Empty / None / non-string inputs.
- Malformed JSON, truncated braces, unclosed fences.
- Fenced JSON objects and arrays, mixed valid / invalid items.
- Last-5-messages scanning window.
- LangChain `SimpleNamespace` and plain-string message shapes.
- Field clamping (title ≤200 chars, observation ≤2000).
- Alias resolution (`description` → `observation`,
  `mitre_ids` → `attack_ids`, `timestamp` → `event_timestamp`).
- Adversarial inputs: 100 KB of prose, unicode in titles, unclosed
  fences.

The fallback signal (empty list → `stage_findings` stages a
placeholder) is exercised by 11 of the 31 cases.

## Migration to pytest

The suites were written as scripts because the script form is faster
to read at a glance and trivial to invoke in CI without configuration.
A pytest migration is welcome — see
[`CONTRIBUTING.md`](../CONTRIBUTING.md).
