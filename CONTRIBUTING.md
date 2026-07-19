# Contributing to DFIR-Nexus

Bug reports, doc fixes, and well-scoped features are welcome.

## Before you start

- For non-trivial changes, open an issue first so we can align on
  approach. This avoids wasted PR work.
- For security defects, do **not** open an issue — see
  [SECURITY.md](SECURITY.md).
- Read [`Docs/ARCHITECTURE.md`](Docs/ARCHITECTURE.md) before touching
  the provenance chain, audit log, HMAC ledger, or transparency log.
  Mistakes there silently break the trust model.

## Development setup

```bash
git clone https://github.com/Unallocated/DFIR-Nexus.git
cd DFIR-Nexus
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -e .[all]
```

## Running tests

**Total: 489 checks (155 pytest + 219 script + 115 functional audit).**

### Pytest suite (155 tests)
```bash
pytest
```

### Script-based tests (219 tests)
```bash
python tests/test_knowledge.py         # 51 tests — knowledge loader
python tests/test_hunt_parser.py       # 31 tests — hunt output parser
python tests/test_integration.py       # 41 tests — MCP tool E2E
python tests/test_detection.py         # 21 tests — Sigma rule detection
python tests/test_ti.py                # 26 tests — threat intel providers
python tests/test_ingest.py            # 14 tests — ingest importers
python tests/test_push.py              # 17 tests — push server
python tests/test_portal.py            # 18 tests — portal middleware
```

### Functional audit (115 checks)
```bash
python tests/functional_audit.py       # End-to-end wiring verification
```

The integration suite writes a case directory under `~/.nexus/`. To
keep it out of your real home directory, redirect `USERPROFILE`:
```bash
# Windows (PowerShell)
$env:USERPROFILE = "$PWD/.testhome"
python tests/test_integration.py

# macOS / Linux
USERPROFILE="$PWD/.testhome" python tests/test_integration.py
```

## Pull-request checklist

- [ ] All test suites pass on your platform.
- [ ] `python -m compileall src/nexus` is clean.
- [ ] No remaining `dfir_nexus` references in `src/nexus/`.
- [ ] New MCP tools include a docstring and `audit_id` recording.
- [ ] Tools accepting user-supplied paths go through path validation
      in `nexus/utils/paths.py`.
- [ ] If you change the audit log, HMAC ledger, approval flow, or
      transparency log, `Docs/ARCHITECTURE.md` is updated to match,
      and `SECURITY.md` "in scope" list reviewed.
- [ ] No new top-level dependencies without justification in the PR
      description. Optional extras (`[rag]`, `[opencti]`,
      `[opensearch]`, `[triage]`) are preferred over baseline deps.
- [ ] Docs follow the single-source rule: CLI surface in
      `Docs/CLI.md`; workflow in `Docs/guide.md`.

## Module structure

New modules should follow the existing pattern:
- `src/nexus/<module>/__init__.py` — public API exports
- `src/nexus/<module>/schemas.py` — dataclasses and enums (if needed)
- Tests in `tests/test_<module>.py`

## Commit style

Short subject (<=72 chars), imperative mood. Body explains the *why*
when not obvious from the diff. Reference an issue when one exists.

## Code style

- Python 3.12+. Use type hints on public functions.
- Stdlib-first. Avoid pulling in a library to do something stdlib
  can do in five lines.
- No emojis in code, comments, or docs unless explicitly requested.

## License

By contributing, you agree that your contributions will be licensed
under the project's MIT license (see [`LICENSE`](LICENSE)).
