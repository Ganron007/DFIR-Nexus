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

Three suites, all runnable as plain scripts. Expected total:
**51 + 41 + 31 = 123 passing**.

The integration suite writes a case directory under `~/.nexus/`. To
keep it out of your real home directory, redirect `USERPROFILE`:

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

See [`tests/README.md`](tests/README.md) for what each suite covers.

## Pull-request checklist

- [ ] All three test suites pass on your platform.
- [ ] New MCP tools include a docstring, an `examiner` field in the
      response envelope, and a `data_provenance` string literal.
- [ ] Tools accepting user-supplied paths go through the existing
      validation in `nexus/tools/sift.py` or `nexus/tools/windows.py`
      — do not add a parallel one.
- [ ] If you change the audit log, HMAC ledger, approval flow, or
      transparency log, `Docs/ARCHITECTURE.md` is updated to match,
      and `SECURITY.md` "in scope" list reviewed.
- [ ] No new top-level dependencies without justification in the PR
      description. Optional extras (`[rag]`, `[opencti]`,
      `[opensearch]`, `[triage]`) are preferred over baseline deps.
- [ ] Docs follow the single-source-of-truth rule: CLI surface lives
      in `Docs/CLI.md` only; README and `Docs/guide.md` link to it.

## Commit style

Short subject (≤72 chars), imperative mood. Body explains the *why*
when not obvious from the diff. Reference an issue when one exists.

## Code style

- Python 3.12+. Use type hints on public functions.
- Stdlib-first. Avoid pulling in a library to do something stdlib
  can do in five lines.
- Prefer Edit-tool-style narrow changes over wholesale rewrites of
  existing modules.
- No emojis in code, comments, or docs unless explicitly requested.

## License

By contributing, you agree that your contributions will be licensed
under the project's MIT license (see [`LICENSE`](LICENSE)).
