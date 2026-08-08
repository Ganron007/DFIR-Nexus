# Security Policy

DFIR-Nexus handles evidence and produces artifacts that may inform
incident response, internal investigations, and — with appropriate
independent verification — legal proceedings. Defects that affect the
trust model are taken seriously.

## Reporting a vulnerability

**Do not open a public issue for security defects.**

Email: `security@Unallocated.in`

Please include:

- A description of the defect and its impact.
- Steps to reproduce on a clean install (`pip install dfir-nexus[all]`).
- Any relevant logs, with case data redacted.
- Your preferred attribution (or "anonymous").

A response will be sent within 5 business days. Coordinated disclosure
is preferred — we'll agree on a fix timeline and embargo before any
public discussion.

## In scope

- **Provenance bypass.** Any path that makes `record_finding` accept an
  `audit_id` that does not exist in the active case audit log.
- **Approval bypass.** Marking a finding `APPROVED` without a
  corresponding HMAC verification ledger entry, or producing a
  verified-looking ledger entry without password verification.
- **Audit-log tampering.** Any code path that can rewrite or delete
  `<case>/audit/*.jsonl` without leaving a trace in the
  hash-chained transparency log (`src/nexus/transparency.py`).
- **Password / key handling.** Defects in PBKDF2 parameters, salt
  handling, or HMAC key derivation that weaken the documented threat
  model (`src/nexus/auth.py`).
- **Privilege escalation** in the SIFT or Windows command executors —
  e.g. escapes from the denylist / allowlist gating in
  `src/nexus/tools/sift.py` or `src/nexus/tools/windows.py`.
- **Encrypted-bundle defects.** Anything in `nexus export --encrypt` /
  `nexus merge --decrypt` (PBKDF2 + Fernet) that weakens
  confidentiality or integrity.

## Out of scope

- The transparency log being readable by a local user with filesystem
  access. The log is designed for integrity, not confidentiality.
- Denial-of-service from a single LLM client overwhelming a local
  `nexus serve` process — single-tenant by design.
- Findings that an examiner approves in error. Human-in-the-loop is
  the trust boundary, not a defect.
- Third-party tool defects (Hayabusa, MFTECmd, chainsaw, etc.) —
  report those upstream.

## Threat model summary

DFIR-Nexus assumes:

- **The examiner is trusted; the LLM is not.** All findings start as
  `DRAFT` and require password-gated approval. The LLM cannot approve.
- **The host running `nexus serve` is trusted; remote MCP clients are
  treated as untrusted callers.** The audit chain captures who called
  which tool with which arguments.
- **HTTP mode is intended for local network or VPN deployment.** Expose
  publicly only behind a reverse proxy enforcing TLS and access
  control, and only after configuring `NEXUS_BEARER_TOKEN`.

See `Docs/ARCHITECTURE.md` (Security Model section) for the per-layer
control matrix.

## Dependency security

pip-audit is run against the full dependency set. Status (2026-08-08):

- **Fixed & pinned:** aiohttp >= 3.14.3 (PYSEC-2026-3545/46/47) and
  cryptography >= 50.0.0 (PYSEC-2026-3552) are pinned in the extras that
  pull them in.
- **Accepted — chromadb 1.5.9 (PYSEC-2026-311):** no fixed release exists
  upstream (1.5.9 is the latest). ChromaDB is used purely as a local
  persistent vector store for the RAG index; it does not parse untrusted
  input. Monitored for an upstream fix.
- **Accepted — setuptools 82.0.1 (PYSEC-2026-3447):** the optional
  `[opencti]` extra (pycti) pins setuptools ~= 82.0.0, blocking the 83.0.0
  fix. setuptools is build/install-time tooling, not a runtime attack
  surface here. Revisit when pycti relaxes the pin.
