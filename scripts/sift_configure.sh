#!/usr/bin/env bash
# Configure DFIR-Nexus on SIFT. Run ON the VM.
set -euo pipefail
ROOT="${HOME}/DFIR-Nexus"
cd "$ROOT"

echo "==> examiner + env"
export NEXUS_EXAMINER="${NEXUS_EXAMINER:-sansforensics}"
if [ -f .env.sift ]; then
  # shellcheck disable=SC1091
  set -a && . .env.sift && set +a
fi
if [ -z "${NEXUS_AUDIT_SECRET:-}" ]; then
  NEXUS_AUDIT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
fi
if [ -z "${NEXUS_PORTAL_PASSWORD:-}" ]; then
  NEXUS_PORTAL_PASSWORD="lab-sift-portal"
fi
if [ -z "${NEXUS_APPROVE_PASSWORD:-}" ]; then
  NEXUS_APPROVE_PASSWORD="LabSift!Approve9"
fi
export NEXUS_EXAMINER NEXUS_AUDIT_SECRET NEXUS_PORTAL_PASSWORD NEXUS_APPROVE_PASSWORD
umask 077
# Preserve extra keys (TI, LLM) already on the VM.
extra="$(grep -E '^(NEXUS_TI_|NEXUS_LLM_|OPENCTI_)' .env.sift 2>/dev/null || true)"
cat > .env.sift <<EOF
NEXUS_EXAMINER=${NEXUS_EXAMINER}
NEXUS_AUDIT_SECRET=${NEXUS_AUDIT_SECRET}
NEXUS_PORTAL_PASSWORD=${NEXUS_PORTAL_PASSWORD}
NEXUS_APPROVE_PASSWORD=${NEXUS_APPROVE_PASSWORD}
${extra}
EOF

echo "==> pip extras (http + dfir + detection + encrypt — no rag/torch)"
.venv/bin/pip install -q -e ".[http,dfir,detection,encrypt]"
echo PIP_OK

echo "==> examiner config + approval password"
.venv/bin/python - <<'PY'
import os
from pathlib import Path
import yaml
from nexus.auth import has_password, setup_password

examiner = os.environ.get("NEXUS_EXAMINER", "sansforensics")
cfg = Path.home() / ".nexus" / "config.yaml"
cfg.parent.mkdir(parents=True, exist_ok=True)
existing = {}
if cfg.exists():
    try:
        existing = yaml.safe_load(cfg.read_text()) or {}
    except Exception:
        existing = {}
existing["examiner"] = examiner
cfg.write_text(yaml.dump(existing, default_flow_style=False))
print("examiner", examiner)
if not has_password(examiner):
    pw = os.environ["NEXUS_APPROVE_PASSWORD"]
    print(setup_password(examiner, pw))
else:
    print("password already set")
PY

echo "==> nexus init (no triage download)"
.venv/bin/nexus init "SIFT-E2E" --examiner "$NEXUS_EXAMINER" --no-baselines --port 4508 || true

echo "==> restart serve"
pkill -f "nexus serve" || true
sleep 1
set -a && . .env.sift && set +a
nohup .venv/bin/nexus serve --http --host 0.0.0.0 --port 4508 \
  > "${HOME}/nexus-serve.log" 2>&1 </dev/null &
disown || true
sleep 4
ss -lntp | grep 4508 && echo SERVE_OK || echo SERVE_FAIL
tail -n 15 "${HOME}/nexus-serve.log" || true
echo CONFIGURE_DONE
