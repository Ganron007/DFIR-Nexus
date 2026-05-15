#!/usr/bin/env bash
#
# setup-linux.sh — one-command DFIR-Nexus install for Linux (SIFT, REMnux,
# any Debian/RHEL/Arch derivative).
#
# Does:
#   1. Verifies Python 3.12+
#   2. Creates a venv at .venv/ (skips if it exists)
#   3. pip install -e .[all]
#   4. Prompts for examiner name + approval password
#   5. Runs `nexus init` (connectivity check, baseline status, MCP config snippet)
#
# Use --no-venv to install into the active interpreter without creating a venv.
# Use --skip-init to stop after the install (handy for CI).

set -euo pipefail

NO_VENV=false
SKIP_INIT=false
SKIP_PASSWORD=false

for arg in "$@"; do
    case "$arg" in
        --no-venv) NO_VENV=true ;;
        --skip-init) SKIP_INIT=true ;;
        --skip-password) SKIP_PASSWORD=true ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
    esac
done

REPO_ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$REPO_ROOT"

echo "==> DFIR-Nexus setup (Linux)"
echo "    Repo: $REPO_ROOT"

# 1. Python version
PY_BIN="${PYTHON:-python3}"
if ! command -v "$PY_BIN" >/dev/null 2>&1; then
    echo "ERROR: python3 not found. Install Python 3.12+ first."
    exit 1
fi
PY_VER=$("$PY_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [ "$($PY_BIN -c 'import sys; print(1 if sys.version_info >= (3,12) else 0)')" != "1" ]; then
    echo "ERROR: Python $PY_VER detected; DFIR-Nexus needs >= 3.12."
    exit 1
fi
echo "    Python $PY_VER OK"

# 2. Venv
if ! $NO_VENV; then
    if [ -d .venv ]; then
        echo "    venv already exists at .venv/ (reusing)"
    else
        echo "==> Creating venv at .venv/"
        "$PY_BIN" -m venv .venv
    fi
    # shellcheck disable=SC1091
    . .venv/bin/activate
fi

# 3. Install
echo "==> pip install -e .[all]"
python -m pip install --upgrade pip
python -m pip install -e ".[all]"

# 4. Examiner + password
if ! $SKIP_PASSWORD; then
    if [ -z "${NEXUS_EXAMINER:-}" ]; then
        read -rp "    Examiner name (Enter to use OS username '$(whoami)'): " EXAMINER_INPUT
        if [ -n "$EXAMINER_INPUT" ]; then
            nexus config --examiner "$EXAMINER_INPUT"
        fi
    fi
    echo ""
    echo "==> Set the approval password now (required for nexus approve)."
    echo "    You can skip with Ctrl-C and run 'nexus config --setup-password' later."
    nexus config --setup-password || true
fi

# 5. nexus init
if ! $SKIP_INIT; then
    echo ""
    nexus init
fi

echo ""
echo "==> Done. Start the server with:"
echo "      nexus serve                       # stdio mode (zero config)"
echo "      nexus serve --http --port 4508    # HTTP mode + Examiner Portal"
