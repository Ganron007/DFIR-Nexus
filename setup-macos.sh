#!/usr/bin/env bash
#
# setup-macos.sh — one-command DFIR-Nexus install for macOS.
#
# Behaviour identical to setup-linux.sh — kept as a separate file so the
# README can point macOS users at a familiarly-named script. Picks
# `python3.12` (or any python3 >= 3.12) from PATH; if Homebrew is
# installed and the python alias is missing, hints at `brew install python@3.12`.

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
            sed -n '2,15p' "$0"
            exit 0
            ;;
    esac
done

REPO_ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$REPO_ROOT"

echo "==> DFIR-Nexus setup (macOS)"
echo "    Repo: $REPO_ROOT"

# Pick the best Python on PATH
PY_BIN=""
for cand in python3.12 python3.13 python3; do
    if command -v "$cand" >/dev/null 2>&1; then
        PY_BIN="$cand"
        break
    fi
done

if [ -z "$PY_BIN" ]; then
    echo "ERROR: no python3 on PATH."
    if command -v brew >/dev/null 2>&1; then
        echo "  Install with: brew install python@3.12"
    else
        echo "  Install Homebrew (https://brew.sh) then: brew install python@3.12"
    fi
    exit 1
fi

PY_VER=$("$PY_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [ "$($PY_BIN -c 'import sys; print(1 if sys.version_info >= (3,12) else 0)')" != "1" ]; then
    echo "ERROR: Python $PY_VER detected via $PY_BIN; DFIR-Nexus needs >= 3.12."
    echo "  Try: brew install python@3.12"
    exit 1
fi
echo "    Python $PY_VER OK ($PY_BIN)"

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

echo "==> pip install -e .[all]"
python -m pip install --upgrade pip
python -m pip install -e ".[all]"

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

if ! $SKIP_INIT; then
    echo ""
    nexus init
fi

echo ""
echo "==> Done. Start the server with:"
echo "      nexus serve                       # stdio mode (zero config)"
echo "      nexus serve --http --port 4508    # HTTP mode + Examiner Portal"
