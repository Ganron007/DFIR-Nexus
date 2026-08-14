#!/usr/bin/env bash
# Download portable Linux/SIFT parsers into Tools/linux/ (gitignored).
# Core SIFT binaries (vol, fls, mactime, esedbexport, plaso) come from the
# SIFT workstation / apt — this script only vendors the same portable
# Python parsers the Windows lane uses (bmc-tools, BitsParser, KStrike).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
LIN="$ROOT/linux"
EXT="$LIN/extra"
mkdir -p "$EXT"
UA="dfir-nexus-fetch"

echo "==> bmc-tools.py (ANSSI)"
curl -fsSL -A "$UA" \
  -o "$EXT/bmc-tools.py" \
  "https://raw.githubusercontent.com/ANSSI-FR/bmc-tools/master/bmc-tools.py"
chmod +x "$EXT/bmc-tools.py"

echo "==> BitsParser (FireEye tree + vendored ANSSI bits/construct)"
TMP="$(mktemp -d)"
curl -fsSL -A "$UA" -o "$TMP/BitsParser.zip" \
  "https://github.com/fireeye/BitsParser/archive/refs/heads/master.zip"
rm -rf "$EXT/BitsParser"
unzip -q "$TMP/BitsParser.zip" -d "$TMP"
mv "$TMP/BitsParser-master" "$EXT/BitsParser"
rm -f "$EXT/BitsParser.py"
# bits_parser pins construct 2.8.12 (breaks host regipy) — vendor into the tree.
VENV="$TMP/bits-venv"
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet bits_parser
for pkg in bits construct; do
  rm -rf "$EXT/BitsParser/$pkg"
  cp -a "$VENV/lib/python"*"/site-packages/$pkg" "$EXT/BitsParser/$pkg"
done
rm -rf "$TMP"

echo "==> KStrike.py (BriMor Labs)"
curl -fsSL -A "$UA" \
  -o "$EXT/KStrike.py" \
  "https://raw.githubusercontent.com/brimorlabs/KStrike/master/KStrike.py"
chmod +x "$EXT/KStrike.py"

echo "==> pip: libesedb-python (KStrike / pyesedb) — not bits_parser (vendored)"
python3 -m pip install --user --upgrade libesedb-python

VER="$LIN/VERSIONS.txt"
{
  echo "DFIR-Nexus Tools/linux — fetched $(date -Iseconds)"
  echo "bmc-tools	master	https://github.com/ANSSI-FR/bmc-tools"
  echo "bitsparser	master	https://github.com/fireeye/BitsParser"
  echo "kstrike	master	https://github.com/brimorlabs/KStrike"
} > "$VER"
echo "Wrote $VER"
echo "Done. Parsers under $EXT"
echo "Core SIFT tools (vol/fls/mactime/esedbexport) must already be on PATH."
echo "Then: nexus doctor"
