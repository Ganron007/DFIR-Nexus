#!/usr/bin/env bash
# Download portable Linux/SIFT parsers into Tools/linux/ (gitignored).
# Core SIFT binaries (vol, fls, mactime, esedbexport, plaso) come from the
# SIFT workstation / apt. This script also stages UAC + AVML for Stage 0
# live Linux collect (copied to the target at run time).
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

echo "==> UAC (tclahr/uac latest)"
UAC_JSON="$(curl -fsSL -A "$UA" https://api.github.com/repos/tclahr/uac/releases/latest)"
UAC_META="$(printf '%s' "$UAC_JSON" | python3 -c '
import json, sys
rel = json.load(sys.stdin)
assets = [a for a in rel.get("assets", []) if a["name"].endswith((".tar.gz", ".tgz", ".zip"))]
if not assets:
    raise SystemExit("no uac archive asset")
a = assets[0]
print(rel.get("tag_name", ""), a["browser_download_url"], a["name"])
')"
UAC_TAG="$(echo "$UAC_META" | awk '{print $1}')"
UAC_URL="$(echo "$UAC_META" | awk '{print $2}')"
UAC_NAME="$(echo "$UAC_META" | awk '{print $3}')"
TMPU="$(mktemp -d)"
curl -fsSL -A "$UA" -o "$TMPU/$UAC_NAME" "$UAC_URL"
mkdir -p "$TMPU/x"
case "$UAC_NAME" in
  *.zip) unzip -q "$TMPU/$UAC_NAME" -d "$TMPU/x" ;;
  *) tar -xf "$TMPU/$UAC_NAME" -C "$TMPU/x" ;;
esac
UAC_BIN="$(find "$TMPU/x" -type f -name uac | head -n1)"
if [ -z "$UAC_BIN" ]; then
  echo "uac launcher not found in archive" >&2
  exit 1
fi
rm -rf "$LIN/uac"
mkdir -p "$LIN/uac"
cp -a "$(dirname "$UAC_BIN")/." "$LIN/uac/"
chmod +x "$LIN/uac/uac"
rm -rf "$TMPU"

echo "==> AVML (microsoft/avml latest Linux x86_64)"
AV_JSON="$(curl -fsSL -A "$UA" https://api.github.com/repos/microsoft/avml/releases/latest)"
AV_META="$(printf '%s' "$AV_JSON" | python3 -c '
import json, sys
rel = json.load(sys.stdin)
assets = [a for a in rel.get("assets", []) if a["name"] == "avml"]
if not assets:
    raise SystemExit("no avml linux asset")
a = assets[0]
print(rel.get("tag_name", ""), a["browser_download_url"])
')"
AV_TAG="$(echo "$AV_META" | awk '{print $1}')"
AV_URL="$(echo "$AV_META" | awk '{print $2}')"
mkdir -p "$LIN/avml"
curl -fsSL -A "$UA" -o "$LIN/avml/avml" "$AV_URL"
chmod +x "$LIN/avml/avml"

VER="$LIN/VERSIONS.txt"
{
  echo "DFIR-Nexus Tools/linux — fetched $(date -Iseconds)"
  echo "bmc-tools	master	https://github.com/ANSSI-FR/bmc-tools"
  echo "bitsparser	master	https://github.com/fireeye/BitsParser"
  echo "kstrike	master	https://github.com/brimorlabs/KStrike"
  echo "uac	${UAC_TAG}	${UAC_URL}"
  echo "avml	${AV_TAG}	${AV_URL}"
} > "$VER"
echo "Wrote $VER"
echo "Done. Parsers under $EXT; UAC under $LIN/uac; AVML under $LIN/avml"
echo "Core SIFT tools (vol/fls/mactime/esedbexport) must already be on PATH."
echo "Then: nexus doctor"
