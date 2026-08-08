"""Download pre-built triage databases from GitHub releases.

Downloads known_good.db.zst and context.db.zst from the configured
release repository (see ``_release_repo``).
"""

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

# Prebuilt triage baselines are currently published under this upstream
# GitHub repository. Operators can host their own release and override it
# via NEXUS_TRIAGE_RELEASE_REPO ("owner/repo").
_DEFAULT_RELEASE_REPO = "AppliedIR/sift-mcp"
ASSETS = ("known_good.db.zst", "context.db.zst", "checksums.sha256")
MAX_ATTEMPTS = 3
CHUNK_SIZE = 1024 * 1024


def _release_repo() -> str:
    """GitHub repo (owner/name) hosting the triage baseline release assets."""
    return os.environ.get("NEXUS_TRIAGE_RELEASE_REPO") or _DEFAULT_RELEASE_REPO


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        try:
            result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                token = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _download_asset(url: str, dest: Path) -> None:
    headers = _github_headers()
    headers["Accept"] = "application/octet-stream"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=300) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = downloaded * 100 // total
                    mb = downloaded / (1024 * 1024)
                    print(f"\r  {dest.name}: {mb:.1f} MB ({pct}%)", end="", flush=True)
        print()


def _verify_checksums(temp_dir: Path) -> bool:
    checksum_file = temp_dir / "checksums.sha256"
    if not checksum_file.is_file():
        return True
    ok = True
    for line in checksum_file.read_text().strip().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        expected = parts[0]
        fname = parts[1]
        fpath = temp_dir / fname
        if not fpath.is_file():
            continue
        actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
        if actual == expected:
            print(f"  OK: {fname}")
        else:
            print(f"  FAILED: {fname}")
            ok = False
    return ok


def _decompress_zst(src: Path, dest: Path) -> None:
    import zstandard as zstd
    dctx = zstd.ZstdDecompressor()
    with open(src, "rb") as fin, open(dest, "wb") as fout:
        dctx.copy_stream(fin, fout)


def download_databases(dest_dir: str | Path) -> bool:
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)

    print(f"Fetching release info from {_release_repo()}...")
    headers = _github_headers()
    url = f"https://api.github.com/repos/{_release_repo()}/releases?per_page=100"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            releases = json.loads(resp.read())
        matching = [r for r in releases if r["tag_name"].startswith("triage-db-")
                    and any(a["name"].endswith(".db.zst") for a in r.get("assets", []))]
        if not matching:
            print("No triage database releases found")
            return False
        release = matching[0]
    except Exception as e:
        print(f"Failed to fetch release: {e}")
        return False

    print(f"Release: {release.get('tag_name', 'unknown')}")

    for attempt in range(1, MAX_ATTEMPTS + 1):
        temp_dir = Path(tempfile.mkdtemp(prefix="triage-db-"))
        try:
            print(f"\nDownloading (attempt {attempt}/{MAX_ATTEMPTS})...")
            ok = True
            for asset_name in ASSETS:
                url = None
                for a in release.get("assets", []):
                    if a["name"] == asset_name:
                        url = a["url"]
                        break
                if not url:
                    print(f"  Asset not found: {asset_name}")
                    ok = False
                    continue
                try:
                    _download_asset(url, temp_dir / asset_name)
                except Exception as e:
                    print(f"  Download failed: {e}")
                    ok = False

            if not ok:
                if attempt < MAX_ATTEMPTS:
                    time.sleep(attempt * 5)
                    continue
                return False

            print("\nVerifying checksums...")
            if not _verify_checksums(temp_dir):
                if attempt < MAX_ATTEMPTS:
                    time.sleep(attempt * 5)
                    continue
                return False

            print("\nDecompressing...")
            for zst_name in ("known_good.db.zst", "context.db.zst"):
                zst_path = temp_dir / zst_name
                db_name = zst_name.removesuffix(".zst")
                db_path = dest / db_name
                print(f"  {db_name}...", end="", flush=True)
                _decompress_zst(zst_path, db_path)
                print(f" {db_path.stat().st_size / (1024*1024):.1f} MB")

            print("\nVerifying databases...")
            verified = True
            for db_name, table, min_rows in [
                ("known_good.db", "baseline_files", 1000000),
                ("context.db", "lolbins", 100),
                ("context.db", "vulnerable_drivers", 100),
            ]:
                db_path = dest / db_name
                if not db_path.is_file():
                    print(f"  {db_name}: missing")
                    verified = False
                    continue
                try:
                    conn = sqlite3.connect(str(db_path))
                    count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    conn.close()
                    print(f"  {db_name} ({table}): {count:,} rows")
                    if count < min_rows:
                        print(f"    Expected {min_rows:,}+ rows")
                        verified = False
                except Exception as e:
                    print(f"  {db_name}: error - {e}")
                    verified = False

            if verified:
                print("\nDatabases installed successfully.")
                return True
            print("\nVerification failed.")
            return False

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    return False
