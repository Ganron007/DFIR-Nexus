"""Export and merge case bundles with optional encryption."""

import base64
import json
import os
import typer
from pathlib import Path

app = typer.Typer(help="Export and merge case bundles")

_HAS_CRYPTO = False
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    _HAS_CRYPTO = True
except ImportError:
    pass


def _derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a Fernet key from a passphrase using PBKDF2."""
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key, salt


def _encrypt_bundle(data: bytes, passphrase: str) -> bytes:
    """Encrypt bundle data with a passphrase-derived Fernet key."""
    key, salt = _derive_key(passphrase)
    f = Fernet(key)
    token = f.encrypt(data)
    # Prepend salt to the encrypted data for decryption
    return salt + token


def _decrypt_bundle(data: bytes, passphrase: str) -> bytes:
    """Decrypt bundle data with a passphrase-derived Fernet key."""
    salt = data[:16]
    token = data[16:]
    key, _ = _derive_key(passphrase, salt)
    f = Fernet(key)
    return f.decrypt(token)


@app.command()
def export(
    file: str = typer.Argument(..., help="Output file path"),
    case_id: str = typer.Option("", "--case", help="Case ID"),
    since: str = typer.Option("", "--since", help="Only include entries since ISO timestamp"),
    encrypt: bool = typer.Option(False, "--encrypt", "-e", help="Encrypt with passphrase"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="Encryption passphrase (prompted if not provided)"),
):
    """Export case findings + timeline as a JSON bundle.

    Use --encrypt to encrypt the bundle with a passphrase (requires cryptography package).
    """
    from nexus.cli.main import _resolve_case
    case_dir = _resolve_case(case_id)
    if not case_dir:
        return

    if encrypt and not _HAS_CRYPTO:
        typer.echo("Encryption requires cryptography. pip install cryptography", err=True)
        raise typer.Exit(1)

    if encrypt and not passphrase:
        import getpass
        passphrase = getpass.getpass("Encryption passphrase: ")
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            typer.echo("Passphrases do not match", err=True)
            raise typer.Exit(1)

    bundle = {
        "version": 1,
        "exported_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
    }
    for name in ("findings", "timeline", "todos", "iocs"):
        path = case_dir / f"{name}.json"
        if path.exists():
            data = json.loads(path.read_text())
            if since and isinstance(data, list):
                data = [d for d in data if d.get("ts", "") >= since or d.get("timestamp", "") >= since]
            bundle[name] = data

    out = Path(file)
    out.parent.mkdir(parents=True, exist_ok=True)

    raw = json.dumps(bundle, indent=2, default=str)
    if encrypt:
        encrypted = _encrypt_bundle(raw.encode(), passphrase)
        out.write_bytes(encrypted)
        typer.echo(f"Exported encrypted bundle to {out} ({len(encrypted):,} bytes)")
    else:
        out.write_text(raw)
        typer.echo(f"Exported bundle to {out} ({len(raw):,} bytes)")


@app.command()
def merge(
    file: str = typer.Argument(..., help="Bundle file to import"),
    case_id: str = typer.Option("", "--case", help="Case ID"),
    decrypt: bool = typer.Option(False, "--decrypt", "-d", help="Decrypt with passphrase"),
    passphrase: str = typer.Option("", "--passphrase", "-p", help="Decryption passphrase (prompted if not provided)"),
):
    """Merge a case bundle into local case data.

    Use --decrypt to decrypt an encrypted bundle (requires cryptography package).
    """
    from nexus.cli.main import _resolve_case
    case_dir = _resolve_case(case_id)
    if not case_dir:
        return

    if decrypt and not _HAS_CRYPTO:
        typer.echo("Decryption requires cryptography. pip install cryptography", err=True)
        raise typer.Exit(1)

    if decrypt and not passphrase:
        import getpass
        passphrase = getpass.getpass("Decryption passphrase: ")

    bundle_path = Path(file)
    if not bundle_path.exists():
        typer.echo(f"File not found: {file}", err=True)
        raise typer.Exit(1)

    try:
        if decrypt:
            raw = bundle_path.read_bytes()
            decrypted = _decrypt_bundle(raw, passphrase)
            bundle = json.loads(decrypted)
        else:
            bundle = json.loads(bundle_path.read_text())
    except Exception as e:
        typer.echo(f"Failed to read bundle: {e}", err=True)
        raise typer.Exit(1)

    merged = {}
    for name in ("findings", "timeline", "todos", "iocs"):
        incoming = bundle.get(name, [])
        if not incoming:
            continue
        path = case_dir / f"{name}.json"
        existing = json.loads(path.read_text()) if path.exists() else []
        ids = {item.get("id", item.get("todo_id", "")) for item in existing}
        new_items = [item for item in incoming if item.get("id", item.get("todo_id", "")) not in ids]
        if new_items:
            existing.extend(new_items)
            path.write_text(json.dumps(existing, indent=2, default=str))
            merged[name] = len(new_items)

    if merged:
        parts = [f"  {k}: {v} items" for k, v in merged.items()]
        typer.echo("Merged:\n" + "\n".join(parts))
    else:
        typer.echo("No new items to merge")
