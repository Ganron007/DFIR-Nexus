import os
from pathlib import Path


def _load_dotenv() -> None:
    """Load repo/CWD `.env` into os.environ. Existing vars win. File is gitignored."""
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[2] / ".env",
    ]
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.is_file():
            continue
        seen.add(resolved)
        try:
            lines = resolved.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()

_pyproject = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
if _pyproject.is_file():
    try:
        import tomllib
        with open(_pyproject, "rb") as f:
            __version__ = tomllib.load(f)["project"]["version"]
    except (OSError, KeyError):
        __version__ = "0.0.0"
else:
    __version__ = "0.0.0"
