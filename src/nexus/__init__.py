from pathlib import Path

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
