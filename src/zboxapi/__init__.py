from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("zboxapi")
except PackageNotFoundError:  # pragma: no cover - running from a bare checkout
    __version__ = "0.0.0"
