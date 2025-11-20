# Handle file I/O operations
from pathlib import Path


def ensure_parent_dir(path: str | Path) -> None:
    """Ensure that the parent directory for `path` exists."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)


def read_file_bytes(path: str | Path) -> bytes:
    """Read a file as raw bytes."""
    with open(path, "rb") as f:
        return f.read()


def write_file_bytes(path: str | Path, data: bytes) -> None:
    """Write raw bytes to a file, creating parent dirs if needed."""
    ensure_parent_dir(path)
    with open(path, "wb") as f:
        f.write(data)
