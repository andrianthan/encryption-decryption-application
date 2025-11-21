from pathlib import Path


def validate_key_size(bits: int) -> None:
    """
    Ensure AES key size is valid: 128, 192, or 256 bits.
    Raises ValueError if invalid.
    """
    if bits not in (128, 192, 256):
        raise ValueError(f"Invalid AES key size: {bits}")


def validate_file_exists(path: str | Path) -> None:
    """
    Ensure the given file path exists and is a file.
    Raises FileNotFoundError if not.
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"File does not exist: {p}")


def validate_algorithm_name(name: str, supported: list[str]) -> None:
    """
    Ensure the algorithm name is in the supported list.
    Raises ValueError if not.
    """
    if name not in supported:
        raise ValueError(f"Unsupported algorithm: {name}")


def validate_positive_int(value: int, field_name: str) -> None:
    """
    Ensure an integer is positive.
    Raises ValueError if invalid.
    """
    if not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer, got {value!r}")