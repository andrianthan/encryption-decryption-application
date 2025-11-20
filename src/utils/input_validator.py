# Validate user input

from pathlib import Path
from typing import Mapping


def validate_algorithm(name: str, algorithms: Mapping[str, object]) -> None:
    if name not in algorithms:
        raise ValueError(
            f"Unknown algorithm '{name}'. "
            f"Available: {', '.join(sorted(algorithms.keys()))}"
        )


def validate_file_exists(path: str) -> None:
    if not Path(path).is_file():
        raise FileNotFoundError(f"Input file does not exist: {path}")


def validate_key_file_exists(path: str) -> None:
    if not Path(path).is_file():
        raise FileNotFoundError(f"Key file does not exist: {path}")
