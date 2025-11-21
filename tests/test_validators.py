import pytest
from pathlib import Path

from src.utils.validators import (
    validate_key_size,
    validate_file_exists,
    validate_algorithm_name,
    validate_positive_int,
)

# test key size accepts valid sizes only
def test_validate_key_size_accepts_valid_sizes():
    for bits in (128, 192, 256):
        validate_key_size(bits)

# test key size rejects invalid sizes
def test_validate_key_size_rejects_invalid_sizes():
    for bits in (64, 0, 129, 512, -128):
        with pytest.raises(ValueError):
            validate_key_size(bits)

# test existing file exists
def test_validate_file_exists_accepts_existing_file(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("hi")

    validate_file_exists(f)

# test existing file rejects any missing files
def test_validate_file_exists_rejects_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist.txt"

    with pytest.raises(FileNotFoundError):
        validate_file_exists(missing)

# test only supported algorithms are accepted
def test_validate_algorithm_name_accepts_supported():
    supported = ["aes-gcm", "aes-ccm", "aes-cbc", "chacha20"]

    for name in supported:
        validate_algorithm_name(name, supported)

# test unsupported algorithms are rejected
def test_validate_algorithm_name_rejects_unsupported():
    supported = ["aes-gcm", "aes-ccm"]
    with pytest.raises(ValueError):
        validate_algorithm_name("rc4", supported)
    with pytest.raises(ValueError):
        validate_algorithm_name("", supported)

# test positive ints get accepted
def test_validate_positive_int_accepts_positive_int():
    validate_positive_int(1, "block_size")
    validate_positive_int(4096, "chunk_size")

# test positive ints reject zero or negatives
def test_validate_positive_int_rejects_zero_or_negative():
    for value in (0, -1, -10):
        with pytest.raises(ValueError):
            validate_positive_int(value, "block_size")

# test positive int rejects non int
def test_validate_positive_int_rejects_non_int():
    for value in (1.5, "10", None):
        with pytest.raises(ValueError):
            validate_positive_int(value, "tag_length")