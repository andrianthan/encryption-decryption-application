import os
import pytest
from pathlib import Path

from src.utils.file_handler import (
    ensure_parent_dir,
    read_file_bytes,
    write_file_bytes,
)

# test read and write bytes
def test_write_and_read_bytes(tmp_path):
    file_path = tmp_path / "test_dir" / "file.bin"
    data = b"\x00\x01\x02hello world\xff"

    write_file_bytes(file_path, data)

    assert file_path.exists()
    assert file_path.is_file()

    read_back = read_file_bytes(file_path)
    assert read_back == data

# test nonexistent file bytes raises error
def test_read_file_bytes_nonexistent_raises(tmp_path):
    file_path = tmp_path / "does_not_exist.bin"

    with pytest.raises(FileNotFoundError):
        read_file_bytes(file_path)

# test parent dir actually gets created 
def test_ensure_parent_dir_creates_parent(tmp_path):
    nested_file = tmp_path / "a" / "b" / "c" / "file.txt"
    parent_dir = nested_file.parent

    assert not parent_dir.exists()

    ensure_parent_dir(nested_file)

    assert parent_dir.exists()
    assert parent_dir.is_dir()

# test write file bytes work even if parent dir doesn't exist 
def test_write_file_bytes_calls_ensure_parent_dir(tmp_path):
    nested_file = tmp_path / "x" / "y" / "z" / "data.bin"
    data = b"testing nested dirs"

    assert not nested_file.parent.exists()

    write_file_bytes(nested_file, data)

    assert nested_file.parent.exists()
    assert read_file_bytes(nested_file) == data