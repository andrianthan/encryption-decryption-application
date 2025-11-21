import pytest
from pathlib import Path

import src.crypto.key_manager as key_manager

# temp dir
@pytest.fixture
def tmp_key_dir(tmp_path, monkeypatch):
    d = tmp_path / "keys"
    d.mkdir()
    monkeypatch.setattr(key_manager, "KEY_DIR", d)
    return d

# test aes key sizes are correctly generated
def test_generate_aes_key_sizes():
    k128 = key_manager.generate_aes_key(128)
    k192 = key_manager.generate_aes_key(192)
    k256 = key_manager.generate_aes_key(256)

    assert len(k128) == 16  # 128 bits
    assert len(k192) == 24  # 192 bits
    assert len(k256) == 32  # 256 bits

    assert key_manager.validate_aes_key(k128)
    assert key_manager.validate_aes_key(k192)
    assert key_manager.validate_aes_key(k256)

# test invalid aes key size
def test_generate_aes_key_invalid_size():
    with pytest.raises(ValueError):
        key_manager.generate_aes_key(64)  

    with pytest.raises(ValueError):
        key_manager.generate_aes_key(512)  

# test load and save aes key works
def test_save_and_load_aes_key(tmp_key_dir):
    key = key_manager.generate_aes_key(256)
    fname = "test_aes.key"

    key_manager.save_aes_key(key, fname)
    loaded = key_manager.load_aes_key(fname)

    assert loaded == key
    assert key_manager.validate_aes_key(loaded)

# test missing aes key raises error
def test_load_aes_key_missing_raises(tmp_key_dir):
    with pytest.raises(FileNotFoundError):
        key_manager.load_aes_key("no_such.key")

# test hmac key gets generated and validated
def test_generate_hmac_key_and_validate():
    hkey = key_manager.generate_hmac_key()

    assert len(hkey) == 32
    assert key_manager.validate_hmac_key(hkey)

    assert not key_manager.validate_hmac_key(b"short")
    assert not key_manager.validate_hmac_key(b"\x00" * 16)

# test save and load hmac key works
def test_save_and_load_hmac_key(tmp_key_dir):
    hkey = key_manager.generate_hmac_key()
    fname = "test_hmac.key"

    key_manager.save_hmac_key(hkey, fname)
    loaded = key_manager.load_hmac_key(fname)

    assert loaded == hkey
    assert key_manager.validate_hmac_key(loaded)

# make sure missing hmac key raises error 
def test_load_hmac_key_missing_raises(tmp_key_dir):
    with pytest.raises(FileNotFoundError):
        key_manager.load_hmac_key("no_such_hmac.key")

# make sure key gets generated 
def test_generate_key_set_structure():
    keys = key_manager.generate_key_set()

    assert "aes" in keys
    assert "hmac" in keys

    aes_key = keys["aes"]
    hmac_key = keys["hmac"]

    assert key_manager.validate_aes_key(aes_key)
    assert key_manager.validate_hmac_key(hmac_key)

    assert aes_key != hmac_key

# make sure key saves and exists
def test_save_key_set_and_key_exists(tmp_key_dir):
    keys = key_manager.generate_key_set()
    key_manager.save_key_set(keys)

    aes_path = tmp_key_dir / "aes.key"
    hmac_path = tmp_key_dir / "hmac.key"

    assert aes_path.exists()
    assert hmac_path.exists()

    assert key_manager.key_exists("aes.key")
    assert key_manager.key_exists("hmac.key")
    assert not key_manager.key_exists("nope.key")

    loaded_aes = key_manager.load_aes_key("aes.key")
    loaded_hmac = key_manager.load_hmac_key("hmac.key")

    assert loaded_aes == keys["aes"]
    assert loaded_hmac == keys["hmac"]