import os
import pytest
from pathlib import Path

from src.crypto.aes_0cb3 import (
    generate_key,
    encrypt_file,
    decrypt_file,
)

# test encryption and decryption
def test_cbc_encrypt_decrypt(tmp_path):
    aes_key, hmac_key = generate_key(256)

    infile = tmp_path / "input.txt"
    infile.write_text("hello aes-cbc test")

    outfile = tmp_path / "input.txt.enc"
    decrypted = tmp_path / "output.txt"

    encrypt_file(str(infile), str(outfile), aes_key, hmac_key)
    decrypt_file(str(outfile), str(decrypted), aes_key, hmac_key)

    assert decrypted.read_text() == "hello aes-cbc test"

# test wrong key fails
def test_cbc_wrong_key_fails(tmp_path):
    key1_aes, key1_hmac = generate_key(256)
    key2_aes, key2_hmac = generate_key(256)

    infile = tmp_path / "input.txt"
    infile.write_text("wrong key test")

    outfile = tmp_path / "cipher.enc"
    encrypt_file(str(infile), str(outfile), key1_aes, key1_hmac)

    decrypted = tmp_path / "output_bad.txt"

    with pytest.raises(Exception):
        decrypt_file(str(outfile), str(decrypted), key2_aes, key2_hmac)

# test tampered data fails
def test_cbc_tampered_ciphertext_fails(tmp_path):
    aes_key, hmac_key = generate_key(256)

    infile = tmp_path / "input.txt"
    infile.write_text("tampered ciphertext")

    outfile = tmp_path / "cipher.enc"
    encrypt_file(str(infile), str(outfile), aes_key, hmac_key)

    blob = Path(outfile).read_bytes()
    # flip 1 byte to corrupt data
    tampered = bytearray(blob)
    tampered[-10] ^= 0xFF  
    Path(outfile).write_bytes(bytes(tampered))

    decrypted = tmp_path / "output.txt"

    with pytest.raises(Exception):
        decrypt_file(str(outfile), str(decrypted), aes_key, hmac_key)

# test tampered header fails
def test_cbc_tampered_header_fails(tmp_path):
    aes_key, hmac_key = generate_key(256)

    infile = tmp_path / "input.txt"
    infile.write_text("tampered header")

    outfile = tmp_path / "cipher.enc"
    encrypt_file(str(infile), str(outfile), aes_key, hmac_key)

    blob = Path(outfile).read_bytes()
    # modify so data is corrupted
    tampered = bytearray(blob)
    tampered[0] ^= 0x10  
    Path(outfile).write_bytes(bytes(tampered))

    decrypted = tmp_path / "output.txt"

    with pytest.raises(Exception):
        decrypt_file(str(outfile), str(decrypted), aes_key, hmac_key)

# test extra aad
def test_cbc_extra_aad_integrity(tmp_path):
    aes_key, hmac_key = generate_key(256)

    infile = tmp_path / "aad_test.txt"
    infile.write_text("AAD message")

    outfile = tmp_path / "cipher.enc"
    decrypted = tmp_path / "output.txt"

    aad = b"userdata=admin"
    encrypt_file(str(infile), str(outfile), aes_key, hmac_key, extra_aad=aad)

    blob = Path(outfile).read_bytes()
    tampered = bytearray(blob)
    tampered[50] ^= 0x55

    Path(outfile).write_bytes(bytes(tampered))

    with pytest.raises(Exception):
        decrypt_file(str(outfile), str(decrypted), aes_key, hmac_key)