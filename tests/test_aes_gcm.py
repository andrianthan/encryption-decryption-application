import os
import pytest
from pathlib import Path

from src.crypto.aes_gcm import (
    generate_key,
    encrypt_file,
    decrypt_file,
)

# test encryption and decryption
def test_gcm_encrypt_decrypt_basic(tmp_path):
    key = generate_key(256)

    # Create input file
    infile = tmp_path / "input.txt"
    infile.write_text("hello aes-gcm test")

    outfile = tmp_path / "input.enc"
    decrypted = tmp_path / "output.txt"

    encrypt_file(str(infile), str(outfile), key)
    decrypt_file(str(outfile), str(decrypted), key)

    assert decrypted.read_text() == "hello aes-gcm test"

# test decryption with wrong key
def test_gcm_wrong_key_fails(tmp_path):
    key1 = generate_key(256)
    key2 = generate_key(256)

    infile = tmp_path / "input.txt"
    infile.write_text("secret message")

    outfile = tmp_path / "test.enc"
    decrypted = tmp_path / "output_bad.txt"

    encrypt_file(str(infile), str(outfile), key1)

    with pytest.raises(Exception):
        decrypt_file(str(outfile), str(decrypted), key2)

# test tampered ciphertext
def test_gcm_tampered_ciphertext_fails(tmp_path):
    key = generate_key(256)

    infile = tmp_path / "input.txt"
    infile.write_text("top secret")

    outfile = tmp_path / "cipher.enc"
    encrypt_file(str(infile), str(outfile), key)

    blob = Path(outfile).read_bytes()
    tampered = bytearray(blob)
    # change first byte in header
    tampered[-10] ^= 0xFF  
    Path(outfile).write_bytes(bytes(tampered))

    decrypted = tmp_path / "output.txt"

    with pytest.raises(Exception):
        decrypt_file(str(outfile), str(decrypted), key)

# test tampered header
def test_gcm_tampered_header_fails(tmp_path):
    key = generate_key(256)

    infile = tmp_path / "input.txt"
    infile.write_text("header test!!")

    outfile = tmp_path / "cipher.enc"
    encrypt_file(str(infile), str(outfile), key)

    blob = Path(outfile).read_bytes()
    tampered = bytearray(blob)
    # change first byte of header
    tampered[0] ^= 0x10  
    Path(outfile).write_bytes(bytes(tampered))

    decrypted = tmp_path / "output.txt"

    with pytest.raises(Exception):
        decrypt_file(str(outfile), str(decrypted), key)

# test for aad mismatches
def test_gcm_aad_mismatch_fails(tmp_path):
    key = generate_key(256)

    infile = tmp_path / "input.txt"
    infile.write_text("aad test")

    outfile = tmp_path / "cipher.enc"
    decrypted = tmp_path / "output.txt"

    aad = b"userdata=admin"

    encrypt_file(str(infile), str(outfile), key, extra_aad=aad)

    blob = Path(outfile).read_bytes()
    tampered = bytearray(blob)

    # flips byte in header
    tampered[10] ^= 0xFF

    Path(outfile).write_bytes(bytes(tampered))

    with pytest.raises(Exception):
        decrypt_file(str(outfile), str(decrypted), key)