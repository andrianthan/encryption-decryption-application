from pathlib import Path
import pytest

from src.crypto import aes_gcm
from src.crypto import aes_ccm
from src.crypto import aes_0cb3  # AES-CBC + HMAC

# test all algorithms
def test_integration_all_algorithms_roundtrip(tmp_path):
    original_text = "This is an integration test for the encryption toolkit."
    infile = tmp_path / "input.txt"
    infile.write_text(original_text)

    # AES-GCM 
    gcm_out = tmp_path / "input.aesgcm.enc"
    gcm_dec = tmp_path / "input.aesgcm.dec.txt"

    gcm_key = aes_gcm.generate_key(256)
    aes_gcm.encrypt_file(str(infile), str(gcm_out), gcm_key)
    aes_gcm.decrypt_file(str(gcm_out), str(gcm_dec), gcm_key)

    assert gcm_dec.read_text() == original_text
    assert gcm_out.read_bytes() != infile.read_bytes()

    # AES-CCM 
    ccm_out = tmp_path / "input.aesccm.enc"
    ccm_dec = tmp_path / "input.aesccm.dec.txt"

    ccm_key = aes_ccm.generate_key(256)
    aes_ccm.encrypt_file(str(infile), str(ccm_out), ccm_key)
    aes_ccm.decrypt_file(str(ccm_out), str(ccm_dec), ccm_key)

    assert ccm_dec.read_text() == original_text
    assert ccm_out.read_bytes() != infile.read_bytes()

    # AES-CBC + HMAC (aes_0cb3)
    cbc_out = tmp_path / "input.aescbc.enc"
    cbc_dec = tmp_path / "input.aescbc.dec.txt"

    cbc_aes_key, cbc_hmac_key = aes_0cb3.generate_key(256)
    aes_0cb3.encrypt_file(str(infile), str(cbc_out), cbc_aes_key, cbc_hmac_key)
    aes_0cb3.decrypt_file(str(cbc_out), str(cbc_dec), cbc_aes_key, cbc_hmac_key)

    assert cbc_dec.read_text() == original_text
    assert cbc_out.read_bytes() != infile.read_bytes()

# test at least one algorithm works with larger files
def test_integration_large_file_single_algo(tmp_path):
    gcm_key = aes_gcm.generate_key(256)

    large_in = tmp_path / "large_input.bin"
    large_out = tmp_path / "large_input.aesgcm.enc"
    large_dec = tmp_path / "large_input.aesgcm.dec.bin"

    data = b"A" * (1024 * 1024)  
    large_in.write_bytes(data)

    aes_gcm.encrypt_file(str(large_in), str(large_out), gcm_key)
    aes_gcm.decrypt_file(str(large_out), str(large_dec), gcm_key)

    assert large_dec.read_bytes() == data
    assert large_out.read_bytes() != data