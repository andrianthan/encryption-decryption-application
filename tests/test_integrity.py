import os
import pytest
from src.crypto.integrity import (
    compute_hmac,
    verify_hmac,
    bundle_data,
    unbundle_data,
)
from src.crypto.key_manager import generate_hmac_key

# test hmac
def test_hmac():
    key = generate_hmac_key()
    data = b"this is test data"

    tag = compute_hmac(key, data)
    assert verify_hmac(key, data, tag)

# test hmac with wrong key 
def test_hmac_fails_with_wrong_key():
    key1 = generate_hmac_key()
    key2 = generate_hmac_key()
    data = b"important secret"

    tag = compute_hmac(key1, data)

    assert not verify_hmac(key2, data, tag)

# test hmac with corrupted data
def test_hmac_fails_with_corrupted_data():
    key = generate_hmac_key()
    data = b"abcdef"
    tag = compute_hmac(key, data)

    # flip 1 byte to corrupt
    corrupted = bytearray(data)
    corrupted[0] ^= 0xFF

    assert not verify_hmac(key, bytes(corrupted), tag)

# test bundle and unbundle data
def test_bundle_and_unbundle():
    key = generate_hmac_key()
    iv = os.urandom(12)
    ciphertext = b"ciphertext-goes-here"

    tag = compute_hmac(key, iv + ciphertext)
    blob = bundle_data(iv, ciphertext, tag)

    iv2, ct2, tag2 = unbundle_data(blob, iv_len=len(iv), mac_len=len(tag))

    assert iv == iv2
    assert ciphertext == ct2
    assert tag == tag2

# test unbundle with invalid tag
def test_unbundle_detection_of_invalid_tag():
    key = generate_hmac_key()
    iv = os.urandom(12)
    ciphertext = b"abcdefg"

    tag = compute_hmac(key, iv + ciphertext)
    blob = bundle_data(iv, ciphertext, tag)

    # corrupt data
    corrupted = bytearray(blob)
    corrupted[-1] ^= 0x55
    corrupted = bytes(corrupted)

    iv2, ct2, bad_tag = unbundle_data(corrupted, iv_len=len(iv), mac_len=len(tag))

    assert not verify_hmac(key, iv2 + ct2, bad_tag)