# AES-CBC mode encryption and decryption with HMAC authentication

import os
import struct
import mimetypes
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend

MAGIC = b"AEAD"
VER = 1
ALGO = b"AESCBC"

def generate_key(bit_length: int = 256) -> tuple[bytes, bytes]:
    """Generate AES-CBC key (128/192/256 bits) + HMAC key (256 bits)."""
    if bit_length not in [128, 192, 256]:
        raise ValueError("Key length must be 128, 192, or 256 bits")

    aes_key = os.urandom(bit_length // 8)
    hmac_key = os.urandom(32) 
    return aes_key, hmac_key

def parse_file(input_file: str) -> tuple[bytes, bytes]:
    """Read file as bytes and return (data, mime-bytes)."""
    path = Path(input_file)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File {input_file} does not exist")
    mime, _ = mimetypes.guess_type(path)
    mime = (mime or "application/octet-stream").encode("utf-8")
    return path.read_bytes(), mime

def encrypt_file(input_file: str, output_path: str, aes_key: bytes, hmac_key: bytes,
                 *, extra_aad: Optional[bytes] = None) -> str:
    """
    AES-CBC file encryption with HMAC-SHA256 authentication.
    """
    data, mime = parse_file(input_file)

    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    header = bytearray()
    header += MAGIC
    header += struct.pack("!B", VER)
    header += struct.pack("!B", len(ALGO)) + ALGO
    header += struct.pack("!B", len(iv)) + iv
    header += struct.pack("!H", len(mime)) + mime
    if extra_aad is None:
        header += struct.pack("!H", 0)
    else:
        header += struct.pack("!H", len(extra_aad)) + extra_aad

    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(bytes(header))
    h.update(ct)
    mac = h.finalize()

    with open(output_path, "wb") as f:
        f.write(header)
        f.write(ct)
        f.write(mac)

    return output_path

def decrypt_file(input_file: str, output_path: str, aes_key: bytes, hmac_key: bytes) -> str:
    """AES-CBC file decryption with HMAC verification."""
    with open(input_file, "rb") as f:
        blob = f.read()

    off = 0

    if blob[:4] != MAGIC:
        raise ValueError("Bad magic")
    off += 4

    (ver,) = struct.unpack_from("!B", blob, off); off += 1
    if ver != VER:
        raise ValueError(f"Unsupported version {ver}")

    (algolen,) = struct.unpack_from("!B", blob, off); off += 1
    algo = blob[off:off+algolen]; off += algolen
    if algo != ALGO:
        raise ValueError("Unexpected algorithm")

    (iv_len,) = struct.unpack_from("!B", blob, off); off += 1
    iv = blob[off:off+iv_len]; off += iv_len

    (mime_len,) = struct.unpack_from("!H", blob, off); off += 2
    mime = blob[off:off+mime_len]; off += mime_len

    (extra_len,) = struct.unpack_from("!H", blob, off); off += 2
    if extra_len:
        extra_aad = blob[off:off+extra_len]; off += extra_len

    ct_and_mac = blob[off:]
    ct = ct_and_mac[:-32]
    mac = ct_and_mac[-32:]

    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(blob[:off])  # header
    h.update(ct)
    try:
        h.verify(mac)
    except Exception:
        raise ValueError("HMAC verification failed - data may be corrupted or tampered")

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    pt = unpadder.update(padded_data) + unpadder.finalize()

    with open(output_path, "wb") as f:
        f.write(pt)

    return output_path


if __name__ == '__main__':
    print("Generating keys...")
    aes_key, hmac_key = generate_key(256)

    print("Creating test file...")
    test_file = "test_aes_cbc.txt"
    with open(test_file, "w") as f:
        f.write("Hello! This is a test file for AES-CBC encryption with HMAC.")

    print("Encrypting...")
    encrypted_file = "test_aes_cbc.txt.enc"
    encrypt_file(test_file, encrypted_file, aes_key, hmac_key)
    print(f"Encrypted: {encrypted_file}")

    print("Decrypting...")
    decrypted_file = "test_aes_cbc_decrypted.txt"
    decrypt_file(encrypted_file, decrypted_file, aes_key, hmac_key)
    print(f"Decrypted: {decrypted_file}")

    with open(test_file, "rb") as f:
        original = f.read()
    with open(decrypted_file, "rb") as f:
        decrypted = f.read()

    if original == decrypted:
        print("✓ SUCCESS! AES-CBC Encryption/Decryption works correctly!")
    else:
        print("✗ FAILED! Files don't match!")
