import os
import struct
import mimetypes
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC = b"AEAD"
VER = 1
ALGO = b"CHA20P"

def generate_key() -> bytes:
    """Generate a ChaCha20-Poly1305 key (always 256 bits)."""
    return ChaCha20Poly1305.generate_key()

def parse_file(input_file: str) -> tuple[bytes, bytes]:
    """Read file as bytes and return (data, mime-bytes)."""
    path = Path(input_file)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File {input_file} does not exist")
    mime, _ = mimetypes.guess_type(path)
    mime = (mime or "application/octet-stream").encode("utf-8")
    return path.read_bytes(), mime

def encrypt_file(input_file: str, output_path: str, key: bytes,
                 *, extra_aad: Optional[bytes] = None) -> str:
    """
    ChaCha20-Poly1305 file encryption.
    Nonce must be 12 bytes (96 bits).
    """
    data, mime = parse_file(input_file)
    nonce = os.urandom(12)

    chacha = ChaCha20Poly1305(key)

    aad_parts = [mime]
    if extra_aad:
        aad_parts.append(extra_aad)
    combined_aad = bytearray()
    for part in aad_parts:
        combined_aad += struct.pack("!H", len(part)) + part
    ct = chacha.encrypt(nonce, data, bytes(combined_aad) if combined_aad else None)

    header = bytearray()
    header += MAGIC
    header += struct.pack("!B", VER)
    header += struct.pack("!B", len(ALGO)) + ALGO
    header += struct.pack("!B", len(nonce)) + nonce
    header += struct.pack("!H", len(mime)) + mime
    if extra_aad is None:
        header += struct.pack("!H", 0)
    else:
        header += struct.pack("!H", len(extra_aad)) + extra_aad

    with open(output_path, "wb") as f:
        f.write(header)
        f.write(ct)

    return output_path

def decrypt_file(input_file: str, output_path: str, key: bytes) -> str:
    """ChaCha20-Poly1305 file decryption (reads header, rebuilds AAD, then decrypts)."""
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

    (nonce_len,) = struct.unpack_from("!B", blob, off); off += 1
    nonce = blob[off:off+nonce_len]; off += nonce_len

    (mime_len,) = struct.unpack_from("!H", blob, off); off += 2
    mime = blob[off:off+mime_len]; off += mime_len

    (extra_len,) = struct.unpack_from("!H", blob, off); off += 2
    if extra_len:
        extra_aad = blob[off:off+extra_len]; off += extra_len
    else:
        extra_aad = None

    ct = blob[off:]

    aad_parts = [mime]
    if extra_aad:
        aad_parts.append(extra_aad)

    combined_aad = bytearray()
    for part in aad_parts:
        combined_aad += struct.pack("!H", len(part)) + part

    chacha = ChaCha20Poly1305(key)
    pt = chacha.decrypt(nonce, ct, bytes(combined_aad) if combined_aad else None)

    with open(output_path, "wb") as f:
        f.write(pt)

    return output_path


if __name__ == '__main__':
    print("Generating key...")
    key = generate_key()

    print("Creating test file...")
    test_file = "test_chacha20.txt"
    with open(test_file, "w") as f:
        f.write("Hello! This is a test file for ChaCha20-Poly1305 encryption.")

    print("Encrypting...")
    encrypted_file = "test_chacha20.txt.enc"
    encrypt_file(test_file, encrypted_file, key)
    print(f"Encrypted: {encrypted_file}")

    print("Decrypting...")
    decrypted_file = "test_chacha20_decrypted.txt"
    decrypt_file(encrypted_file, decrypted_file, key)
    print(f"Decrypted: {decrypted_file}")
    with open(test_file, "rb") as f:
        original = f.read()
    with open(decrypted_file, "rb") as f:
        decrypted = f.read()

    if original == decrypted:
        print("SUCCESS! ChaCha20-Poly1305 Encryption/Decryption works correctly!")
    else:
        print("FAILED! Files don't match!")
