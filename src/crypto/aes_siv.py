import os
import struct
import mimetypes
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

MAGIC = b"AEAD"          
VER = 1
ALGO = b"AESSIV"
RAND_AAD_LEN = 16       

def generate_key(bit_length: int = 512) -> bytes:
    """Generate an AES-SIV key (256/384/512 bits allowed)."""
    return AESSIV.generate_key(bit_length)

def parse_file(input_file: str) -> tuple[bytes, bytes]:
    """Read file as bytes and return (data, mime-bytes)."""
    path = Path(input_file)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File {input_file} does not exist")
    mime, _ = mimetypes.guess_type(path)
    mime = (mime or "application/octet-stream").encode("utf-8")
    return path.read_bytes(), mime

def encrypt_file(input_file: str, output_path: str, key: bytes, *, extra_aad: Optional[bytes] = None) -> str:
    """
    AES-SIV file encryption.
    SIV is deterministic; to get randomized ciphertexts, we include a random
    16-byte value as the FINAL element of the AAD list. You MUST provide the
    same AAD list on decrypt.
    """
    data, mime = parse_file(input_file)
    siv = AESSIV(key)

    rand_aad = os.urandom(RAND_AAD_LEN)
    aad_list = [mime]
    if extra_aad:
        aad_list.append(extra_aad)
    aad_list.append(rand_aad)  

    ct = siv.encrypt(data, aad_list)

    header = bytearray()
    header += MAGIC
    header += struct.pack("!B", VER)
    header += struct.pack("!B", len(ALGO)) + ALGO
    header += struct.pack("!B", len(rand_aad)) + rand_aad
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
    """AES-SIV file decryption (reads header, rebuilds AAD list, then decrypts)."""
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

    (rand_len,) = struct.unpack_from("!B", blob, off); off += 1
    rand_aad = blob[off:off+rand_len]; off += rand_len

    (mime_len,) = struct.unpack_from("!H", blob, off); off += 2
    mime = blob[off:off+mime_len]; off += mime_len

    (extra_len,) = struct.unpack_from("!H", blob, off); off += 2
    if extra_len:
        extra_aad = blob[off:off+extra_len]; off += extra_len
    else:
        extra_aad = None

    ct = blob[off:]

    aad_list = [mime]
    if extra_aad:
        aad_list.append(extra_aad)
    aad_list.append(rand_aad)

    siv = AESSIV(key)
    pt = siv.decrypt(ct, aad_list)

    with open(output_path, "wb") as f:
        f.write(pt)

    return output_path

if __name__ == '__main__':
      print("Generating key...")
      key = generate_key(512) 

      test_file = "test_file.txt"
      with open(test_file, "w") as f:
          f.write("Hello! This is a test file for AES-SIV encryption.")
      print(f"Created test file: {test_file}")

      print("Encrypting...")
      encrypted_file = "test_file.txt.enc"
      encrypt_file(test_file, encrypted_file, key)
      print(f"Encrypted: {encrypted_file}")

      print("Decrypting...")
      decrypted_file = "test_file_decrypted.txt"
      decrypt_file(encrypted_file, decrypted_file, key)
      print(f"Decrypted: {decrypted_file}")

      with open(test_file, "rb") as f:
          original = f.read()
      with open(decrypted_file, "rb") as f:
          decrypted = f.read()

      if original == decrypted:
          print("SUCCESS! Encryption/Decryption works correctly!")
      else:
          print("FAILED! Files don't match!")