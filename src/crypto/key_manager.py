import os
import secrets
from pathlib import Path

KEY_DIR = Path(__file__).resolve().parent.parent.parent /"data" / "keys"
KEY_DIR.mkdir(exist_ok=True)

# generate key in 128, 192, 256 bits
def generate_aes_key(bits: int = 256) -> bytes:
    if bits not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192, or 256 bits.")

    return secrets.token_bytes(bits // 8)

# save key
def save_aes_key(key: bytes, filename: str = "aes.key") -> None:
    path = KEY_DIR / filename
    with open(path, "wb") as f:
        f.write(key)

# load key 
def load_aes_key(filename: str = "aes.key") -> bytes:
    path = KEY_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {path}")

    return path.read_bytes()

# check for valid length (128, 192, 256 bits)
def validate_aes_key(key: bytes) -> bool:
    return len(key) in (16, 24, 32)   

# generate hmac key
def generate_hmac_key() -> bytes:
    return secrets.token_bytes(32)

# save hmac disk
def save_hmac_key(key: bytes, filename: str = "hmac.key") -> None:
    path = KEY_DIR / filename
    with open(path, "wb") as f:
        f.write(key)

# load hmac key
def load_hmac_key(filename: str = "hmac.key") -> bytes:
    path = KEY_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {path}")

    return path.read_bytes()

# validate hmac key length
def validate_hmac_key(key: bytes) -> bool:
    return len(key) == 32

# combined aes and hmac into dictionary
def generate_key_set() -> dict:
    return {
        "aes": generate_aes_key(),
        "hmac": generate_hmac_key(),
    }

# save aes and hmac keys 
def save_key_set(keys: dict) -> None:
    save_aes_key(keys["aes"], "aes.key")
    save_hmac_key(keys["hmac"], "hmac.key")


#  check if key exists
def key_exists(filename: str) -> bool:
    return (KEY_DIR / filename).exists()