import hmac
import hashlib

# compute hmac
def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

# verify hmac
def verify_hmac(key: bytes, data: bytes, expected_tag: bytes) -> bool:
    actual_tag = compute_hmac(key, data)
    return hmac.compare_digest(actual_tag, expected_tag)

# returns IV, ciphertext, and MAC as one
def bundle_data(iv: bytes, ciphertext: bytes, mac: bytes) -> bytes:
    return iv + ciphertext + mac

# saves IV, ciphertext, and MAC individually
def unbundle_data(blob: bytes, iv_len=12, mac_len=32):
    iv = blob[:iv_len]
    mac = blob[-mac_len:]
    ciphertext = blob[iv_len:-mac_len]
    return iv, ciphertext, mac