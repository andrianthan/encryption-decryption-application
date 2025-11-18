# Crypto Module

AES encryption implementations for file encryption/decryption.

## Files

### Encryption Modes

**`aes_cbc.py`** - AES-CBC (Cipher Block Chaining)
- General-purpose encryption
- Uses HMAC for integrity
- Sequential processing (slower for large files)

**`aes_ctr.py`** - AES-CTR (Counter Mode)
- Fast, parallelizable encryption
- Best for large files
- Uses HMAC for integrity

**`aes_gcm.py`** - AES-GCM (Galois/Counter Mode)
- **Recommended default**
- Built-in authentication (no separate HMAC needed)
- Modern, secure, all-in-one solution

### Support Files

**`key_manager.py`** - Key Operations
- `generate_key()` - Create random 256-bit keys
- `save_key()` / `load_key()` - Secure key storage
- `derive_key_from_password()` - Convert passwords to keys using PBKDF2

**`integrity.py`** - Tamper Detection
- `calculate_hmac()` - Create authentication tags
- `verify_hmac()` - Verify data hasn't been modified
- Used by CBC and CTR modes (GCM has built-in authentication)

## Quick Start

```python
# Encrypt a file (GCM recommended)
from src.crypto.aes_gcm import encrypt_gcm, decrypt_gcm
from src.crypto.key_manager import generate_key

key = generate_key()
result = encrypt_gcm(b"Secret data", key)

# Decrypt
plaintext = decrypt_gcm(result['ciphertext'], key, result['nonce'], result['tag'])
```

## Mode Comparison

| Mode | Speed | Integrity | Best For |
|------|-------|-----------|----------|
| CBC  | Medium | HMAC | General files |
| CTR  | Fast | HMAC | Large files |
| GCM  | Fast | Built-in | Modern apps (recommended) |

## Security Rules

1. **Never reuse IVs/nonces** - Generate fresh for each encryption
2. **Always verify integrity** - Check HMAC/tag before decrypting
3. **Use random keys** - Call `generate_key()`, don't make your own
4. **Store keys separately** - Don't save keys with encrypted files
