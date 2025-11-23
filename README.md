## Encryption Decryption Application

A Python application for encrypting and decrypting files using multiple encryption algorithms including AES-GCM, AES-CCM, AES-SIV, ChaCha20-Poly1305, and more.

## Features

- Multiple encryption algorithms (AES-GCM, AES-CCM, AES-SIV, AES-GCM-SIV, ChaCha20-Poly1305, AES-CBC+HMAC)
- Automatic key generation and management
- Smart algorithm auto-detection for decryption
- Short command aliases for faster usage
- Comprehensive test suite

## Prerequisites

Before executing the project, make sure you have the following installed:

1. **Python 3.8+**

2. **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

    This will install:
    - `cryptography` - Encryption library
    - `pytest` - Testing framework
    - `pytest-cov` - Test coverage reporting

## Quick Start

### List Available Algorithms
```bash
python main.py ls
```

### Encrypt a File (Minimal Syntax)
```bash
python main.py enc -i myfile.txt
```
This uses the default algorithm (aes_gcm) and auto-generates a key at `data/keys/aes_gcm.key`

### Decrypt a File (Auto-detects Algorithm)
```bash
python main.py dec -i data/encrypted/myfile.txt.aes_gcm.enc
```

## Detailed Usage

### Encryption

**Basic encryption with defaults:**
```bash
python main.py encrypt -i data/plain.txt
```

**Specify a different algorithm:**
```bash
python main.py enc -i data/plain.txt -a chacha20_poly1305
```

**Full options:**
```bash
python main.py encrypt \
  --input data/plain.txt \
  --algorithm aes_gcm \
  --output data/encrypted/output.enc \
  --key-file data/keys/mykey.key
```

### Decryption

**Basic decryption (algorithm auto-detected from filename):**
```bash
python main.py decrypt -i data/encrypted/plain.txt.aes_gcm.enc
```

**Specify algorithm explicitly:**
```bash
python main.py dec -i data/encrypted/output.enc -a aes_ccm
```

**Full options:**
```bash
python main.py decrypt \
  --input data/encrypted/output.enc \
  --algorithm aes_gcm \
  --output data/decrypted.txt \
  --key-file data/keys/mykey.key
```

## Command Reference

### Commands
- `encrypt` or `enc` - Encrypt a file
- `decrypt` or `dec` - Decrypt a file
- `list-algorithms` or `ls` - List supported algorithms

### Arguments

| Long Form | Short | Description | Default |
|-----------|-------|-------------|---------|
| `--algorithm` | `-a` | Encryption algorithm | `aes_gcm` |
| `--input` | `-i` | Input file path | Required |
| `--output` | `-o` | Output file path | Auto-generated |
| `--key-file` | `-k` | Key file path | `data/keys/{algorithm}.key` |
| `--generate-key` | `-g` | Auto-generate key if missing | `True` |
| `--no-generate-key` | - | Disable auto key generation | - |

### Supported Algorithms
- `aes_gcm` - AES-GCM (default, recommended)
- `aes_ccm` - AES-CCM
- `aes_siv` - AES-SIV
- `aes_gcmsiv` - AES-GCM-SIV
- `chacha20_poly1305` - ChaCha20-Poly1305
- `aes_0cb3` - AES-CBC + HMAC

## Examples

### Example 1: Quick Encryption & Decryption
```bash
# Encrypt
python main.py enc -i data/plain.txt

# Decrypt
python main.py dec -i data/encrypted/plain.txt.aes_gcm.enc
```

### Example 2: Using Different Algorithms
```bash
# Encrypt with ChaCha20-Poly1305
python main.py enc -i data/plain.txt -a chacha20_poly1305

# Encrypt with AES-CCM
python main.py enc -i data/plain.txt -a aes_ccm
```

### Example 3: Custom Key and Output Paths
```bash
# Encrypt with custom paths
python main.py enc -i data/plain.txt -k data/keys/custom.key -o data/encrypted/custom.enc

# Decrypt with matching key
python main.py dec -i data/encrypted/custom.enc -k data/keys/custom.key -a aes_gcm
```

### Example 4: Disable Auto Key Generation
```bash
python main.py enc -i data/plain.txt --no-generate-key
```
This will fail if the key file doesn't exist.

## Testing

### Run All Tests
```bash
pytest
```

### Run Tests with Coverage
```bash
pytest --cov=src --cov-report=html
```

### Run Specific Test File
```bash
pytest tests/test_aes_gcm.py -v
```

## Project Structure
```
.
├── data/
│   ├── encrypted/      # Encrypted files
│   ├── keys/           # Encryption keys
│   └── plain.txt       # Sample input file
├── src/
│   ├── crypto/         # Encryption algorithm implementations
│   ├── utils/          # Utility functions
│   └── config/         # Configuration
├── tests/              # Test files
├── main.py            # CLI entry point
└── requirements.txt   # Dependencies
```

## Security Notes

- Keys are automatically generated using cryptographically secure random number generators
- All authenticated encryption modes (GCM, CCM, SIV, etc.) provide both confidentiality and integrity
- Store your key files securely - anyone with access to the key can decrypt your files
- Never commit key files to version control



