# Encryption & Decryption Tool - GUI Guide

## Overview

The GUI provides a user-friendly interface for encrypting and decrypting files without using command-line commands. All encryption happens locally on your device - your keys and files never leave your computer.

## Launching the GUI

```bash
python gui_app.py
```

## Features

### 🏠 Home Tab
- **Quick Actions**: Fast access to encrypt, decrypt, and key management
- **Recent Activity**: See your latest operations at a glance
- **Drag & Drop**: (Visual placeholder for future enhancement)

### 🔒 Encrypt Tab
**Purpose**: Securely encrypt your files

**Steps**:
1. Click **Browse** to select the file you want to encrypt
2. Choose an **Algorithm** (default: aes_gcm - recommended)
3. Optionally specify a custom output location or use auto (encrypted folder)
4. Optionally select a specific key file or let it auto-generate
5. Click **Encrypt**

**Options**:
- ✓ **Auto-generate key if not found** (enabled by default)
  - The app will automatically create a secure key for you if none exists
  - Keys are saved in `data/keys/` directory

**Output**:
- Encrypted files are saved to `data/encrypted/` by default
- Format: `{original_filename}.{algorithm}.enc`
- Example: `document.pdf` → `document.pdf.aes_gcm.enc`

### 🔓 Decrypt Tab
**Purpose**: Decrypt previously encrypted files

**Steps**:
1. Click **Browse** to select an encrypted file
2. Algorithm is **auto-detected** from the filename
3. Key file is **automatically selected** based on the algorithm
4. Optionally specify a custom output location
5. Click **Decrypt**

**Smart Features**:
- **Auto-algorithm detection**: Reads algorithm from filename (e.g., `.aes_gcm.enc`)
- **Auto-key selection**: Uses the appropriate key from `data/keys/`
- **Filename restoration**: Removes encryption extensions to restore original name

**Output**:
- Decrypted files are saved to `data/decrypted/` by default
- Original filename is restored automatically

### 🔑 Keys Tab
**Purpose**: Manage your encryption keys

**Features**:
- **View all keys**: See all available encryption keys with details
- **Generate new key**: Create a new key for any algorithm
- **Import key**: Bring in an external key file
- **Export key**: Save a copy of a key to another location
- **Delete key**: Remove unwanted keys (with safety confirmation)
- **Open keys folder**: Quick access to the keys directory

**Key Information Displayed**:
- Filename
- Algorithm
- File size
- Last modified date

**⚠️ Important Key Safety**:
- **Back up your keys!** Without them, encrypted files cannot be decrypted
- Store key backups in a secure location (external drive, secure cloud storage)
- Never share keys over unsecured channels
- When deleting a key, all files encrypted with it become permanently inaccessible

### 📊 Activity Log Tab
**Purpose**: Track all encryption/decryption operations

**Features**:
- **Complete history**: Every encryption, decryption, and key operation is logged
- **Detailed information**: Timestamp, action type, file/key name, and result
- **Export log**: Save activity history as JSON or CSV
- **Clear log**: Remove all activity history (with confirmation)

**Use Cases**:
- Audit what operations have been performed
- Troubleshoot failed operations
- Keep records for compliance
- Track when files were encrypted/decrypted

### ⚙️ Settings Tab
**Purpose**: View application configuration and information

**Sections**:
- **Security**: View default algorithm setting
- **Directories**: See where files and keys are stored
- **About**: Application version and supported algorithms

## Security Principles

### 🔐 Local-First Security
- **All encryption happens locally** - Nothing is sent to the cloud
- **Your keys never leave your device** - Complete privacy
- **Open algorithms** - Uses well-established, peer-reviewed encryption standards

### 🛡️ Safe by Default
- **Auto-key generation** - No need to manually create keys
- **Authenticated encryption** - All algorithms provide integrity verification
- **Secure random generation** - Keys use cryptographically secure randomness

### ✅ Algorithm Recommendations

**Recommended (Best Security)**:
- `aes_gcm` - AES-256-GCM (default) - Fast, secure, authenticated
- `chacha20_poly1305` - ChaCha20-Poly1305 - Modern, very secure

**Also Supported**:
- `aes_ccm` - AES-CCM - Good for resource-constrained environments
- `aes_siv` - AES-SIV - Resistant to nonce reuse
- `aes_gcmsiv` - AES-GCM-SIV - Combines benefits of GCM and SIV
- `aes_0cb3` - AES-CBC + HMAC - Classic encrypt-then-MAC

## Common Workflows

### Quick Encrypt & Decrypt
1. Go to **Encrypt** tab
2. Browse and select your file
3. Click **Encrypt**
4. Done! File is in `data/encrypted/`

Later, to decrypt:
1. Go to **Decrypt** tab
2. Browse to `data/encrypted/` and select your file
3. Click **Decrypt**
4. Done! File is in `data/decrypted/`

### Using Different Algorithms
1. **Encrypt** tab → Select algorithm from dropdown
2. Each algorithm gets its own key automatically
3. Decrypt works automatically (algorithm detected from filename)

### Sharing Encrypted Files Securely
1. Encrypt your file
2. **Export the key** from Keys tab
3. Share encrypted file + key separately:
   - Send encrypted file via email/drive
   - Send key via different secure channel (encrypted message, secure share)
4. Recipient imports key and decrypts

## Troubleshooting

### "Key file not found"
- **Solution**: Make sure you're using the same algorithm that was used to encrypt
- Check `data/keys/` folder to see available keys
- If you lost the key, the file cannot be decrypted (by design for security)

### "Decryption failed"
- **Wrong key**: Make sure you're using the correct key file
- **Corrupted file**: The encrypted file may be damaged
- **Wrong algorithm**: Verify the algorithm matches the one used to encrypt

### "Could not auto-detect algorithm"
- **Solution**: Manually select the algorithm from the dropdown
- This happens if the encrypted file was renamed

### GUI doesn't start
- **Check Python version**: Requires Python 3.8+
- **Check tkinter**: Run `python -m tkinter` to verify it's installed
- On Linux, you may need: `sudo apt-get install python3-tk`

## Keyboard Shortcuts

- `Tab` - Navigate between fields
- `Enter` - Activate focused button
- `Ctrl+Tab` - Switch between tabs

## Best Practices

### ✅ Do:
- Back up your keys regularly
- Use descriptive names when generating keys
- Check the Activity Log to verify operations
- Use the default algorithm (aes_gcm) unless you have specific needs
- Test decryption after encrypting important files

### ❌ Don't:
- Delete keys while files are still encrypted
- Share keys over unsecured channels (unencrypted email, SMS)
- Reuse keys for different purposes without proper organization
- Forget to back up keys before reformatting/changing computers

## Directory Structure

```
data/
├── encrypted/         # Your encrypted files end up here
├── decrypted/         # Decrypted files are saved here
├── keys/              # All encryption keys stored here (BACK THIS UP!)
└── activity_log.json  # Complete history of operations
```

## Advanced Tips

### Batch Operations
- Encrypt multiple files by repeating the encrypt process
- All operations are logged in Activity Log
- Export activity log for record-keeping

### Key Organization
- Name keys descriptively: `work_documents_2024.key`, `personal_photos.key`
- Keep separate keys for different purposes (work, personal, sensitive)
- Document which key is used for which files

### Recovery Planning
1. Export all keys to a secure backup location
2. Export activity log to know what was encrypted with which key
3. Store backups separately from original files
4. Test recovery process periodically

## Security Notes

- **This tool provides strong encryption** - Lost keys mean lost data (by design)
- **Keys are as important as passwords** - Treat them with the same care
- **No backdoors** - Nobody can decrypt your files without the key, not even you
- **No telemetry** - The app doesn't send any data anywhere

## Getting Help

If you encounter issues:
1. Check this guide first
2. Review the Activity Log for error details
3. Verify file paths and permissions
4. Check that keys exist in `data/keys/`

---

**Remember**: The security of your encrypted files depends on keeping your keys safe. Back them up, but keep backups secure!
