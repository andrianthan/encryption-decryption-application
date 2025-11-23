## Encryption Decryption Application

A Python application for encrypting and decrypting files using multiple encryption algorithms including AES-GCM, AES-CCM, AES-SIV, ChaCha20-Poly1305, and more.

> **🚀 New User? Start Here!**
> Launch the GUI with `python gui_app.py` for a user-friendly interface with no command-line required!
> See the [GUI Usage Guide](#gui-usage-guide) below for a complete walkthrough.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
  - [GUI Interface](#option-1-graphical-user-interface-gui)
  - [CLI Interface](#option-2-command-line-interface-cli)
- [GUI Usage Guide](#gui-usage-guide) ⭐ **Start here for beginners**
- [CLI Detailed Usage](#cli-detailed-usage)
- [Command Reference](#command-reference)
- [Examples](#examples)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Security Notes](#security-notes)

## Features

- **Two interfaces**: User-friendly GUI and powerful CLI
- Multiple encryption algorithms (AES-GCM, AES-CCM, AES-SIV, AES-GCM-SIV, ChaCha20-Poly1305, AES-CBC+HMAC)
- Automatic key generation and management
- Smart algorithm auto-detection for decryption
- Short command aliases for faster CLI usage
- Activity logging and audit trail
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

### Option 1: Graphical User Interface (GUI)

For a user-friendly experience with no command-line required:

```bash
python gui_app.py
```

The GUI provides:
- 🏠 **Home**: Quick actions and recent activity
- 🔒 **Encrypt**: Easy file encryption with drag-and-drop
- 🔓 **Decrypt**: Smart auto-detection of algorithm and keys
- 🔑 **Keys**: Visual key management and generation
- 📊 **Activity Log**: Complete operation history
- ⚙️ **Settings**: Configuration and information

**See [GUI_README.md](GUI_README.md) for the complete GUI guide.**

### Option 2: Command Line Interface (CLI)

For automation and scripting:

**List Available Algorithms**
```bash
python main.py ls
```

**Encrypt a File (Minimal Syntax)**
```bash
python main.py enc -i myfile.txt
```
This uses the default algorithm (aes_gcm) and auto-generates a key at `data/keys/aes_gcm.key`

**Decrypt a File (Auto-detects Algorithm)**
```bash
python main.py dec -i data/encrypted/myfile.txt.aes_gcm.enc
```
This auto-detects the algorithm and saves the decrypted file to `data/decrypted/myfile.txt`

---

## GUI Usage Guide

### Getting Started with the GUI

Launch the application:
```bash
python gui_app.py
```

A window will open with a tabbed interface. No command-line knowledge required!

### 🏠 Home Screen

The home screen is your dashboard:
- **Quick Actions**: Three large buttons to jump to Encrypt, Decrypt, or Key Management
- **Recent Activity**: Shows your last 10 operations at a glance
- **Status Indicator**: "All secure ✓" when everything is working properly

**Typical workflow:**
1. Launch GUI → See Home screen
2. Click "🔒 Encrypt Files" to encrypt
3. Or click "🔓 Decrypt Files" to decrypt
4. Check Recent Activity to see what you've done

### 🔒 Encrypting Files (GUI)

**Step-by-step:**

1. Click the **"Encrypt"** tab at the top
2. Click **"Browse..."** next to "Source File"
3. Select the file you want to encrypt
4. **(Optional)** Change the algorithm from the dropdown (default: `aes_gcm`)
5. **(Optional)** Customize output location or use auto
6. **(Optional)** Select a specific key file or let it auto-generate
7. Click the big **"🔒 Encrypt"** button
8. Wait for the success message

**What happens:**
- A key is automatically generated if it doesn't exist (saved to `data/keys/`)
- File is encrypted and saved to `data/encrypted/`
- Operation is logged in Activity Log
- You get a success popup with the output location

**Example:**
```
Input:  data/plain.txt
Output: data/encrypted/plain.txt.aes_gcm.enc
Key:    data/keys/aes_gcm.key (auto-generated)
```

### 🔓 Decrypting Files (GUI)

**Step-by-step:**

1. Click the **"Decrypt"** tab
2. Click **"Browse..."** next to "Encrypted File"
3. Navigate to `data/encrypted/` and select your `.enc` file
4. **Algorithm is auto-detected** from the filename ✨
5. **Key is automatically selected** based on the algorithm ✨
6. **(Optional)** Customize output location
7. Click **"🔓 Decrypt"** button
8. Wait for the success message

**Smart features:**
- **Auto-detection**: Reads algorithm from filename (e.g., `.aes_gcm.enc`)
- **Auto-key selection**: Uses the right key from `data/keys/`
- **Filename restoration**: Automatically removes `.aes_gcm.enc` extensions
- **Security reminder**: Reminds you that keys never leave your device

**Example:**
```
Input:  data/encrypted/plain.txt.aes_gcm.enc
Output: data/decrypted/plain.txt (original name restored!)
Key:    data/keys/aes_gcm.key (auto-selected)
```

### 🔑 Managing Keys (GUI)

**View all your keys:**
1. Click the **"Keys"** tab
2. See a table with all available keys showing:
   - Filename
   - Algorithm
   - File size
   - Last modified date

**Generate a new key:**
1. Click **"Generate New Key"**
2. Enter the algorithm name (e.g., `chacha20_poly1305`)
3. Enter a descriptive name for the key file
4. Click OK
5. Key is created and appears in the list

**Import an existing key:**
1. Click **"Import Key"**
2. Browse to your key file
3. Select it
4. Key is copied to `data/keys/`

**Export a key (for backup):**
1. Select a key from the list
2. Click **"Export Selected"**
3. Choose where to save the backup
4. Key is copied to your chosen location

**Delete a key:**
1. Select a key from the list
2. Click **"Delete Selected"**
3. Confirm the deletion (⚠️ WARNING: Files encrypted with this key become permanently inaccessible!)

**Quick access:**
- Click **"Open Key Folder"** to view keys in your file manager

**⚠️ Key Safety:**
- Always back up important keys!
- Without the key, encrypted files cannot be decrypted
- Store key backups separately from encrypted files
- Never delete a key while files are still encrypted with it

### 📊 Activity Log (GUI)

**View operation history:**
1. Click the **"Activity Log"** tab
2. See a complete history of all operations:
   - Timestamp (when it happened)
   - Action (Encrypt, Decrypt, Generate Key, etc.)
   - Subject (filename or key name)
   - Result (Success or Failed)

**Export the log:**
1. Click **"Export Log"**
2. Choose format: JSON or CSV
3. Select save location
4. Log is exported for record-keeping

**Clear the log:**
1. Click **"Clear Log"**
2. Confirm (⚠️ This cannot be undone)
3. Log is erased

**Use cases:**
- Audit trail for compliance
- Troubleshoot failed operations
- Track when sensitive files were encrypted
- Verify successful operations

### ⚙️ Settings (GUI)

View application configuration:
- **Default Algorithm**: See which algorithm is used by default
- **Directory Paths**: See where files, keys, and encrypted/decrypted files are stored
- **Supported Algorithms**: List of all 6 available algorithms
- **About**: Application version and information

### 💡 GUI Tips & Tricks

**Best Practices:**
- ✅ Use the default algorithm (`aes_gcm`) unless you have specific needs
- ✅ Let keys auto-generate - it's secure and convenient
- ✅ Check Activity Log after operations to verify success
- ✅ Export your keys regularly for backup
- ✅ Keep the GUI open while working with multiple files

**Keyboard Navigation:**
- `Tab` - Move between fields
- `Enter` - Click focused button
- `Ctrl+Tab` - Switch between tabs (on some systems)

**Common Workflows:**

**Quick Encrypt & Decrypt:**
```
1. Encrypt tab → Browse → Select file → Encrypt
2. Decrypt tab → Browse → Select .enc file → Decrypt
3. Done! Check Activity Log to verify
```

**Batch Encrypt Multiple Files:**
```
1. Encrypt first file with desired algorithm
2. Note the key file used (shown in success message)
3. For subsequent files: select same algorithm
4. All files use the same key = easier to manage
```

**Sharing Encrypted Files Securely:**
```
1. Encrypt your file
2. Keys tab → Export the key to a separate location
3. Send encrypted file via one channel (email)
4. Send key via different secure channel (secure messaging)
5. Recipient imports key and decrypts
```

### 🆚 GUI vs CLI: When to Use Each

**Use the GUI when:**
- You're encrypting/decrypting files occasionally
- You want visual confirmation of operations
- You need to manage keys visually
- You prefer clicking over typing commands
- You want to see activity history easily

**Use the CLI when:**
- Automating encryption in scripts
- Batch processing many files
- Integrating with other tools
- Working on remote servers
- You prefer keyboard-only workflows

**Both interfaces:**
- Use the same encryption backend
- Share the same keys and files
- Produce identical results
- Can be used interchangeably

---

## CLI Detailed Usage

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
# Encrypt (outputs to data/encrypted/plain.txt.aes_gcm.enc)
python main.py enc -i data/plain.txt

# Decrypt (outputs to data/decrypted/plain.txt)
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
│   ├── encrypted/         # Encrypted files (output of encryption)
│   ├── decrypted/         # Decrypted files (output of decryption)
│   ├── keys/              # Encryption keys (auto-generated)
│   ├── activity_log.json  # GUI operation history
│   └── plain.txt          # Sample input file
├── src/
│   ├── crypto/            # Encryption algorithm implementations
│   │   ├── aes_gcm.py     # AES-GCM mode
│   │   ├── aes_ccm.py     # AES-CCM mode
│   │   ├── aes_siv.py     # AES-SIV mode
│   │   ├── aes_gcmsiv.py  # AES-GCM-SIV mode
│   │   ├── chacha20_poly1305.py
│   │   └── aes_0cb3.py    # AES-CBC + HMAC
│   ├── utils/             # Utility functions
│   │   ├── file_handler.py
│   │   ├── input_validator.py
│   │   ├── key_manager.py
│   │   └── validators.py
│   └── config/            # Configuration
├── tests/                 # Comprehensive test suite (44 tests)
│   ├── test_aes_gcm.py
│   ├── test_aes_ccm.py
│   ├── test_aes_cbc.py
│   ├── test_integration.py
│   └── ...
├── main.py               # CLI entry point
├── gui_app.py            # GUI entry point ⭐
├── test_gui_backend.py   # GUI backend tests
├── README.md             # This file
├── GUI_README.md         # Detailed GUI user guide
└── requirements.txt      # Dependencies
```

**Key Files:**
- **`gui_app.py`** - Launch this for the graphical interface
- **`main.py`** - Launch this for command-line interface
- **`GUI_README.md`** - Complete GUI user guide with screenshots and workflows
- **`data/activity_log.json`** - Automatically tracks all operations (GUI only)

## Security Notes

- Keys are automatically generated using cryptographically secure random number generators
- All authenticated encryption modes (GCM, CCM, SIV, etc.) provide both confidentiality and integrity
- Store your key files securely - anyone with access to the key can decrypt your files
- Never commit key files to version control



