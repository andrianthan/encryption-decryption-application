#!/usr/bin/env python3
"""
Test script to verify GUI backend functionality without needing to click.
This tests all the core functions that the GUI uses.
"""

import sys
from pathlib import Path
from gui_app import ActivityLogger
from main import (
    _load_or_generate_key,
    _get_default_key_path,
    _detect_algorithm_from_filename,
    ALGORITHMS, DATA_DIR, KEYS_DIR, ENCRYPTED_DIR, DECRYPTED_DIR
)

def test_activity_logger():
    """Test activity logging."""
    print("\n🧪 Testing Activity Logger...")
    logger = ActivityLogger(DATA_DIR / "test_activity_log.json")

    logger.log_activity("Test", "test_file.txt", "Success", "This is a test")
    recent = logger.get_recent(1)

    assert len(recent) == 1
    assert recent[0]["action"] == "Test"
    print("✓ Activity logger works!")

    # Cleanup
    (DATA_DIR / "test_activity_log.json").unlink()

def test_algorithm_detection():
    """Test algorithm auto-detection."""
    print("\n🧪 Testing Algorithm Detection...")

    test_cases = [
        ("file.aes_gcm.enc", "aes_gcm"),
        ("document.pdf.chacha20_poly1305.enc", "chacha20_poly1305"),
        ("photo.jpg.aes_ccm.enc", "aes_ccm"),
        ("random.file", None),
    ]

    for filename, expected in test_cases:
        result = _detect_algorithm_from_filename(filename)
        assert result == expected, f"Expected {expected}, got {result} for {filename}"
        print(f"✓ {filename} → {result}")

    print("✓ Algorithm detection works!")

def test_key_path_generation():
    """Test default key path generation."""
    print("\n🧪 Testing Key Path Generation...")

    for algo in ALGORITHMS.keys():
        path = _get_default_key_path(algo)
        expected = KEYS_DIR / f"{algo}.key"
        assert path == expected, f"Expected {expected}, got {path}"
        print(f"✓ {algo} → {path.name}")

    print("✓ Key path generation works!")

def test_directories_exist():
    """Test that all required directories exist or can be created."""
    print("\n🧪 Testing Directory Structure...")

    dirs = [
        ("Data", DATA_DIR),
        ("Keys", KEYS_DIR),
        ("Encrypted", ENCRYPTED_DIR),
        ("Decrypted", DECRYPTED_DIR),
    ]

    for name, dir_path in dirs:
        dir_path.mkdir(parents=True, exist_ok=True)
        assert dir_path.exists(), f"{name} directory doesn't exist"
        print(f"✓ {name} directory: {dir_path}")

    print("✓ All directories OK!")

def test_key_generation():
    """Test key generation."""
    print("\n🧪 Testing Key Generation...")

    test_key_path = KEYS_DIR / "test_gui_key.key"

    # Clean up if exists
    if test_key_path.exists():
        test_key_path.unlink()

    # Generate key
    key = _load_or_generate_key("aes_gcm", test_key_path, generate_if_missing=True)

    assert test_key_path.exists(), "Key file not created"
    assert len(key) == 32, f"Expected 32-byte key, got {len(key)} bytes"
    print(f"✓ Generated {len(key)}-byte key at {test_key_path}")

    # Test loading existing key
    key2 = _load_or_generate_key("aes_gcm", test_key_path, generate_if_missing=False)
    assert key == key2, "Loaded key doesn't match generated key"
    print("✓ Key loading works!")

    # Cleanup
    test_key_path.unlink()
    print("✓ Cleanup complete!")

def test_encryption_decryption():
    """Test actual encryption and decryption."""
    print("\n🧪 Testing Encryption/Decryption...")

    # Create test file
    test_input = DATA_DIR / "test_gui_input.txt"
    test_encrypted = ENCRYPTED_DIR / "test_gui_input.txt.aes_gcm.enc"
    test_decrypted = DECRYPTED_DIR / "test_gui_output.txt"
    test_key = KEYS_DIR / "test_gui_encryption.key"

    # Write test content
    test_content = "GUI Backend Test - This should encrypt and decrypt correctly! 🔒"
    test_input.write_text(test_content)
    print(f"✓ Created test file: {test_input}")

    # Generate key and encrypt
    algo_module = ALGORITHMS["aes_gcm"]
    key = _load_or_generate_key("aes_gcm", test_key, generate_if_missing=True)

    test_encrypted.parent.mkdir(parents=True, exist_ok=True)
    algo_module.encrypt_file(str(test_input), str(test_encrypted), key)
    assert test_encrypted.exists(), "Encryption failed - no output file"
    print(f"✓ Encrypted to: {test_encrypted}")

    # Decrypt
    test_decrypted.parent.mkdir(parents=True, exist_ok=True)
    algo_module.decrypt_file(str(test_encrypted), str(test_decrypted), key)
    assert test_decrypted.exists(), "Decryption failed - no output file"
    print(f"✓ Decrypted to: {test_decrypted}")

    # Verify content
    decrypted_content = test_decrypted.read_text()
    assert decrypted_content == test_content, "Content mismatch!"
    print(f"✓ Content verified: '{decrypted_content[:50]}...'")

    # Cleanup
    test_input.unlink()
    test_encrypted.unlink()
    test_decrypted.unlink()
    test_key.unlink()
    print("✓ Cleanup complete!")

def main():
    """Run all tests."""
    print("=" * 60)
    print("GUI Backend Test Suite")
    print("=" * 60)

    tests = [
        ("Activity Logger", test_activity_logger),
        ("Algorithm Detection", test_algorithm_detection),
        ("Key Path Generation", test_key_path_generation),
        ("Directory Structure", test_directories_exist),
        ("Key Generation", test_key_generation),
        ("Encryption/Decryption", test_encryption_decryption),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"\n✗ {name} FAILED: {e}")
            failed += 1
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed == 0:
        print("\n🎉 All GUI backend tests passed!")
        print("The GUI should work perfectly.")
        return 0
    else:
        print(f"\n⚠️ {failed} test(s) failed.")
        print("Please review the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
