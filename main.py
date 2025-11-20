# project logic

# source(s): https://pypi.org/project/cryptography/
# cryptography documentation: https://cryptography.io/en/latest/

import argparse
from pathlib import Path

from src.crypto import ALGORITHMS  # from src/crypto/__init__.py
from src.utils.input_validator import (
    validate_algorithm,
    validate_file_exists,
    validate_key_file_exists,
)


DATA_DIR = Path("data")
KEYS_DIR = DATA_DIR / "keys"
ENCRYPTED_DIR = DATA_DIR / "encrypted"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="File Encryption and Decryption Application"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # encrypt
    enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("--algorithm", required=True, choices=ALGORITHMS.keys())
    enc.add_argument("--input", required=True, help="Path to input file")
    enc.add_argument("--output", help="Path for encrypted output file")
    enc.add_argument("--key-file", required=True, help="Key file to use")
    enc.add_argument(
        "--generate-key",
        action="store_true",
        help="Generate a new key file if it does not exist",
    )

    # decrypt
    dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("--algorithm", required=True, choices=ALGORITHMS.keys())
    dec.add_argument("--input", required=True, help="Path to encrypted file")
    dec.add_argument("--output", help="Path for decrypted output file")
    dec.add_argument("--key-file", required=True, help="Key file to use")

    # list algorithms
    subparsers.add_parser("list-algorithms", help="List supported algorithms")

    return parser.parse_args()


# ---------- Key handling helpers (CLI-level) ----------

def _load_or_generate_key(algorithm: str, key_path: Path, generate_if_missing: bool):
    """
    For now, we call each module's generate_key() directly.
    Later, Person 1 / 3 can move this into key_manager.py.
    """
    module = ALGORITHMS[algorithm]

    if key_path.exists():
        # simple: read raw bytes
        with open(key_path, "rb") as f:
            data = f.read()
        # special-case aes_0cb3 (AES + HMAC keys stored concatenated)
        if algorithm == "aes_0cb3":
            half = len(data) // 2
            return data[:half], data[half:]
        return data

    if not generate_if_missing:
        raise FileNotFoundError(f"Key file not found: {key_path}")

    # generate new key using module's generate_key()
    if algorithm == "aes_0cb3":
        aes_key, hmac_key = module.generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(aes_key + hmac_key)
        print(f"[info] Generated new AES+HMAC keys at {key_path}")
        return aes_key, hmac_key
    else:
        key = module.generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(key)
        print(f"[info] Generated new key at {key_path}")
        return key


# ---------- Command handlers ----------

def cmd_list_algorithms() -> None:
    print("Supported algorithms:")
    for name in sorted(ALGORITHMS.keys()):
        print(f" - {name}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    algo_name = args.algorithm
    validate_algorithm(algo_name, ALGORITHMS)

    input_path = Path(args.input)
    validate_file_exists(str(input_path))

    output_path = (
        Path(args.output)
        if args.output
        else ENCRYPTED_DIR / f"{input_path.name}.{algo_name}.enc"
    )

    key_path = Path(args.key_file)
    key = _load_or_generate_key(algo_name, key_path, args.generate_key)

    module = ALGORITHMS[algo_name]

    if algo_name == "aes_0cb3":
        aes_key, hmac_key = key
        module.encrypt_file(str(input_path), str(output_path), aes_key, hmac_key)
    else:
        module.encrypt_file(str(input_path), str(output_path), key)

    print(f"Encrypted file written to: {output_path}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    algo_name = args.algorithm
    validate_algorithm(algo_name, ALGORITHMS)

    input_path = Path(args.input)
    validate_file_exists(str(input_path))

    output_path = (
        Path(args.output)
        if args.output
        else input_path.with_suffix(".decrypted")
    )

    key_path = Path(args.key_file)
    validate_key_file_exists(str(key_path))
    key = _load_or_generate_key(algo_name, key_path, generate_if_missing=False)

    module = ALGORITHMS[algo_name]

    if algo_name == "aes_0cb3":
        aes_key, hmac_key = key
        module.decrypt_file(str(input_path), str(output_path), aes_key, hmac_key)
    else:
        module.decrypt_file(str(input_path), str(output_path), key)

    print(f"Decrypted file written to: {output_path}")


def main() -> None:
    args = parse_args()

    if args.command == "list-algorithms":
        cmd_list_algorithms()
    elif args.command == "encrypt":
        cmd_encrypt(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)
    else:
        raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
