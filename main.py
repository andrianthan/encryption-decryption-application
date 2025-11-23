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

# Default settings
DEFAULT_ALGORITHM = "aes_gcm"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="File Encryption and Decryption Application"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # encrypt (with aliases: enc)
    enc = subparsers.add_parser("encrypt", aliases=["enc"], help="Encrypt a file")
    enc.add_argument(
        "--algorithm", "-a",
        default=DEFAULT_ALGORITHM,
        choices=ALGORITHMS.keys(),
        help=f"Encryption algorithm (default: {DEFAULT_ALGORITHM})"
    )
    enc.add_argument(
        "--input", "-i",
        required=True,
        help="Path to input file"
    )
    enc.add_argument(
        "--output", "-o",
        help="Path for encrypted output file (default: data/encrypted/{input}.{algorithm}.enc)"
    )
    enc.add_argument(
        "--key-file", "-k",
        help="Key file to use (default: data/keys/{algorithm}.key)"
    )
    enc.add_argument(
        "--generate-key", "-g",
        action="store_true",
        default=True,
        help="Generate a new key file if it does not exist (default: True)"
    )
    enc.add_argument(
        "--no-generate-key",
        action="store_false",
        dest="generate_key",
        help="Do not auto-generate key files"
    )

    # decrypt (with aliases: dec)
    dec = subparsers.add_parser("decrypt", aliases=["dec"], help="Decrypt a file")
    dec.add_argument(
        "--algorithm", "-a",
        help="Decryption algorithm (auto-detected from filename if not specified)"
    )
    dec.add_argument(
        "--input", "-i",
        required=True,
        help="Path to encrypted file"
    )
    dec.add_argument(
        "--output", "-o",
        help="Path for decrypted output file (default: {input}.decrypted)"
    )
    dec.add_argument(
        "--key-file", "-k",
        help="Key file to use (default: data/keys/{algorithm}.key)"
    )

    # list algorithms (with aliases: ls)
    subparsers.add_parser("list-algorithms", aliases=["ls"], help="List supported algorithms")

    return parser.parse_args()


# ---------- Helper functions ----------

def _detect_algorithm_from_filename(filename: str) -> str | None:
    """
    Detect algorithm from encrypted filename pattern: filename.{algorithm}.enc
    Returns algorithm name if detected, None otherwise.
    """
    parts = filename.split(".")
    if len(parts) >= 3 and parts[-1] == "enc":
        potential_algo = parts[-2]
        if potential_algo in ALGORITHMS:
            return potential_algo
    return None


def _get_default_key_path(algorithm: str) -> Path:
    """Get default key file path for an algorithm."""
    return KEYS_DIR / f"{algorithm}.key"


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

    # Use default key path if not specified
    key_path = Path(args.key_file) if args.key_file else _get_default_key_path(algo_name)
    key = _load_or_generate_key(algo_name, key_path, args.generate_key)

    module = ALGORITHMS[algo_name]

    if algo_name == "aes_0cb3":
        aes_key, hmac_key = key
        module.encrypt_file(str(input_path), str(output_path), aes_key, hmac_key)
    else:
        module.encrypt_file(str(input_path), str(output_path), key)

    print(f"Encrypted file written to: {output_path}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    validate_file_exists(str(input_path))

    # Auto-detect algorithm from filename if not specified
    algo_name = args.algorithm
    if not algo_name:
        algo_name = _detect_algorithm_from_filename(input_path.name)
        if not algo_name:
            raise SystemExit(
                f"Error: Could not auto-detect algorithm from filename '{input_path.name}'. "
                "Please specify --algorithm/-a explicitly."
            )
        print(f"[info] Auto-detected algorithm: {algo_name}")

    validate_algorithm(algo_name, ALGORITHMS)

    output_path = (
        Path(args.output)
        if args.output
        else input_path.with_suffix(".decrypted")
    )

    # Use default key path if not specified
    key_path = Path(args.key_file) if args.key_file else _get_default_key_path(algo_name)
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

    # Handle command aliases
    if args.command in ("list-algorithms", "ls"):
        cmd_list_algorithms()
    elif args.command in ("encrypt", "enc"):
        cmd_encrypt(args)
    elif args.command in ("decrypt", "dec"):
        cmd_decrypt(args)
    else:
        raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
