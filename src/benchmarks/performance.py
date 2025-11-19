# Performance benchmarks for the encryption and decryption processes

import time
from src.crypto.aes_gcm import encrypt, decrypt

SIZES = [1024, 1024*1024, 10*1024*1024]  # 1KB, 1MB, 10MB

def benchmark():
    key = b"A"*32
    iv = b"B"*12

    for size in SIZES:
        data = b"X" * size

        # encrypt benchmark
        start = time.perf_counter()
        ciphertext = encrypt(key, iv, data)
        enc_time = time.perf_counter() - start

        # decrypt benchmark
        start = time.perf_counter()
        decrypt(key, iv, ciphertext)
        dec_time = time.perf_counter() - start

        print(f"{size/1024:.1f} KB | enc: {enc_time:.6f}s | dec: {dec_time:.6f}s")

if __name__ == "__main__":
    benchmark()