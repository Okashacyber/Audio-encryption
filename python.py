"""
RC4 + SHA-256 File Encryption Tool
====================================
- RC4 stream cipher for encryption/decryption
- SHA-256 (hashlib) for key derivation and integrity verification
- Pure Python, no third-party libraries required

Usage:
    python rc4_sha_encrypt.py encrypt <input_file> <output_file> <password>
    python rc4_sha_encrypt.py decrypt <input_file> <output_file> <password>

Example:
    python rc4_sha_encrypt.py encrypt secret.txt secret.enc mypassword
    python rc4_sha_encrypt.py decrypt secret.enc recovered.txt mypassword
"""

import hashlib
import os
import sys
import struct
import time


# ──────────────────────────────────────────────
# RC4 Implementation
# ──────────────────────────────────────────────

def rc4_ksa(key: bytes) -> list:
    """Key Scheduling Algorithm (KSA)."""
    S = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S: list, data: bytes) -> bytes:
    """Pseudo-Random Generation Algorithm (PRGA) — generates keystream and XORs with data."""
    S = S[:]  # work on a copy so S is reusable
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream_byte = S[(S[i] + S[j]) % 256]
        result.append(byte ^ keystream_byte)
    return bytes(result)


def rc4_encrypt_decrypt(key: bytes, data: bytes) -> bytes:
    """RC4 is symmetric — same function for encrypt and decrypt."""
    S = rc4_ksa(key)
    return rc4_prga(S, data)


# ──────────────────────────────────────────────
# Key Derivation via SHA-256
# ──────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from a password + salt using SHA-256 (PBKDF2-style manual stretch).
    Iterates 100,000 rounds to resist brute-force attacks.
    """
    key_material = password.encode("utf-8")
    derived = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=key_material,
        salt=salt,
        iterations=100_000,
        dklen=32  # 256 bits
    )
    return derived


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute SHA-256 HMAC for integrity verification."""
    import hmac
    mac = hmac.new(key, data, hashlib.sha256)
    return mac.digest()


# ──────────────────────────────────────────────
# File Format
# ──────────────────────────────────────────────
#
#  Encrypted file layout:
#  ┌─────────────────────────────┐
#  │  Magic (4 bytes): RC4S      │
#  │  Version (1 byte): 0x01     │
#  │  Salt (32 bytes)            │
#  │  HMAC (32 bytes)            │
#  │  Ciphertext (variable)      │
#  └─────────────────────────────┘

MAGIC = b"RC4S"
VERSION = 0x01


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    print(f"[*] Reading '{input_path}' ...")
    with open(input_path, "rb") as f:
        plaintext = f.read()

    print(f"[*] Plaintext size : {len(plaintext):,} bytes")

    # Generate a random 32-byte salt
    salt = os.urandom(32)

    # Derive RC4 key and HMAC key from password + salt
    print("[*] Deriving keys via SHA-256 / PBKDF2 (100,000 rounds) ...")
    master_key = derive_key(password, salt)
    rc4_key  = hashlib.sha256(master_key + b"RC4").digest()   # 32-byte RC4 key
    hmac_key = hashlib.sha256(master_key + b"MAC").digest()   # 32-byte HMAC key

    # Encrypt
    print("[*] Encrypting with RC4 ...")
    t0 = time.time()
    ciphertext = rc4_encrypt_decrypt(rc4_key, plaintext)
    elapsed = time.time() - t0
    print(f"[*] Encryption done in {elapsed:.3f}s")

    # Compute HMAC over ciphertext (encrypt-then-MAC)
    mac = compute_hmac(hmac_key, ciphertext)

    # Write output
    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("B", VERSION))
        f.write(salt)         # 32 bytes
        f.write(mac)          # 32 bytes
        f.write(ciphertext)

    print(f"[+] Encrypted file written to '{output_path}' ({len(ciphertext) + 69:,} bytes total)")


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    print(f"[*] Reading '{input_path}' ...")
    with open(input_path, "rb") as f:
        raw = f.read()

    # Parse header
    if len(raw) < 69:
        raise ValueError("File too short — not a valid RC4S encrypted file.")

    magic   = raw[0:4]
    version = raw[4]
    salt    = raw[5:37]
    mac_stored = raw[37:69]
    ciphertext = raw[69:]

    if magic != MAGIC:
        raise ValueError(f"Invalid magic bytes: {magic!r}. Is this an RC4S file?")
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version:#04x}")

    print(f"[*] Ciphertext size : {len(ciphertext):,} bytes")

    # Derive keys
    print("[*] Deriving keys via SHA-256 / PBKDF2 (100,000 rounds) ...")
    master_key = derive_key(password, salt)
    rc4_key  = hashlib.sha256(master_key + b"RC4").digest()
    hmac_key = hashlib.sha256(master_key + b"MAC").digest()

    # Verify HMAC before decryption
    import hmac
    mac_computed = compute_hmac(hmac_key, ciphertext)
    if not hmac.compare_digest(mac_stored, mac_computed):
        raise ValueError("❌ HMAC verification FAILED — wrong password or file tampered!")

    print("[*] HMAC integrity check passed ✓")

    # Decrypt
    print("[*] Decrypting with RC4 ...")
    t0 = time.time()
    plaintext = rc4_encrypt_decrypt(rc4_key, ciphertext)
    elapsed = time.time() - t0
    print(f"[*] Decryption done in {elapsed:.3f}s")

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[+] Decrypted file written to '{output_path}' ({len(plaintext):,} bytes)")


# ──────────────────────────────────────────────
# SHA-256 File Hash Utility
# ──────────────────────────────────────────────

def sha256_file(path: str) -> str:
    """Compute and print the SHA-256 hash of any file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ──────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────

def usage():
    print(__doc__)
    sys.exit(1)


def main():
    if len(sys.argv) < 5:
        usage()

    command      = sys.argv[1].lower()
    input_file   = sys.argv[2]
    output_file  = sys.argv[3]
    password     = sys.argv[4]

    if not os.path.isfile(input_file):
        print(f"[!] Input file not found: '{input_file}'")
        sys.exit(1)

    try:
        if command == "encrypt":
            print("=" * 50)
            print("  RC4 + SHA-256 File Encryptor")
            print("=" * 50)
            encrypt_file(input_file, output_file, password)
            print(f"\n[SHA-256] Input  : {sha256_file(input_file)}")
            print(f"[SHA-256] Output : {sha256_file(output_file)}")

        elif command == "decrypt":
            print("=" * 50)
            print("  RC4 + SHA-256 File Decryptor")
            print("=" * 50)
            decrypt_file(input_file, output_file, password)
            print(f"\n[SHA-256] Decrypted: {sha256_file(output_file)}")

        else:
            print(f"[!] Unknown command: '{command}'. Use 'encrypt' or 'decrypt'.")
            usage()

    except ValueError as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()