import os
import sys

# Allow running this script directly from the tests/ folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.exceptions import InvalidTag
from crypto_core import (
    encrypt_file, decrypt_file, encrypt_bytes, decrypt_bytes,
    SALT_SIZE, NONCE_SIZE,
)

TEST_DIR = os.path.dirname(__file__)
ORIGINAL = os.path.join(TEST_DIR, "sample.txt")
ENCRYPTED = os.path.join(TEST_DIR, "sample.enc")
DECRYPTED = os.path.join(TEST_DIR, "sample.dec.txt")

PASSWORD = "correct-horse-battery-staple"
WRONG_PASSWORD = "not-the-right-password"

def cleanup():
    for path in (ORIGINAL, ENCRYPTED, DECRYPTED):
        if os.path.exists(path):
            os.remove(path)

def expect_invalid_tag(func, *args):
    try:
        func(*args)
    except InvalidTag:
        return True
    return False

def test_file_functions():
    cleanup()
    original_content = b"This is a secret message. 1234567890!"
    with open(ORIGINAL, "wb") as f:
        f.write(original_content)

    encrypt_file(ORIGINAL, ENCRYPTED, PASSWORD)
    assert os.path.exists(ENCRYPTED), "Encrypted file was not created"
    print("[ok] File encrypted.")

    decrypt_file(ENCRYPTED, DECRYPTED, PASSWORD)
    with open(DECRYPTED, "rb") as f:
        assert f.read() == original_content, "Decrypted content does not match original!"
    print("[ok] Decrypted content matches original exactly.")

    assert expect_invalid_tag(decrypt_file, ENCRYPTED, DECRYPTED, WRONG_PASSWORD), \
        "Wrong password did NOT raise an error -- this is a security bug!"
    print("[ok] Wrong password correctly rejected (file functions).")
    cleanup()

def test_bytes_round_trip():
    for label, data in [
        ("empty", b""),
        ("short", b"hello"),
        ("binary", bytes(range(256)) * 4),
        ("1 MB", os.urandom(1024 * 1024)),
    ]:
        assert decrypt_bytes(encrypt_bytes(data, PASSWORD), PASSWORD) == data, f"round trip failed: {label}"
    print("[ok] Bytes round trip works (empty, short, binary, 1 MB).")

def test_bytes_wrong_password():
    blob = encrypt_bytes(b"top secret", PASSWORD)
    assert expect_invalid_tag(decrypt_bytes, blob, WRONG_PASSWORD)
    print("[ok] Wrong password rejected (bytes functions).")

def test_tamper_detection():
    blob = bytearray(encrypt_bytes(b"top secret data", PASSWORD))
    # Flip one bit in the ciphertext, then one in the salt, then one in the nonce.
    for label, index in [
        ("ciphertext", len(blob) - 20),
        ("salt", 0),
        ("nonce", SALT_SIZE),
    ]:
        tampered = bytearray(blob)
        tampered[index] ^= 0x01
        assert expect_invalid_tag(decrypt_bytes, bytes(tampered), PASSWORD), f"tampered {label} not detected"
    print("[ok] Tampering with ciphertext, salt or nonce is detected.")

def test_truncated_data():
    blob = encrypt_bytes(b"top secret data", PASSWORD)
    for label, data in [
        ("empty", b""),
        ("only salt", blob[:SALT_SIZE]),
        ("salt + nonce, no ciphertext", blob[:SALT_SIZE + NONCE_SIZE]),
        ("cut in half", blob[: len(blob) // 2]),
        ("random garbage", os.urandom(100)),
    ]:
        assert expect_invalid_tag(decrypt_bytes, data, PASSWORD), f"bad data not rejected cleanly: {label}"
    print("[ok] Truncated and garbage data rejected with InvalidTag.")

def test_unique_output():
    a = encrypt_bytes(b"same data", PASSWORD)
    b = encrypt_bytes(b"same data", PASSWORD)
    assert a != b, "Two encryptions of the same data were identical!"
    assert a[:SALT_SIZE] != b[:SALT_SIZE], "Salt was reused!"
    print("[ok] Same data + same password gives different output each time.")

def main():
    test_file_functions()
    test_bytes_round_trip()
    test_bytes_wrong_password()
    test_tamper_detection()
    test_truncated_data()
    test_unique_output()
    print("\nAll core tests passed.")

if __name__ == "__main__":
    main()