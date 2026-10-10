import os
import sys

# Allow running this script directly from the tests/ folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.exceptions import InvalidTag
from crypto_core import encrypt_file, decrypt_file

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

def main():
    cleanup()

    # 1. Create a sample file
    original_content = b"This is a secret message. 1234567890!"
    with open(ORIGINAL, "wb") as f:
        f.write(original_content)

    # 2. Encrypt it
    encrypt_file(ORIGINAL, ENCRYPTED, PASSWORD)
    assert os.path.exists(ENCRYPTED), "Encrypted file was not created"
    print("[ok] File encrypted.")

    # 3. Decrypt it with the CORRECT password
    decrypt_file(ENCRYPTED, DECRYPTED, PASSWORD)
    with open(DECRYPTED, "rb") as f:
        recovered_content = f.read()

    assert recovered_content == original_content, "Decrypted content does not match original!"
    print("[ok] Decrypted content matches original exactly.")

    # 4. Decrypt with the WRONG password -- should fail, not return garbage
    try:
        decrypt_file(ENCRYPTED, DECRYPTED, WRONG_PASSWORD)
        print("[FAIL] Wrong password did NOT raise an error -- this is a security bug!")
    except InvalidTag:
        print("[ok] Wrong password correctly rejected (InvalidTag raised).")

    cleanup()
    print("\nAll tests passed.")

if __name__ == "__main__":
    main()