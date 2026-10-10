import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    with open(output_path, "wb") as f:
        f.write(plaintext)