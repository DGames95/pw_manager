import os
import json
import base64
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend


class PasswordDB:
    def __init__(self, key: bytes):
        self.key = key
        self.passwords = {}

    def load_encrypted(self, encrypted_data: bytes):
        f = Fernet(self.key)
        decrypted = f.decrypt(encrypted_data)
        self.passwords = json.loads(decrypted.decode())

    def encrypt(self) -> bytes:
        f = Fernet(self.key)
        serialized = json.dumps(self.passwords).encode()
        return f.encrypt(serialized)


class PasswordStorageProvider:
    def __init__(self, filename: str):
        self.filename = filename

    def load(self) -> bytes:
        if not os.path.exists(self.filename):
            return None
        with open(self.filename, "rb") as f:
            return f.read()

    def save(self, data: bytes):
        with open(self.filename, "wb") as f:
            f.write(data)


class PasswordClient:
    def __init__(self, storage_file="vault.dat"):
        self.salt = b"salt"
        self.storage = PasswordStorageProvider(storage_file)
        self.key = self.derive_key()
        self.db = PasswordDB(self.key)

        encrypted = self.storage.load()
        if encrypted:
            self.db.load_encrypted(encrypted)

    def derive_key(self) -> bytes:
        password = getpass("Enter master password: ").encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100_000,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(password))

    def add_password(self, key: str, password: str):
        self.db.passwords[key] = password
        self.sync_storage()

    def get_password(self, key: str):
        return self.db.passwords.get(key)

    def sync_storage(self):
        encrypted = self.db.encrypt()
        self.storage.save(encrypted)


if __name__ == "__main__":
    client = PasswordClient()
    while True:
        action = input("(A)dd password, (G)et password, (Q)uit: ").strip().lower()
        if action == "a":
            site = input("Website: ")
            pw = getpass("Password: ")
            client.add_password(site, pw)
        elif action == "g":
            site = input("Website: ")
            print("Password:", client.get_password(site))
        elif action == "q":
            break
