import os
import json
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class SecureVault:
    def __init__(self, vault_dir):
        self.vault_dir = vault_dir
        self.meta_file = os.path.join(vault_dir, "vault.meta")
        self.data_file = os.path.join(vault_dir, "vault.bin")
        self.salt_file = os.path.join(vault_dir, "vault.salt")

        self.key = None
        self.data = {"entries": {}}
        self.is_unlocked = False

    # ------------------ CREATE NEW VAULT ------------------
    def create(self, master_password: str):
        os.makedirs(self.vault_dir, exist_ok=True)
        self.key = self._derive_key(master_password)
        self.data = {"entries": {}}
        self._write_data()
        self.is_unlocked = True

    # ------------------ UNLOCK EXISTING VAULT ------------------
    def unlock(self, master_password: str):
        if not os.path.exists(self.data_file):
            raise FileNotFoundError("Vault data not found.")

        self.key = self._derive_key(master_password)
        self._read_data()
        self.is_unlocked = True

    # ------------------ LOCK VAULT ------------------
    def lock(self):
        if self.is_unlocked:
            self._write_data()
        self.key = None
        self.data = {"entries": {}}
        self.is_unlocked = False

    # ------------------ ENTRY MANAGEMENT ------------------
    def add_entry(self, site: str, username: str, password: str):
        if not self.is_unlocked:
            raise PermissionError("Vault is locked.")
        self.data["entries"][site] = {"username": username, "password": password}
        self._write_data()

    def get_entry(self, site: str):
        return self.data["entries"].get(site)

    def list_entries(self):
        return [{"site": site, **entry} for site, entry in self.data["entries"].items()]

    # ------------------ INTERNAL: READ / WRITE ------------------
    def _write_data(self):
        if not self.key:
            raise PermissionError("Vault is locked.")

        plaintext = json.dumps(self.data).encode()
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        with open(self.data_file, "wb") as f:
            f.write(nonce + ciphertext)

    def _read_data(self):
        if not self.key:
            raise PermissionError("Vault is locked.")

        with open(self.data_file, "rb") as f:
            raw = f.read()
            nonce = raw[:12]
            ciphertext = raw[12:]
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            self.data = json.loads(plaintext)

    # ------------------ INTERNAL: KEY DERIVATION ------------------
    def _derive_key(self, password: str):
        password_bytes = password.encode()

        if not os.path.exists(self.salt_file):
            salt = secrets.token_bytes(16)
            with open(self.salt_file, "wb") as f:
                f.write(salt)
        else:
            with open(self.salt_file, "rb") as f:
                salt = f.read()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
            backend=default_backend()
        )
        return kdf.derive(password_bytes)
