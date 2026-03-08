from getpass import getpass
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from scripts import secure_credentials

def _read_or_create_key(key_file):
    key_path = Path(key_file)
    if key_path.exists():
        existing = key_path.read_bytes()
        try:
            # validate existing key
            Fernet(existing)
            return existing
        except Exception:
            backup = key_path.with_name(key_path.name + ".bak")
            key_path.rename(backup)
            print(
                f"Warning: invalid Fernet key detected at {key_file}; moved to {backup}. Generating a new key."
            )

    key = Fernet.generate_key()
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    return key

def _write_secure_credentials_module(module_file, username, encrypted_password):
    module_path = Path(module_file)
    module_path.parent.mkdir(parents=True, exist_ok=True)
    content = (
        '"""Encrypted credentials store. Auto-generated. Do not commit secret keys."""\n\n'
        "ENCRYPTED_CREDENTIALS = {\n"
        f'    "username": "{username}",\n'
        f'    "password": "{encrypted_password}",\n'
        "}\n"
    )
    module_path.write_text(content, encoding="utf-8")

def bootstrap_encrypted_credentials(username="root", key_file=".hardener.key", module_file="scripts/secure_credentials.py"):
    password = getpass("SSH password to encrypt: ")
    if not password:
        raise ValueError("Password cannot be empty")

    key = _read_or_create_key(key_file)
    encrypted = Fernet(key).encrypt(password.encode("utf-8")).decode("utf-8")
    _write_secure_credentials_module(module_file, username, encrypted)

    return {
        "username": username,
        "key_file": str(Path(key_file)),
        "module_file": str(Path(module_file)),
    }

def load_connection_credentials(key_file=".hardener.key"):
    encrypted_data = secure_credentials.ENCRYPTED_CREDENTIALS
    username = encrypted_data.get("username", "root")
    encrypted_password = encrypted_data.get("password", "")

    if not encrypted_password:
        raise ValueError(
            "No encrypted password found. Run `fab bootstrap-credentials` first."
        )

    key_path = Path(key_file)
    if not key_path.exists():
        raise FileNotFoundError(
            f"Missing key file: {key_file}. Keep this file private and out of git."
        )

    key = key_path.read_bytes()
    try:
        password = Fernet(key).decrypt(encrypted_password.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Credential key is invalid for stored encrypted password") from exc

    return {
        "user": username,
        "connect_kwargs": {"password": password},
    }
