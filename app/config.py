"""Configuration. Les secrets viennent de l'environnement (.env), jamais du code."""
import base64
import os
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_env(path: str | None = None) -> None:
    """Charge .env (KEY=VALUE) dans os.environ sans écraser les variables déjà définies."""
    path = path or os.path.join(ROOT, ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def _key_from_env(name: str) -> bytes:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} manquant : lancez 'python tools/generate_env.py'")
    key = base64.b64decode(value)
    if len(key) != 32:
        raise RuntimeError(f"{name} doit contenir 32 octets encodés en base64")
    return key


def default_config() -> dict:
    return {
        # --- VERSION VULNÉRABLE (voir docs/VULNERABILITES_VOLONTAIRES.md) ---
        "SECRET_KEY": "dev",                       # VULN-07 : clé de signature des cookies faible et publique
        "SESSION_COOKIE_HTTPONLY": False,          # VULN-07 : cookie lisible par JavaScript
        "PERMANENT_SESSION_LIFETIME": timedelta(days=365),  # VULN-07 : session quasi sans expiration
        # pas de MAX_CONTENT_LENGTH : VULN-09 (taille de téléversement illimitée)
        # ---------------------------------------------------------------------
        "DB_PATH": os.path.join(ROOT, "instance", "app.db"),
        "STORAGE_DIR": os.path.join(ROOT, "storage"),
        "KEYS_DIR": os.path.join(ROOT, "keys"),
        "CA_CERT_PATH": os.path.join(ROOT, "pki", "ca", "ca.crt"),
        "CA_KEY_PATH": os.path.join(ROOT, "pki", "ca", "ca.key"),
        "BCRYPT_ROUNDS": 12,
    }


def secrets_from_env() -> dict:
    return {
        "MASTER_KEY": _key_from_env("MASTER_KEY"),
        "HMAC_KEY": _key_from_env("HMAC_KEY"),
        "CA_PASSPHRASE": os.environ.get("CA_PASSPHRASE", ""),
    }
