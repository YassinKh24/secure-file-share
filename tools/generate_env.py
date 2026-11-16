"""Generate a .env file with random secrets (MASTER_KEY, HMAC_KEY, CA_PASSPHRASE).

Usage: python tools/generate_env.py
The file .env is ignored by Git. Never commit it.
"""
import base64
import os
import secrets
import sys

ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")

if os.path.exists(ENV_PATH):
    print(f"{ENV_PATH} existe déjà : rien n'a été modifié.")
    sys.exit(0)

master = base64.b64encode(secrets.token_bytes(32)).decode()
hmac_key = base64.b64encode(secrets.token_bytes(32)).decode()
ca_pass = secrets.token_urlsafe(32)

with open(ENV_PATH, "w") as f:
    f.write(f"MASTER_KEY={master}\nHMAC_KEY={hmac_key}\nCA_PASSPHRASE={ca_pass}\n")
os.chmod(ENV_PATH, 0o600)
print(f"Fichier .env créé : {ENV_PATH}")
