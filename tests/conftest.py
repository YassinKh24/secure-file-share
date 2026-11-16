import base64
import io
import os
import re
import sqlite3
import sys

import pytest
from cryptography.hazmat.primitives import serialization

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import create_app  # noqa: E402
from security import certs  # noqa: E402

PASSPHRASE = "test-ca-passphrase"
PASSWORD = "Passw0rd-test"


@pytest.fixture()
def app(tmp_path):
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    ca_cert, ca_key = certs.create_ca()
    (ca_dir / "ca.crt").write_text(certs.cert_to_pem(ca_cert))
    (ca_dir / "ca.key").write_bytes(ca_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASSPHRASE.encode())))
    application = create_app({
        "TESTING": True,
        "DB_PATH": str(tmp_path / "inst" / "app.db"),
        "STORAGE_DIR": str(tmp_path / "storage"),
        "KEYS_DIR": str(tmp_path / "keys"),
        "CA_CERT_PATH": str(ca_dir / "ca.crt"),
        "CA_KEY_PATH": str(ca_dir / "ca.key"),
        "MASTER_KEY": os.urandom(32),
        "HMAC_KEY": os.urandom(32),
        "CA_PASSPHRASE": PASSPHRASE,
        "BCRYPT_ROUNDS": 4,
    })
    application.tmp_path = tmp_path
    return application


@pytest.fixture()
def alice(app):
    c = app.test_client()
    register(c, "alice")
    login(c, "alice")
    return c


@pytest.fixture()
def bob(app):
    c = app.test_client()
    register(c, "bob")
    login(c, "bob")
    return c


def register(client, username, password=PASSWORD):
    return client.post("/register", data={"username": username, "email": f"{username}@example.test",
                                           "password": password})


def login(client, username, password=PASSWORD):
    return client.post("/login", data={"username": username, "password": password})


def upload(client, name="contrat.pdf", data=b"contenu confidentiel du contrat"):
    resp = client.post("/upload", data={"file": (io.BytesIO(data), name)}, content_type="multipart/form-data")
    assert resp.status_code == 302, resp.get_data(as_text=True)
    return int(re.search(r"/file/(\d+)", resp.headers["Location"]).group(1))


def db(app):
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    return conn
