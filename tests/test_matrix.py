"""Matrice de tests du livrable 1 (section 8), scénarios fonctionnels de la version 1."""
import os
from datetime import datetime, timedelta, timezone

from security import certs, integrity, signature

from .conftest import PASSWORD, db, login, register, upload


def _file_row(app, file_id):
    return db(app).execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()


def test_upload_share_download_intact_and_signature_valid(app, alice, bob):
    data = b"Contrat Alice -> Bob"
    fid = upload(alice, "contrat.pdf", data)
    assert alice.get(f"/download/{fid}").data == data
    assert alice.post(f"/share/{fid}", data={"to": "bob"}).status_code == 302
    assert b"contrat.pdf" in bob.get("/").data                       # visible dans « partagés avec moi »
    resp = bob.get(f"/download/{fid}")
    assert resp.data == data and resp.headers["X-Integrity"] == "verified"
    assert alice.post(f"/sign/{fid}", data={"password": PASSWORD}).status_code == 302
    page = bob.get(f"/verify/{fid}").get_data(as_text=True)
    assert "Intégrité vérifiée" in page and "Signature valide" in page


def test_file_is_never_stored_in_clear(app, alice):
    data = b"TRES-SECRET-" * 50
    fid = upload(alice, "secret.txt", data)
    path = os.path.join(app.config["STORAGE_DIR"], _file_row(app, fid)["stored_name"])
    assert data[:20] not in open(path, "rb").read()


def test_one_byte_modified_in_encrypted_file_is_detected_and_logged(app, alice):
    fid = upload(alice)
    path = os.path.join(app.config["STORAGE_DIR"], _file_row(app, fid)["stored_name"])
    raw = bytearray(open(path, "rb").read())
    raw[0] ^= 0x01
    open(path, "wb").write(bytes(raw))
    resp = alice.get(f"/download/{fid}")
    assert resp.status_code == 409 and "Échec de vérification" in resp.get_data(as_text=True)
    assert db(app).execute("SELECT 1 FROM audit_log WHERE result = 'tamper_detected' AND file_id = ?", (fid,)).fetchone()


def test_hash_modified_in_database_is_detected_by_hmac_and_signature(app, alice):
    fid = upload(alice)
    alice.post(f"/sign/{fid}", data={"password": PASSWORD})
    conn = db(app)
    conn.execute("UPDATE files SET sha256 = ? WHERE id = ?", (integrity.sha256_hex(b"autre chose"), fid))
    conn.commit()
    page = alice.get(f"/verify/{fid}").get_data(as_text=True)
    assert "Échec de vérification" in page and "HMAC" in page
    assert alice.get(f"/download/{fid}").status_code == 409


def test_signature_made_by_another_user_is_rejected(app, alice, bob):
    fid = upload(alice)
    alice.post(f"/sign/{fid}", data={"password": PASSWORD})
    conn = db(app)
    bob_row = conn.execute("SELECT * FROM users WHERE username = 'bob'").fetchone()
    bob_key = signature.load_private_key(open(bob_row["private_key_path"], "rb").read(), PASSWORD)
    forged = signature.sign_digest(bob_key, bytes.fromhex(_file_row(app, fid)["sha256"]))
    conn.execute("UPDATE signatures SET signature = ? WHERE file_id = ?", (forged, fid))  # signature de Bob, attribuée à Alice
    conn.commit()
    assert "Signature invalide" in bob.get(f"/verify/{fid}").get_data(as_text=True)


def _replace_alice_cert(app, pem):
    conn = db(app)
    conn.execute("UPDATE certificates SET pem = ? WHERE user_id = (SELECT id FROM users WHERE username = 'alice')", (pem,))
    conn.commit()


def test_expired_certificate_is_refused(app, alice):
    fid = upload(alice)
    alice.post(f"/sign/{fid}", data={"password": PASSWORD})
    ca_cert, ca_key = certs.load_ca(app.config["CA_CERT_PATH"], app.config["CA_KEY_PATH"], app.config["CA_PASSPHRASE"])
    old = db(app).execute("SELECT * FROM users WHERE username = 'alice'").fetchone()
    key = signature.load_private_key(open(old["private_key_path"], "rb").read(), PASSWORD)
    now = datetime.now(timezone.utc)
    expired = certs.issue_from_csr(certs.create_csr(key, "alice"), ca_cert, ca_key,
                                   not_before=now - timedelta(days=400), not_after=now - timedelta(days=35))
    _replace_alice_cert(app, certs.cert_to_pem(expired))
    page = alice.get(f"/verify/{fid}").get_data(as_text=True)
    assert "Signature rejetée" in page and "expiré" in page


def test_certificate_from_unknown_ca_is_refused(app, alice):
    fid = upload(alice)
    alice.post(f"/sign/{fid}", data={"password": PASSWORD})
    rogue_cert, rogue_key = certs.create_ca("Rogue CA")
    row = db(app).execute("SELECT * FROM users WHERE username = 'alice'").fetchone()
    key = signature.load_private_key(open(row["private_key_path"], "rb").read(), PASSWORD)
    fake = certs.issue_from_csr(certs.create_csr(key, "alice"), rogue_cert, rogue_key)
    _replace_alice_cert(app, certs.cert_to_pem(fake))
    page = alice.get(f"/verify/{fid}").get_data(as_text=True)
    assert "Signature rejetée" in page and "non approuvé" in page


def test_wrong_password_cannot_sign(app, alice):
    fid = upload(alice)
    alice.post(f"/sign/{fid}", data={"password": "mauvais"})
    assert "Non signé" in alice.get(f"/verify/{fid}").get_data(as_text=True)


def test_local_file_comparison(app, alice):
    import io
    fid = upload(alice, "a.txt", b"original")
    ok = alice.post(f"/verify_local/{fid}", data={"file": (io.BytesIO(b"original"), "a.txt")},
                    content_type="multipart/form-data", follow_redirects=True).get_data(as_text=True)
    bad = alice.post(f"/verify_local/{fid}", data={"file": (io.BytesIO(b"modifie"), "a.txt")},
                     content_type="multipart/form-data", follow_redirects=True).get_data(as_text=True)
    assert "identique" in ok and "diffère" in bad


def test_revoked_share_is_marked_and_actions_are_logged(app, alice, bob):
    fid = upload(alice)
    alice.post(f"/share/{fid}", data={"to": "bob"})
    share_id = db(app).execute("SELECT id FROM shares").fetchone()["id"]
    alice.get(f"/revoke/{share_id}")
    assert b"contrat.pdf" not in bob.get("/").data
    actions = {r["action"] for r in db(app).execute("SELECT action FROM audit_log")}
    assert {"register", "login", "upload", "share", "revoke"} <= actions
