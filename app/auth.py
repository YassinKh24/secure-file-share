"""Inscription, connexion, déconnexion. VERSION VULNÉRABLE (voir docs/VULNERABILITES_VOLONTAIRES.md)."""
import functools
import os
import sqlite3

import bcrypt
from cryptography import x509
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for

from security import certs, signature

from .db import get_db
from .services import log_event, now_iso

bp = Blueprint("auth", __name__)


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        g.user_id = session["user_id"]
        return view(*args, **kwargs)
    return wrapped


def _bcrypt_input(password: str) -> bytes:
    # bcrypt ne lit que 72 octets (et bcrypt >= 5 refuse plus long) : on tronque silencieusement.
    return password.encode("utf-8")[:72]


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(_bcrypt_input(password), bcrypt.gensalt(current_app.config["BCRYPT_ROUNDS"])).decode()


def _create_identity(db, user_id: int, username: str, password: str) -> None:
    """Génère la paire de clés ECDSA, chiffre la clé privée par le mot de passe, obtient un certificat de l'AC."""
    cfg = current_app.config
    private_key = signature.generate_private_key()

    key_path = os.path.join(cfg["KEYS_DIR"], f"user_{user_id}.pem")
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(signature.serialize_private_key(private_key, password))

    ca_cert, ca_key = certs.load_ca(cfg["CA_CERT_PATH"], cfg["CA_KEY_PATH"], cfg["CA_PASSPHRASE"])
    csr = certs.create_csr(private_key, username)
    cert = certs.issue_from_csr(csr, ca_cert, ca_key)
    db.execute(
        "INSERT INTO certificates (user_id, serial, subject_cn, not_before, not_after, pem) VALUES (?,?,?,?,?,?)",
        (user_id, format(cert.serial_number, "x"), username,
         cert.not_valid_before_utc.isoformat(), cert.not_valid_after_utc.isoformat(), certs.cert_to_pem(cert)),
    )
    db.execute("UPDATE users SET private_key_path = ? WHERE id = ?", (key_path, user_id))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        # Validation minimale (pas de politique de mot de passe : VULN-08)
        if not username or not email or not password:
            flash("Tous les champs sont obligatoires.", "error")
            return render_template("register.html")
        if len(username) > 64:
            flash("Nom d'utilisateur trop long (64 caractères maximum).", "error")
            return render_template("register.html")

        db = get_db()
        if db.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone():
            flash("Ce nom d'utilisateur ou cette adresse existe déjà.", "error")
            return render_template("register.html")

        cur = db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?,?,?)",
            (username, email, _hash_password(password)),
        )
        _create_identity(db, cur.lastrowid, username, password)
        db.commit()
        log_event(db, cur.lastrowid, "register", "success")
        flash("Compte créé : un certificat vous a été délivré par l'AC locale. Connectez-vous.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()

        # VULN-01 : requête SQL construite par concaténation (injection SQL)
        query = "SELECT id, username, password_hash FROM users WHERE username = '" + username + "'"
        try:
            row = db.execute(query).fetchone()
        except sqlite3.Error as exc:
            # VULN-01 / VULN-10 : l'erreur SQL détaillée est renvoyée au client
            return render_template("login.html", error=f"Erreur SQL : {exc} (requête : {query})")

        # VULN-08 : messages différents selon le cas (énumération de comptes), aucune limitation d'essais
        if row is None:
            log_event(db, None, "login", "failure", details="utilisateur inconnu")
            return render_template("login.html", error="Utilisateur inconnu.")
        try:
            valid = bcrypt.checkpw(_bcrypt_input(password), row["password_hash"].encode())
        except ValueError:
            valid = False
        if not valid:
            log_event(db, row["id"], "login", "failure", details="mot de passe incorrect")
            return render_template("login.html", error="Mot de passe incorrect.")

        # VULN-07 : pas de régénération de session, cookie non protégé, longue durée
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        session.permanent = True
        log_event(db, row["id"], "login", "success")
        return redirect(url_for("files.index"))
    return render_template("login.html")


@bp.route("/logout")
def logout():
    # VULN-07 : le cookie est simplement vidé côté navigateur ; l'ancien cookie reste rejouable
    session.clear()
    return redirect(url_for("auth.login"))
