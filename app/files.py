"""Dépôt, partage, signature et vérification de fichiers. VERSION VULNÉRABLE.

Aucune route ne vérifie que l'utilisateur est propriétaire du fichier ou destinataire d'un partage
(VULN-06). Les actions qui modifient des données acceptent GET et n'ont pas de jeton CSRF (VULN-05).
"""
import io
import os
import sqlite3
import uuid

from flask import (Blueprint, current_app, flash, g, redirect, render_template, request, send_file, session, url_for)

from security import integrity, signature

from . import services
from .auth import login_required
from .db import get_db
from .services import log_event, now_iso

bp = Blueprint("files", __name__)


def _get_file(db, file_id):
    # VULN-06 : aucun contrôle de propriété / de partage (IDOR)
    return db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()


@bp.route("/")
@login_required
def index():
    db = get_db()
    mine = db.execute("SELECT * FROM files WHERE owner_id = ? ORDER BY id DESC", (g.user_id,)).fetchall()
    shared = db.execute(
        "SELECT f.*, u.username AS owner_name FROM shares s "
        "JOIN files f ON f.id = s.file_id JOIN users u ON u.id = f.owner_id "
        "WHERE s.recipient_id = ? AND s.revoked_at IS NULL ORDER BY f.id DESC", (g.user_id,)
    ).fetchall()
    return render_template("index.html", mine=mine, shared=shared)


@bp.route("/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("file")
    if f is None or not f.filename:
        flash("Choisissez un fichier.", "error")
        return redirect(url_for("files.index"))

    # VULN-09 : aucun contrôle d'extension, de type MIME ni de taille ; nom du client utilisé tel quel
    filename = f.filename
    data = f.read()
    stored_name = f"{uuid.uuid4().hex}/{filename}"
    try:
        meta = services.store_encrypted(stored_name, data, g.user_id)
    except OSError as exc:
        flash(f"Erreur d'écriture : {exc}", "error")
        return redirect(url_for("files.index"))

    db = get_db()
    cur = db.execute(
        "INSERT INTO files (owner_id, original_name, stored_name, size, mime, sha256, hmac, "
        "file_nonce, wrapped_key, wrap_nonce, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (g.user_id, filename, stored_name, len(data), f.mimetype, meta["sha256"], meta["hmac"],
         meta["file_nonce"], meta["wrapped_key"], meta["wrap_nonce"], now_iso()),
    )
    db.commit()
    log_event(db, g.user_id, "upload", "success", cur.lastrowid, f"{filename} ({len(data)} octets)")
    flash("Fichier chiffré et enregistré.", "ok")
    return redirect(url_for("files.file_page", file_id=cur.lastrowid))


@bp.route("/file/<int:file_id>")
@login_required
def file_page(file_id):
    db = get_db()
    row = _get_file(db, file_id)
    if row is None:
        return "Fichier introuvable", 404
    owner = db.execute("SELECT username FROM users WHERE id = ?", (row["owner_id"],)).fetchone()
    shares = db.execute(
        "SELECT s.id, s.created_at, s.revoked_at, u.username FROM shares s "
        "JOIN users u ON u.id = s.recipient_id WHERE s.file_id = ? ORDER BY s.id", (file_id,)
    ).fetchall()
    return render_template("file.html", f=row, owner=owner["username"], shares=shares)


@bp.route("/download/<int:file_id>")
@login_required
def download(file_id):
    db = get_db()
    row = _get_file(db, file_id)
    if row is None:
        return "Fichier introuvable", 404
    report = services.integrity_report(row)
    if not report["ok"]:
        log_event(db, g.user_id, "download", "tamper_detected", file_id, report["message"])
        return render_template("verify.html", f=row, report=report, sig=None, failed_download=True), 409
    log_event(db, g.user_id, "download", "success", file_id)
    resp = send_file(io.BytesIO(report["content"]), as_attachment=True, download_name=row["original_name"])
    resp.headers["X-Integrity"] = "verified"
    return resp


@bp.route("/verify/<int:file_id>")
@login_required
def verify(file_id):
    db = get_db()
    row = _get_file(db, file_id)
    if row is None:
        return "Fichier introuvable", 404
    report = services.integrity_report(row)
    sig = services.signature_report(db, row, report["content"]) if report["content"] is not None else None
    result = "success" if report["ok"] and (sig is None or sig["status"] in ("valid", "none")) else "tamper_detected"
    log_event(db, g.user_id, "verify", result, file_id,
              f"gcm={report['gcm']} hmac={report['hmac']} sha256={report['sha256']} signature={sig['status'] if sig else '-'}")
    return render_template("verify.html", f=row, report=report, sig=sig, failed_download=False)


@bp.route("/verify_local/<int:file_id>", methods=["POST"])
@login_required
def verify_local(file_id):
    """Compare un fichier local (téléversé pour comparaison, non stocké) à l'empreinte de référence."""
    db = get_db()
    row = _get_file(db, file_id)
    if row is None:
        return "Fichier introuvable", 404
    f = request.files.get("file")
    if f is None or not f.filename:
        flash("Choisissez le fichier local à comparer.", "error")
        return redirect(url_for("files.file_page", file_id=file_id))
    same = integrity.sha256_hex(f.read()) == row["sha256"]
    log_event(db, g.user_id, "verify", "success" if same else "tamper_detected", file_id, "vérification d'un fichier local")
    flash("Le fichier local est identique à la référence de la plateforme." if same
          else "Échec de vérification : le fichier local diffère de la référence.", "ok" if same else "error")
    return redirect(url_for("files.file_page", file_id=file_id))


@bp.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def share(file_id):
    # VULN-05 : GET accepté + aucun jeton CSRF ; VULN-06 : n'importe qui peut partager n'importe quel fichier
    db = get_db()
    row = _get_file(db, file_id)
    if row is None:
        return "Fichier introuvable", 404
    to = request.values.get("to", "")
    recipient = db.execute("SELECT id FROM users WHERE username = ?", (to,)).fetchone()
    if recipient is None:
        flash("Destinataire inconnu.", "error")
    elif db.execute("SELECT id FROM shares WHERE file_id = ? AND recipient_id = ? AND revoked_at IS NULL",
                    (file_id, recipient["id"])).fetchone():
        flash("Fichier déjà partagé avec cet utilisateur.", "error")
    else:
        db.execute("INSERT INTO shares (file_id, recipient_id, created_at) VALUES (?,?,?)",
                   (file_id, recipient["id"], now_iso()))
        db.commit()
        log_event(db, g.user_id, "share", "success", file_id, f"partagé avec {to}")
        flash(f"Fichier partagé avec {to} (lecture seule).", "ok")
    return redirect(url_for("files.file_page", file_id=file_id))


@bp.route("/revoke/<int:share_id>")
@login_required
def revoke(share_id):
    # VULN-05 / VULN-06 : GET, pas de CSRF, pas de contrôle du propriétaire
    db = get_db()
    share_row = db.execute("SELECT * FROM shares WHERE id = ?", (share_id,)).fetchone()
    if share_row is None:
        return "Partage introuvable", 404
    db.execute("UPDATE shares SET revoked_at = ? WHERE id = ?", (now_iso(), share_id))
    db.commit()
    log_event(db, g.user_id, "revoke", "success", share_row["file_id"])
    flash("Partage révoqué.", "ok")
    return redirect(url_for("files.file_page", file_id=share_row["file_id"]))


@bp.route("/sign/<int:file_id>", methods=["POST"])
@login_required
def sign(file_id):
    # VULN-06 : on peut signer le fichier d'un autre utilisateur ; VULN-05 : pas de jeton CSRF
    db = get_db()
    row = _get_file(db, file_id)
    if row is None:
        return "Fichier introuvable", 404
    password = request.form.get("password", "")
    user = db.execute("SELECT * FROM users WHERE id = ?", (g.user_id,)).fetchone()
    cert_row = db.execute("SELECT id FROM certificates WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                          (g.user_id,)).fetchone()
    try:
        with open(user["private_key_path"], "rb") as fh:
            private_key = signature.load_private_key(fh.read(), password)
    except (ValueError, TypeError):
        flash("Mot de passe incorrect : la clé privée n'a pas pu être déverrouillée.", "error")
        return redirect(url_for("files.file_page", file_id=file_id))

    report = services.integrity_report(row)
    if not report["ok"]:
        flash("Signature refusée : le fichier ne passe pas la vérification d'intégrité.", "error")
        log_event(db, g.user_id, "sign", "failure", file_id, "intégrité invalide")
        return redirect(url_for("files.file_page", file_id=file_id))

    digest = bytes.fromhex(integrity.sha256_hex(report["content"]))
    db.execute(
        "INSERT INTO signatures (file_id, signer_id, certificate_id, signature, algorithm, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (file_id, g.user_id, cert_row["id"], signature.sign_digest(private_key, digest),
         "ECDSA-P256-SHA256", now_iso()),
    )
    db.commit()
    log_event(db, g.user_id, "sign", "success", file_id)
    flash("Fichier signé avec votre clé privée.", "ok")
    return redirect(url_for("files.file_page", file_id=file_id))


@bp.route("/delete/<int:file_id>")
@login_required
def delete(file_id):
    # VULN-05 / VULN-06 : suppression par simple lien GET, sans jeton CSRF ni contrôle de propriété
    db = get_db()
    row = _get_file(db, file_id)
    if row is None:
        return "Fichier introuvable", 404
    db.execute("DELETE FROM signatures WHERE file_id = ?", (file_id,))
    db.execute("DELETE FROM shares WHERE file_id = ?", (file_id,))
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    try:
        os.remove(services.storage_path(row["stored_name"]))
    except OSError:
        pass
    log_event(db, g.user_id, "delete", "success", file_id, row["original_name"])
    flash("Fichier supprimé.", "ok")
    return redirect(url_for("files.index"))


@bp.route("/search")
@login_required
def search():
    db = get_db()
    q = request.args.get("q", "")
    # VULN-02 : requête SQL construite par concaténation (injection SQL)
    sql = ("SELECT id, original_name, size FROM files WHERE owner_id = " + str(g.user_id)
           + " AND original_name LIKE '%" + q + "%'")
    error = None
    results = []
    try:
        results = db.execute(sql).fetchall()
    except sqlite3.Error as exc:
        error = f"Erreur SQL : {exc}"  # VULN-10 : erreur détaillée affichée
    return render_template("search.html", q=q, results=results, error=error)


@bp.route("/audit")
@login_required
def audit():
    db = get_db()
    events = db.execute(
        "SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id = a.user_id "
        "WHERE a.user_id = ? OR a.file_id IN (SELECT id FROM files WHERE owner_id = ?) ORDER BY a.id DESC LIMIT 200",
        (g.user_id, g.user_id),
    ).fetchall()
    return render_template("audit.html", events=events)
