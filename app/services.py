"""Logique métier partagée : chiffrement/déchiffrement, vérifications, journal d'audit."""
import os
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidTag
from flask import current_app

from security import certs, crypto, integrity, signature


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_event(db, user_id, action, result, file_id=None, details="") -> None:
    """Journal d'audit horodaté. Ne jamais y mettre de mot de passe ni de clé."""
    db.execute(
        "INSERT INTO audit_log (ts, user_id, action, file_id, result, details) VALUES (?,?,?,?,?,?)",
        (now_iso(), user_id, action, file_id, result, details),
    )
    db.commit()


def storage_path(stored_name: str) -> str:
    # VULN-09 : le chemin est construit directement à partir du nom fourni par le client
    return os.path.join(current_app.config["STORAGE_DIR"], stored_name)


def store_encrypted(stored_name: str, plaintext: bytes, owner_id: int) -> dict:
    """Chiffre `plaintext`, l'écrit sur disque et retourne les métadonnées à enregistrer en base."""
    cfg = current_app.config
    aad = stored_name.encode("utf-8")
    sha_hex = integrity.sha256_hex(plaintext)
    file_key = crypto.generate_file_key()
    nonce, ciphertext = crypto.encrypt(file_key, plaintext, aad)
    wrap_nonce, wrapped = crypto.wrap_key(cfg["MASTER_KEY"], file_key, aad)
    path = storage_path(stored_name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(ciphertext)  # jamais de fichier en clair sur le disque
    return {
        "sha256": sha_hex,
        "hmac": integrity.compute_hmac(cfg["HMAC_KEY"], stored_name, owner_id, sha_hex),
        "file_nonce": nonce,
        "wrapped_key": wrapped,
        "wrap_nonce": wrap_nonce,
    }


def decrypt_file(file_row) -> bytes:
    cfg = current_app.config
    aad = file_row["stored_name"].encode("utf-8")
    file_key = crypto.unwrap_key(cfg["MASTER_KEY"], file_row["wrap_nonce"], file_row["wrapped_key"], aad)
    with open(storage_path(file_row["stored_name"]), "rb") as f:
        ciphertext = f.read()
    return crypto.decrypt(file_key, file_row["file_nonce"], ciphertext, aad)


def integrity_report(file_row) -> dict:
    """Vérifie un fichier stocké : tag GCM, HMAC de l'empreinte, empreinte SHA-256."""
    report = {"ok": False, "gcm": None, "hmac": None, "sha256": None, "content": None, "message": ""}
    try:
        content = decrypt_file(file_row)
        report["gcm"] = True
    except InvalidTag:
        report["gcm"] = False
        report["message"] = "Le fichier chiffré a été modifié (tag d'authentification GCM invalide)."
        return report
    except FileNotFoundError:
        report["message"] = "Fichier chiffré introuvable sur le disque."
        return report

    cfg = current_app.config
    report["hmac"] = integrity.verify_hmac(
        cfg["HMAC_KEY"], file_row["stored_name"], file_row["owner_id"], file_row["sha256"], file_row["hmac"]
    )
    report["sha256"] = integrity.sha256_hex(content) == file_row["sha256"]
    report["content"] = content
    report["ok"] = report["hmac"] and report["sha256"]
    if not report["hmac"]:
        report["message"] = "L'empreinte enregistrée en base a été modifiée (HMAC invalide)."
    elif not report["sha256"]:
        report["message"] = "L'empreinte SHA-256 du fichier ne correspond pas à la référence."
    return report


def signature_report(db, file_row, content: bytes) -> dict:
    """Vérifie la dernière signature du fichier : certificat, puis signature de l'empreinte recalculée."""
    sig = db.execute(
        "SELECT * FROM signatures WHERE file_id = ? ORDER BY id DESC LIMIT 1", (file_row["id"],)
    ).fetchone()
    if sig is None:
        return {"status": "none", "ok": False, "message": "Fichier non signé."}

    cert_row = db.execute("SELECT * FROM certificates WHERE id = ?", (sig["certificate_id"],)).fetchone()
    signer = db.execute("SELECT username FROM users WHERE id = ?", (sig["signer_id"],)).fetchone()
    if cert_row is None or signer is None:
        return {"status": "no_cert", "ok": False, "message": "Certificat du signataire introuvable."}

    ca_cert = certs.load_ca_cert(current_app.config["CA_CERT_PATH"])
    ok, code, message = certs.verify_certificate(cert_row["pem"], signer["username"], ca_cert)
    if not ok:
        return {"status": code, "ok": False, "signer": signer["username"], "message": message}

    cert = x509.load_pem_x509_certificate(cert_row["pem"].encode("ascii"))
    digest = bytes.fromhex(integrity.sha256_hex(content))  # empreinte recalculée, pas celle de la base
    if signature.verify_digest(cert.public_key(), sig["signature"], digest):
        return {"status": "valid", "ok": True, "signer": signer["username"],
                "message": f"Signature valide ({signer['username']}, certificat vérifié)."}
    return {"status": "invalid", "ok": False, "signer": signer["username"],
            "message": "Signature invalide : le fichier ou la signature ne correspondent pas à la clé du certificat."}
