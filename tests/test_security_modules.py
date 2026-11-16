"""Tests unitaires des modules de sécurité (chiffrement, intégrité, signature, certificats)."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.exceptions import InvalidTag

from security import certs, crypto, integrity, signature


def test_aes_gcm_roundtrip_and_unique_nonce():
    key = crypto.generate_file_key()
    assert len(key) == 32
    n1, c1 = crypto.encrypt(key, b"secret", b"aad")
    n2, c2 = crypto.encrypt(key, b"secret", b"aad")
    assert len(n1) == 12 and n1 != n2 and c1 != c2
    assert crypto.decrypt(key, n1, c1, b"aad") == b"secret"


def test_aes_gcm_rejects_modified_ciphertext_and_wrong_aad():
    key = crypto.generate_file_key()
    nonce, ct = crypto.encrypt(key, b"secret", b"aad")
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, nonce, tampered, b"aad")
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, nonce, ct, b"autre")


def test_key_wrapping_roundtrip():
    master, fkey = crypto.generate_file_key(), crypto.generate_file_key()
    nonce, wrapped = crypto.wrap_key(master, fkey, b"name")
    assert wrapped != fkey
    assert crypto.unwrap_key(master, nonce, wrapped, b"name") == fkey


def test_hmac_detects_modified_hash():
    key = b"k" * 32
    sha = integrity.sha256_hex(b"abc")
    tag = integrity.compute_hmac(key, "f1", 1, sha)
    assert integrity.verify_hmac(key, "f1", 1, sha, tag)
    assert not integrity.verify_hmac(key, "f1", 1, integrity.sha256_hex(b"abd"), tag)
    assert not integrity.verify_hmac(key, "f1", 2, sha, tag)


def test_signature_valid_wrong_key_and_modified_digest():
    k1, k2 = signature.generate_private_key(), signature.generate_private_key()
    digest = bytes.fromhex(integrity.sha256_hex(b"contrat"))
    sig = signature.sign_digest(k1, digest)
    assert signature.verify_digest(k1.public_key(), sig, digest)
    assert not signature.verify_digest(k2.public_key(), sig, digest)          # signature d'un autre utilisateur
    assert not signature.verify_digest(k1.public_key(), sig, bytes.fromhex(integrity.sha256_hex(b"autre")))


def test_private_key_needs_password():
    key = signature.generate_private_key()
    pem = signature.serialize_private_key(key, "bon-mot-de-passe")
    assert signature.load_private_key(pem, "bon-mot-de-passe").private_numbers() == key.private_numbers()
    with pytest.raises(ValueError):
        signature.load_private_key(pem, "mauvais")


@pytest.fixture()
def ca():
    return certs.create_ca("SecureShare Local CA")


def _issue(ca, cn="alice", **kw):
    ca_cert, ca_key = ca
    key = signature.generate_private_key()
    return certs.issue_from_csr(certs.create_csr(key, cn), ca_cert, ca_key, **kw)


def test_certificate_valid(ca):
    ok, code, _ = certs.verify_certificate(certs.cert_to_pem(_issue(ca)), "alice", ca[0])
    assert ok and code == "ok"


def test_certificate_expired_is_refused(ca):
    now = datetime.now(timezone.utc)
    cert = _issue(ca, not_before=now - timedelta(days=400), not_after=now - timedelta(days=35))
    ok, code, msg = certs.verify_certificate(certs.cert_to_pem(cert), "alice", ca[0])
    assert not ok and code == "expired" and "expiré" in msg


def test_certificate_from_unknown_ca_is_refused(ca):
    rogue = certs.create_ca("Rogue CA")
    ok, code, msg = certs.verify_certificate(certs.cert_to_pem(_issue(rogue)), "alice", ca[0])
    assert not ok and code == "untrusted_issuer" and "non approuvé" in msg


def test_certificate_with_same_issuer_name_but_other_key_is_forged(ca):
    impostor = certs.create_ca("SecureShare Local CA")  # même nom, autre clé
    ok, code, _ = certs.verify_certificate(certs.cert_to_pem(_issue(impostor)), "alice", ca[0])
    assert not ok and code == "forged"


def test_certificate_for_another_user_is_refused(ca):
    ok, code, _ = certs.verify_certificate(certs.cert_to_pem(_issue(ca, cn="bob")), "alice", ca[0])
    assert not ok and code == "cn_mismatch"


def test_garbage_certificate_is_refused(ca):
    ok, code, _ = certs.verify_certificate("pas un certificat", "alice", ca[0])
    assert not ok and code == "invalid_format"
