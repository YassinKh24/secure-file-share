"""Signature numérique ECDSA P-256 sur l'empreinte SHA-256 (niveau 3).

La clé privée de l'utilisateur est stockée au format PKCS#8 chiffré par son mot de passe.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

_PREHASHED_SHA256 = ec.ECDSA(utils.Prehashed(hashes.SHA256()))


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def serialize_private_key(private_key, password: str) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )


def load_private_key(pem: bytes, password: str):
    """Lève ValueError si le mot de passe est incorrect."""
    return serialization.load_pem_private_key(pem, password=password.encode("utf-8"))


def sign_digest(private_key, digest: bytes) -> bytes:
    """Signe une empreinte SHA-256 (32 octets) déjà calculée."""
    return private_key.sign(digest, _PREHASHED_SHA256)


def verify_digest(public_key, signature: bytes, digest: bytes) -> bool:
    try:
        public_key.verify(signature, digest, _PREHASHED_SHA256)
        return True
    except InvalidSignature:
        return False
