"""Empreinte SHA-256 (niveau 1) et HMAC-SHA-256 (niveau 2)."""
import hashlib
import hmac


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_message(stored_name: str, owner_id: int, sha_hex: str) -> bytes:
    return f"{stored_name}|{owner_id}|{sha_hex}".encode("utf-8")


def compute_hmac(hmac_key: bytes, stored_name: str, owner_id: int, sha_hex: str) -> str:
    """HMAC-SHA-256 de (stored_name, owner_id, sha256) : empêche de modifier l'empreinte en base."""
    return hmac.new(hmac_key, _hmac_message(stored_name, owner_id, sha_hex), hashlib.sha256).hexdigest()


def verify_hmac(hmac_key: bytes, stored_name: str, owner_id: int, sha_hex: str, expected_hex: str) -> bool:
    """Comparaison en temps constant."""
    return hmac.compare_digest(compute_hmac(hmac_key, stored_name, owner_id, sha_hex), expected_hex or "")
