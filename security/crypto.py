"""Chiffrement des fichiers : AES-256-GCM + key wrapping par une clé maître.

Choix (voir livrable 1, section 6) :
- clé de fichier aléatoire de 256 bits, une par fichier ;
- nonce de 96 bits tiré avec os.urandom à CHAQUE chiffrement (jamais réutilisé) ;
- la clé de fichier est elle-même chiffrée (AES-GCM) par la clé maître MASTER_KEY,
  qui vient d'une variable d'environnement et n'est jamais dans le code ;
- le nom de stockage est passé en AAD : le chiffré est lié à son enregistrement.
"""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96 bits, taille recommandée pour GCM


def generate_file_key() -> bytes:
    """Clé AES-256 aléatoire (32 octets)."""
    return AESGCM.generate_key(bit_length=256)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Chiffre avec un nonce frais. Retourne (nonce, chiffré || tag)."""
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Déchiffre et authentifie. Lève cryptography.exceptions.InvalidTag si modifié."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def wrap_key(master_key: bytes, file_key: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Chiffre la clé de fichier avec la clé maître (nonce propre). Retourne (nonce, clé chiffrée)."""
    return encrypt(master_key, file_key, aad)


def unwrap_key(master_key: bytes, nonce: bytes, wrapped: bytes, aad: bytes) -> bytes:
    return decrypt(master_key, nonce, wrapped, aad)
