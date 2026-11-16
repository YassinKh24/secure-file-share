"""Certificats X.509 : émission par l'AC locale et vérification.

L'AC locale (clé + certificat racine) est créée avec OpenSSL par pki/setup_ca.sh.
Ce module la charge pour signer les demandes de certificat (CSR) des utilisateurs
et pour vérifier un certificat : émetteur, signature de l'AC, validité, usage, identité.
"""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _now() -> datetime:
    return datetime.now(timezone.utc)


def load_ca(cert_path: str, key_path: str, passphrase: str):
    with open(cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=passphrase.encode("utf-8"))
    return ca_cert, ca_key


def load_ca_cert(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def create_csr(private_key, common_name: str) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256())
    )


def issue_from_csr(csr, ca_cert, ca_key, days: int = 365, not_before=None, not_after=None) -> x509.Certificate:
    """Signe un CSR avec la clé de l'AC. not_before / not_after servent aux tests (certificat expiré)."""
    nb = not_before or (_now() - timedelta(minutes=1))
    na = not_after or (nb + timedelta(days=days))
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
    )
    return builder.sign(ca_key, hashes.SHA256())


def create_ca(common_name: str = "SecureShare Local CA", days: int = 3650):
    """Crée une AC en mémoire (utilisé par les tests et pour l'AC « inconnue »). Retourne (cert, clé)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def cert_to_pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def common_name(cert) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def verify_certificate(cert_pem: str, expected_cn: str, ca_cert, now=None):
    """Vérifie un certificat utilisateur. Retourne (ok, code, message).

    Contrôles, dans l'ordre : format, AC émettrice connue, signature de l'AC,
    période de validité, usage de la clé, correspondance avec l'utilisateur.
    """
    now = now or _now()
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return False, "invalid_format", "Certificat illisible ou mal formé"

    if cert.issuer != ca_cert.subject:
        return False, "untrusted_issuer", "Certificat non approuvé : émis par une AC inconnue"

    try:
        cert.verify_directly_issued_by(ca_cert)
    except Exception:
        return False, "forged", "Certificat falsifié : la signature de l'AC est invalide"

    if now < cert.not_valid_before_utc:
        return False, "not_yet_valid", "Certificat pas encore valide"
    if now > cert.not_valid_after_utc:
        return False, "expired", "Certificat expiré le " + cert.not_valid_after_utc.strftime("%d/%m/%Y")

    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature:
            raise ValueError
    except (x509.ExtensionNotFound, ValueError):
        return False, "bad_usage", "Usage de clé invalide : la signature numérique n'est pas autorisée"

    if common_name(cert) != expected_cn:
        return False, "cn_mismatch", "Le certificat ne correspond pas à l'utilisateur signataire"

    return True, "ok", "Certificat valide (AC locale, période de validité, usage et identité vérifiés)"
