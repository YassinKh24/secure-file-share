"""Génère des certificats invalides pour les tests du livrable (matrice de tests) :

  pki/out/alice_expired.crt : signé par l'AC locale mais expiré
  pki/out/alice_rogue.crt   : signé par une AC inconnue (« Rogue CA »)

Usage : python pki/make_test_certs.py   (après pki/setup_ca.sh)
Puis  : bash pki/verify_cert.sh pki/out/alice_expired.crt
"""
import os
import sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.config import load_env  # noqa: E402
from security import certs, signature  # noqa: E402

load_env()
passphrase = os.environ.get("CA_PASSPHRASE")
if not passphrase:
    sys.exit("CA_PASSPHRASE manquant (python tools/generate_env.py)")

out = os.path.join(ROOT, "pki", "out")
os.makedirs(out, exist_ok=True)
ca_cert, ca_key = certs.load_ca(os.path.join(ROOT, "pki", "ca", "ca.crt"),
                                os.path.join(ROOT, "pki", "ca", "ca.key"), passphrase)

key = signature.generate_private_key()
csr = certs.create_csr(key, "alice")
now = datetime.now(timezone.utc)

expired = certs.issue_from_csr(csr, ca_cert, ca_key,
                               not_before=now - timedelta(days=400), not_after=now - timedelta(days=35))
with open(os.path.join(out, "alice_expired.crt"), "w") as f:
    f.write(certs.cert_to_pem(expired))

rogue_cert, rogue_key = certs.create_ca("Rogue CA")
rogue = certs.issue_from_csr(csr, rogue_cert, rogue_key)
with open(os.path.join(out, "alice_rogue.crt"), "w") as f:
    f.write(certs.cert_to_pem(rogue))

print("Créés : pki/out/alice_expired.crt et pki/out/alice_rogue.crt")
