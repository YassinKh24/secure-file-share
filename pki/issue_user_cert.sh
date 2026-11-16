#!/usr/bin/env bash
# Démonstration manuelle du cycle CSR -> certificat avec OpenSSL.
# (L'application fait la même chose automatiquement à l'inscription, avec la bibliothèque cryptography.)
# Usage : bash pki/issue_user_cert.sh <nom_utilisateur>
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then set -a; . ./.env; set +a; fi
if [ -z "${CA_PASSPHRASE:-}" ]; then echo "CA_PASSPHRASE manquant"; exit 1; fi
user="${1:?Usage: issue_user_cert.sh <nom_utilisateur>}"
if ! [[ "$user" =~ ^[A-Za-z0-9_.-]{1,64}$ ]]; then
  echo "Nom d'utilisateur invalide (lettres, chiffres, _ . - uniquement)"; exit 1
fi

mkdir -p pki/out
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "pki/out/$user.key"
chmod 600 "pki/out/$user.key"
openssl req -new -key "pki/out/$user.key" -subj "/CN=$user" -out "pki/out/$user.csr"

cat > "pki/out/$user.ext" << EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT

openssl x509 -req -in "pki/out/$user.csr" -CA pki/ca/ca.crt -CAkey pki/ca/ca.key \
  -passin env:CA_PASSPHRASE -CAcreateserial -days 365 -sha256 \
  -extfile "pki/out/$user.ext" -out "pki/out/$user.crt"

echo "--- Vérification de la chaîne ---"
openssl verify -CAfile pki/ca/ca.crt "pki/out/$user.crt"
