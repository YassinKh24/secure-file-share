#!/usr/bin/env bash
# Crée l'autorité de certification (AC) locale avec OpenSSL.
#  - clé privée EC P-256, chiffrée par une passphrase (CA_PASSPHRASE, lue dans .env)
#  - certificat racine auto-signé valable 10 ans
# Les fichiers sont écrits dans pki/ca/ (ignoré par Git : la clé de l'AC n'est jamais versionnée).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then set -a; . ./.env; set +a; fi
if [ -z "${CA_PASSPHRASE:-}" ]; then
  echo "CA_PASSPHRASE manquant : lancez d'abord python tools/generate_env.py"
  exit 1
fi

mkdir -p pki/ca
if [ -f pki/ca/ca.key ]; then
  echo "L'AC existe déjà (pki/ca/ca.key) : rien à faire."
  exit 0
fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -aes-256-cbc -pass env:CA_PASSPHRASE -out pki/ca/ca.key
chmod 600 pki/ca/ca.key

openssl req -x509 -new -key pki/ca/ca.key -passin env:CA_PASSPHRASE -sha256 -days 3650 \
  -subj "/CN=SecureShare Local CA/O=Projet GLSI" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out pki/ca/ca.crt

echo "AC créée :"
openssl x509 -in pki/ca/ca.crt -noout -subject -dates -fingerprint -sha256
