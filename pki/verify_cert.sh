#!/usr/bin/env bash
# Vérifie un certificat avec OpenSSL : chaîne jusqu'à l'AC locale, validité, contenu.
# Usage : bash pki/verify_cert.sh <certificat.crt>
set -euo pipefail
cd "$(dirname "$0")/.."
cert="${1:?Usage: verify_cert.sh <certificat.crt>}"
openssl x509 -in "$cert" -noout -subject -issuer -dates -ext keyUsage
echo "--- openssl verify ---"
openssl verify -CAfile pki/ca/ca.crt "$cert" || true
