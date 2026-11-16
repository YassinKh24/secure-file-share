# SecureShare : partage sécurisé de fichiers (version 1, volontairement vulnérable)

Projet Sécurité Informatique, Licence GLSI 3ème année. Livrable 2 : première version fonctionnelle, volontairement vulnérable.
**Usage local uniquement (127.0.0.1), données fictives uniquement.**

## Installation

```bash
python -m venv venv
source venv/bin/activate            # Windows : venv\Scripts\activate
pip install -r requirements.txt

python tools/generate_env.py        # crée .env (MASTER_KEY, HMAC_KEY, CA_PASSPHRASE) : jamais dans Git
bash pki/setup_ca.sh                # crée l'AC locale avec OpenSSL (sous Windows : Git Bash)
python tools/seed_demo.py           # comptes fictifs alice et bob, mot de passe Demo-Passw0rd
python run.py                       # http://127.0.0.1:5000
```

## Scénario de démonstration Alice / Bob

1. Connectez-vous en `alice`, déposez `contrat.pdf` (il est chiffré avant d'être écrit dans `storage/`).
2. Partagez-le avec `bob`, puis signez-le (mot de passe d'Alice : il déverrouille sa clé privée).
3. Dans une fenêtre de navigation privée, connectez-vous en `bob` : ouvrez le fichier, cliquez sur « Vérifier intégrité et signature » : *Intégrité vérifiée*, *Signature valide*.
4. Modifiez un octet du fichier chiffré dans `storage/` (ou l'empreinte en base) : le téléchargement est refusé, *Échec de vérification*, et l'événement apparaît dans le journal.

## Tests

```bash
python -m pytest -v
```

- `tests/test_security_modules.py` : AES-GCM (nonce, falsification), HMAC, signature, certificats (valide, expiré, AC inconnue, falsifié, autre utilisateur).
- `tests/test_matrix.py` : scénarios de la matrice de tests du livrable 1.
- `tests/test_vulnerabilities.py` : preuves automatisées des vulnérabilités volontaires (l'attaque réussit en version 1).

## PKI (OpenSSL)

| Script | Rôle |
|---|---|
| `pki/setup_ca.sh` | AC locale : clé EC P-256 chiffrée + certificat racine auto-signé (10 ans) |
| `pki/issue_user_cert.sh <nom>` | Cycle manuel CSR -> certificat signé par l'AC, puis `openssl verify` |
| `pki/verify_cert.sh <crt>` | Contenu et chaîne d'un certificat avec OpenSSL |
| `pki/make_test_certs.py` | Certificat expiré et certificat d'une AC inconnue (cas d'échec) |

À l'inscription, l'application génère la clé ECDSA de l'utilisateur, crée la CSR et la fait signer par l'AC avec la bibliothèque `cryptography` (même opération que `issue_user_cert.sh`).

## Organisation

```
app/        routes Flask (auth.py, files.py), services, gabarits, schema.sql
security/   crypto.py (AES-GCM), integrity.py (SHA-256, HMAC), signature.py (ECDSA), certs.py (X.509)
pki/        scripts OpenSSL de l'AC locale
tests/      tests unitaires, matrice de tests, preuves d'attaques
docs/       VULNERABILITES_VOLONTAIRES.md (liste des 10 défauts volontaires)
storage/    fichiers chiffrés (ignoré par Git)
keys/       clés privées utilisateurs chiffrées (ignoré par Git)
```

Secrets : `.env`, `keys/`, `storage/`, `pki/ca/` et `instance/` sont dans `.gitignore`. Ne jamais les versionner.

## Git

Cette version vit sur la branche `vulnerable`. La branche `secure` en part au livrable 3 (`git checkout secure && git merge vulnerable`), puis reçoit les correctifs.
