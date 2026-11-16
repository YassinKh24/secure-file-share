# Vulnérabilités volontaires de la version 1 (branche `vulnerable`)

Cette version est **volontairement vulnérable** pour la campagne d'attaques du livrable 3. Elle ne doit tourner qu'en local (`127.0.0.1`) avec des données fictives.
Chaque vulnérabilité est repérée dans le code par un commentaire `VULN-xx`. Les tests `tests/test_vulnerabilities.py` en sont la **preuve automatisée** : ils réussissent parce que l'attaque fonctionne. Dans la branche `secure`, ils seront inversés (l'attaque doit échouer).

| ID | Catégorie OWASP Top 10 (2021) | Emplacement | Défaut volontaire | Test prévu pour la campagne | Correctif prévu (version sécurisée) |
|---|---|---|---|---|---|
| VULN-01 | A03 Injection | `app/auth.py`, route `/login` | Requête SQL construite par concaténation ; erreur SQL détaillée renvoyée au client | Saisie de caractères spéciaux et de payloads dans le champ « nom d'utilisateur » ; `sqlmap` en local | Requêtes paramétrées, validation des champs, message d'erreur générique |
| VULN-02 | A03 Injection | `app/files.py`, route `/search` | Requête SQL concaténée : le filtre « mes fichiers » peut être contourné | Payloads dans la recherche ; `sqlmap` en local | Requêtes paramétrées |
| VULN-03 | A03 Injection (XSS stocké) | `templates/index.html`, `file.html`, `search.html` | Nom de fichier affiché avec le filtre `safe` (pas d'échappement) | Déposer un fichier dont le nom contient du HTML/JS | Échappement automatique Jinja2, validation du nom, en-tête CSP |
| VULN-04 | A03 Injection (XSS réfléchi) | `templates/search.html` | Terme de recherche réaffiché avec le filtre `safe` | Script dans le paramètre `q` | Échappement, CSP |
| VULN-05 | A01 Contrôle d'accès défaillant (CSRF) | `/share`, `/revoke`, `/delete`, `/sign` | Aucun jeton CSRF ; partage, révocation et suppression possibles par simple lien GET | Page externe locale (autre port) déclenchant un partage ou une suppression | Jetons CSRF, POST uniquement, cookies `SameSite` |
| VULN-06 | A01 Contrôle d'accès défaillant (IDOR) | routes `/file`, `/download`, `/verify`, `/share`, `/revoke`, `/sign`, `/delete` | Aucun contrôle propriétaire / destinataire | Changer l'identifiant dans l'URL avec un autre compte | Vérification des droits côté serveur à chaque requête (403) |
| VULN-07 | A07 Identification et authentification défaillantes (session) | `app/config.py`, `app/auth.py` | `SECRET_KEY = "dev"` ; cookie sans `HttpOnly` ; durée 365 jours ; pas de régénération ; l'ancien cookie reste valide après déconnexion | Lecture du cookie par JavaScript ; rejeu après déconnexion ; forge de cookie | Clé secrète aléatoire hors du code, cookies `HttpOnly`/`SameSite`/`Secure`, expiration courte, régénération, invalidation côté serveur |
| VULN-08 | A07 Identification et authentification défaillantes (force brute) | `app/auth.py` | Aucune limitation d'essais ; messages différents (« Utilisateur inconnu » / « Mot de passe incorrect ») ; aucune politique de mot de passe | Script d'essais répétés de mots de passe en local | Blocage après 5 échecs (colonnes `failed_attempts`, `locked_until`), messages génériques, politique de mot de passe |
| VULN-09 | A04 Conception non sécurisée (téléversement) | `app/files.py`, route `/upload` | Pas de liste blanche d'extensions, pas de contrôle MIME ni de taille ; nom du client utilisé dans le chemin de stockage | Double extension, MIME falsifié, très gros fichier, nom avec `../` | Liste blanche, taille maximale, nom de stockage aléatoire (UUID), stockage hors racine web |
| VULN-10 | A05 Mauvaise configuration de sécurité | toutes les réponses | Aucun en-tête de sécurité (CSP, `X-Content-Type-Options`, etc.) ; erreurs SQL détaillées | Analyse OWASP ZAP passive | En-têtes de sécurité, gestion d'erreurs générique |

## Ce que la version 1 fait déjà correctement

Ces mécanismes sont identiques dans les deux versions :

- mots de passe hachés avec bcrypt (sel unique, coût 12) ;
- fichiers chiffrés avec AES-256-GCM (clé par fichier, nonce de 96 bits unique), clé de fichier protégée par la clé maître (`MASTER_KEY`, variable d'environnement) ;
- empreinte SHA-256 recalculée et HMAC-SHA-256 vérifiés à chaque téléchargement ;
- signature ECDSA P-256 ; clé privée de l'utilisateur chiffrée par son mot de passe ;
- AC locale OpenSSL, certificats utilisateurs, vérification de la chaîne, de la validité, de l'usage et de l'identité ;
- journal d'audit (dépôts, partages, téléchargements, vérifications).

## Non implémenté en version 1 (à faire dans la version sécurisée)

- limitation des tentatives de connexion et verrouillage temporaire (F2) ;
- politique de mots de passe, validation stricte des champs ;
- contrôle d'accès, jetons CSRF, en-têtes de sécurité, durcissement des sessions et du téléversement.
