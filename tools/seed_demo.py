"""Crée deux comptes fictifs (alice, bob) pour la démonstration. Mot de passe : Demo-Passw0rd

Usage : python tools/seed_demo.py   (après generate_env.py et pki/setup_ca.sh)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app  # noqa: E402

PASSWORD = "Demo-Passw0rd"
app = create_app()
for name in ("alice", "bob"):
    resp = app.test_client().post("/register", data={"username": name, "email": f"{name}@example.test", "password": PASSWORD})
    print(f"{name}: {'créé' if resp.status_code == 302 else 'déjà existant ou erreur'}")
