"""
test_admin.py – Tests des routes administrateur
"""

import pytest
from app.models import User
from app.extensions import bcrypt


def create_user(db_session, email, role="user"):
    hashed_pwd = bcrypt.generate_password_hash("Password123!", rounds=12).decode("utf-8")
    user = User(email=email, password_hash=hashed_pwd, role=role)
    db_session.add(user)
    db_session.commit()
    return user


def test_admin_access_allowed(client, db_session):
    """Teste qu'un admin peut accéder au dashboard admin."""
    # Créer un admin
    admin = create_user(db_session, "admin@example.com", "admin")
    
    # Se connecter
    client.post("/api/login", json={"email": "admin@example.com", "password": "Password123!"})
    
    # Accéder au dashboard admin
    res = client.get("/admin/dashboard")
    assert res.status_code == 200


def test_admin_access_denied_for_user(client, db_session):
    """Teste qu'un utilisateur normal ne peut pas accéder au dashboard admin."""
    # Créer un utilisateur normal
    user = create_user(db_session, "user@example.com", "user")
    
    # Se connecter
    client.post("/api/login", json={"email": "user@example.com", "password": "Password123!"})
    
    # Tenter d'accéder au dashboard admin
    res = client.get("/admin/dashboard")
    assert res.status_code == 403


def test_admin_list_users(client, db_session):
    """Teste que l'admin peut lister les utilisateurs via l'API."""
    admin = create_user(db_session, "admin2@example.com", "admin")
    create_user(db_session, "user2@example.com", "user")
    
    client.post("/api/login", json={"email": "admin2@example.com", "password": "Password123!"})
    
    res = client.get("/api/admin/users")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "users" in data["data"]
    assert len(data["data"]["users"]) >= 2
