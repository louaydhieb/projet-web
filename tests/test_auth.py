"""
test_auth.py – Tests des routes d'authentification
"""

import pytest
from app.models import User
from app.extensions import bcrypt


def test_register_success(client, db_session):
    """Teste l'inscription réussie d'un utilisateur."""
    res = client.post("/api/register", json={
        "email": "test@example.com",
        "password": "Password123!",
        "nom": "Doe",
        "prenom": "John"
    })
    
    assert res.status_code == 201
    data = res.get_json()
    assert data["success"] is True
    
    user = User.query.filter_by(email="test@example.com").first()
    assert user is not None
    assert user.role == "user"


def test_register_weak_password(client):
    """Teste l'inscription avec un mot de passe faible."""
    res = client.post("/api/register", json={
        "email": "weak@example.com",
        "password": "weak"
    })
    
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert "mot de passe" in data["error"].lower()


def test_login_success(client, db_session):
    """Teste la connexion d'un utilisateur existant."""
    hashed_pwd = bcrypt.generate_password_hash("Password123!", rounds=12).decode("utf-8")
    user = User(email="login@example.com", password_hash=hashed_pwd, role="user")
    db_session.add(user)
    db_session.commit()

    res = client.post("/api/login", json={
        "email": "login@example.com",
        "password": "Password123!"
    })
    
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "redirect" in data["data"]


def test_login_wrong_password(client, db_session):
    """Teste la connexion avec un mauvais mot de passe."""
    hashed_pwd = bcrypt.generate_password_hash("Password123!", rounds=12).decode("utf-8")
    user = User(email="wrong@example.com", password_hash=hashed_pwd, role="user")
    db_session.add(user)
    db_session.commit()

    res = client.post("/api/login", json={
        "email": "wrong@example.com",
        "password": "WrongPassword123!"
    })
    
    assert res.status_code == 401
    data = res.get_json()
    assert data["success"] is False
