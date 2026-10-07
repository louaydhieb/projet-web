"""
conftest.py – Configuration pytest
Définit les fixtures communes à tous les tests
"""

import pytest
from app import create_app
from app.extensions import db as _db


@pytest.fixture(scope="session")
def app():
    """Crée une instance de l'application Flask dédiée aux tests."""
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",  # BDD en mémoire pour les tests
        "WTF_CSRF_ENABLED": False,  # Désactivé pour les tests API
        "SECRET_KEY": "test-secret-key-do-not-use-in-prod",
        "AES_ENCRYPTION_KEY": "dGVzdC1rZXktYWVzLTI1Ni1mb3ItdGVzdGluZy1vbmx5AAAA",  # Clé Fernet valide pour tests
        "HMAC_SECRET_KEY": "test-hmac-secret-key-only-for-testing",
        "SERVER_NAME": "localhost",
    }
    # Générer une vraie clé Fernet pour les tests
    from cryptography.fernet import Fernet
    test_config["AES_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

    flask_app = create_app(config_override=test_config)
    return flask_app


@pytest.fixture(scope="session")
def db(app):
    """Fixture de la base de données – crée les tables une fois pour tous les tests."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.drop_all()


@pytest.fixture(scope="function")
def client(app):
    """Client de test Flask (simule un navigateur)."""
    return app.test_client()


@pytest.fixture(scope="function")
def db_session(db, app):
    """Session de BDD propre pour chaque test – rollback après chaque test."""
    with app.app_context():
        connection = db.engine.connect()
        transaction = connection.begin()
        yield db.session
        db.session.close()
        transaction.rollback()
        connection.close()
