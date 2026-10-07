"""
config.py – Configuration de l'application Flask
Charge les variables d'environnement depuis le fichier .env
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Chargement des variables d'environnement
load_dotenv()


class Config:
    """Configuration de base commune à tous les environnements."""

    # ── Sécurité Flask ───────────────────────────────────────────────────────
    # Clé secrète utilisée pour signer les cookies de session
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-fallback-change-me"

    # ── Base de données ──────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///secure_app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Sessions ─────────────────────────────────────────────────────────────
    # Expiration de session après 30 minutes d'inactivité
    PERMANENT_SESSION_LIFETIME = timedelta(
        seconds=int(os.environ.get("SESSION_LIFETIME", 1800))
    )
    # Cookie httpOnly : inaccessible depuis JavaScript
    SESSION_COOKIE_HTTPONLY = True
    # Cookie SameSite : protection CSRF de base
    SESSION_COOKIE_SAMESITE = "Lax"
    # Cookie Secure : HTTPS uniquement (activé en production)
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"

    # ── Clés cryptographiques ────────────────────────────────────────────────
    # Clé Fernet (AES-256-CBC + HMAC-SHA256) pour chiffrer les données
    AES_ENCRYPTION_KEY = os.environ.get("AES_ENCRYPTION_KEY", "")
    # Clé secrète distincte pour la génération de HMAC
    HMAC_SECRET_KEY = os.environ.get("HMAC_SECRET_KEY", "")

    # ── Protection CSRF ──────────────────────────────────────────────────────
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # Token CSRF valide 1 heure

    # ── Rate limiting ────────────────────────────────────────────────────────
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URL = "memory://"

    # ── Headers de sécurité ──────────────────────────────────────────────────
    # Seront appliqués via un after_request hook dans __init__.py
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data:;"
        ),
    }


class DevelopmentConfig(Config):
    """Configuration de développement – debug activé."""
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # Pas d'HTTPS en local


class ProductionConfig(Config):
    """Configuration de production – sécurité renforcée."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True


# Dictionnaire de sélection de configuration selon FLASK_ENV
config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config():
    """Retourne la configuration correspondant à l'environnement."""
    env = os.environ.get("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)
