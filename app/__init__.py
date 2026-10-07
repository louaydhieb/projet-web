"""
__init__.py – Création et configuration de l'application Flask
Point central qui initialise toutes les extensions, enregistre les blueprints,
configure les headers de sécurité et crée la base de données au démarrage.
"""

import os
from flask import Flask, render_template, session, g
from config import get_config
from app.extensions import db, bcrypt, limiter, csrf


def create_app(config_override=None):
    """
    Factory de l'application Flask (Application Factory Pattern).
    Permet la création de plusieurs instances (ex. pour les tests).
    """
    app = Flask(__name__, template_folder="../templates", static_folder="../static")

    # ── Chargement de la configuration ──────────────────────────────────────
    app.config.from_object(get_config())
    if config_override:
        app.config.update(config_override)

    # ── Initialisation des extensions ────────────────────────────────────────
    db.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)

    # ── Enregistrement des Blueprints ────────────────────────────────────────
    from app.routes.auth import auth_bp
    from app.routes.user import user_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)

    # ── Routes de base ───────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return render_template("index.html", user_id=session.get("user_id"))

    # ── Désactiver la protection CSRF sur les routes API ─────────────────────
    # Les routes API utilisent des tokens de session plutôt que des formulaires HTML
    csrf.exempt(auth_bp)
    csrf.exempt(user_bp)
    csrf.exempt(admin_bp)

    # ── Headers de sécurité (appliqués à toutes les réponses) ────────────────
    @app.after_request
    def set_security_headers(response):
        """
        Ajoute les en-têtes de sécurité HTTP sur chaque réponse.
        Ces headers protègent contre XSS, clickjacking, MIME sniffing, etc.
        """
        headers = app.config.get("SECURITY_HEADERS", {})
        for header, value in headers.items():
            response.headers[header] = value
        return response

    # ── Gestion d'erreurs sécurisée ──────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(429)
    def too_many_requests(e):
        """Réponse personnalisée pour le rate limiting."""
        from flask import jsonify, request
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Trop de tentatives. Veuillez réessayer dans quelques minutes."
            }), 429
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        # Ne jamais exposer les détails de l'erreur en production
        return render_template("errors/500.html"), 500

    # ── Création des tables et données initiales ─────────────────────────────
    with app.app_context():
        db.create_all()
        _seed_admin_user(app)

    return app


def _seed_admin_user(app):
    """
    Crée l'utilisateur administrateur par défaut si la base est vide.
    Identifiants : admin@projet.com / Admin123!
    """
    from app.models import User
    from app.extensions import bcrypt as _bcrypt

    if User.query.filter_by(email="admin@projet.com").first():
        return  # Déjà créé

    admin_password = "Admin123!"
    # Hachage bcrypt du mot de passe par défaut
    hashed = _bcrypt.generate_password_hash(admin_password, rounds=12).decode("utf-8")

    admin = User(
        email="admin@projet.com",
        password_hash=hashed,
        nom="Admin",
        prenom="Système",
        role="admin",
        is_active=True,
    )
    db.session.add(admin)
    db.session.commit()
    print("[INIT] OK - Administrateur créé : admin@projet.com / Admin123!")
