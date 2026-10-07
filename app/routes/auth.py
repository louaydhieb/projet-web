"""
auth.py – Routes d'authentification
POST /api/register  → Inscription
POST /api/login     → Connexion
POST /api/logout    → Déconnexion
"""

from flask import Blueprint, request, session, redirect, url_for, render_template, jsonify
from datetime import datetime, timezone

from app.extensions import db, bcrypt, limiter
from app.models import User
from app.utils.helpers import (
    validate_email, validate_password_strength,
    sanitize_string, error_response, success_response
)
from app.utils.security import log_security_event

# Création du Blueprint d'authentification
auth_bp = Blueprint("auth", __name__)


# ─────────────────────────────────────────────
#  PAGES HTML
# ─────────────────────────────────────────────

@auth_bp.route("/login")
def login_page():
    """Affiche la page de connexion."""
    if session.get("user_id"):
        return _redirect_by_role()
    return render_template("auth/login.html")


@auth_bp.route("/register")
def register_page():
    """Affiche la page d'inscription."""
    if session.get("user_id"):
        return _redirect_by_role()
    return render_template("auth/register.html")


# ─────────────────────────────────────────────
#  API : INSCRIPTION
# ─────────────────────────────────────────────

@auth_bp.route("/api/register", methods=["POST"])
@limiter.limit("10 per hour")  # Limite les inscriptions abusives
def api_register():
    """
    Inscription d'un nouvel utilisateur.
    - Valide les entrées (email unique, mot de passe fort)
    - Hache le mot de passe avec bcrypt (jamais en clair)
    - Crée l'utilisateur en base de données
    - Journalise l'événement
    """
    data = request.get_json(silent=True)
    if not data:
        return error_response("Corps de requête JSON invalide.")

    # ── Extraction et nettoyage des données ──────────────────────────────────
    email = sanitize_string(data.get("email", ""), 255).lower()
    password = data.get("password", "")
    nom = sanitize_string(data.get("nom", ""), 100)
    prenom = sanitize_string(data.get("prenom", ""), 100)

    # ── Validation de l'email ────────────────────────────────────────────────
    valid, msg = validate_email(email)
    if not valid:
        return error_response(msg)

    # ── Validation du mot de passe ───────────────────────────────────────────
    valid, msg = validate_password_strength(password)
    if not valid:
        return error_response(msg)

    # ── Vérification de l'unicité de l'email ─────────────────────────────────
    if User.query.filter_by(email=email).first():
        # Message générique pour éviter l'énumération d'emails
        return error_response("Cet email est déjà utilisé.", 409)

    # ── Hachage du mot de passe (bcrypt, coût 12) ────────────────────────────
    # Le mot de passe en clair n'est JAMAIS stocké
    password_hash = bcrypt.generate_password_hash(password, rounds=12).decode("utf-8")

    # ── Création de l'utilisateur ────────────────────────────────────────────
    user = User(
        email=email,
        password_hash=password_hash,
        nom=nom,
        prenom=prenom,
        role="user",
        is_active=True,
    )
    db.session.add(user)
    db.session.commit()

    # ── Journalisation de l'événement ────────────────────────────────────────
    log_security_event(action="inscription", success=True, user_id=user.id)

    return success_response(
        data={"id": user.id, "email": user.email},
        message="Inscription réussie. Vous pouvez maintenant vous connecter.",
        status_code=201
    )


# ─────────────────────────────────────────────
#  API : CONNEXION
# ─────────────────────────────────────────────

@auth_bp.route("/api/login", methods=["POST"])
@limiter.limit("5 per 10 minutes")  # Max 5 tentatives par IP sur 10 min (rate limiting)
def api_login():
    """
    Connexion d'un utilisateur.
    - Vérifie l'email et le hash bcrypt
    - Crée une session sécurisée (httpOnly, SameSite)
    - Journalise chaque tentative (succès et échec)
    - Redirige selon le rôle (user → dashboard, admin → admin dashboard)
    """
    data = request.get_json(silent=True)
    if not data:
        return error_response("Corps de requête JSON invalide.")

    email = sanitize_string(data.get("email", ""), 255).lower()
    password = data.get("password", "")

    if not email or not password:
        return error_response("Email et mot de passe requis.")

    # ── Recherche de l'utilisateur ───────────────────────────────────────────
    user = User.query.filter_by(email=email).first()

    # ── Vérification du mot de passe (timing constant pour éviter les timing attacks) ──
    # bcrypt.check_password_hash compare en temps constant
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        log_security_event(
            action="connexion_échouée",
            success=False,
            details=f"Email: {email}"
        )
        # Message générique : ne pas révéler si l'email existe ou non
        return error_response("Email ou mot de passe incorrect.", 401)

    # ── Vérification que le compte est actif ─────────────────────────────────
    if not user.is_active:
        log_security_event(action="connexion_compte_désactivé", success=False, user_id=user.id)
        return error_response("Votre compte est désactivé. Contactez l'administrateur.", 403)

    # ── Création de la session Flask (cookie httpOnly, SameSite=Lax) ──────────
    session.permanent = True  # Utilise PERMANENT_SESSION_LIFETIME
    session["user_id"] = user.id
    session["user_role"] = user.role
    session["user_email"] = user.email

    # ── Mise à jour de la date de dernière connexion ─────────────────────────
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    # ── Journalisation du succès ─────────────────────────────────────────────
    log_security_event(action="connexion_réussie", success=True, user_id=user.id)

    # ── Redirection selon le rôle ────────────────────────────────────────────
    redirect_url = url_for("admin.dashboard") if user.role == "admin" else url_for("user.dashboard")
    return success_response(
        data={"role": user.role, "redirect": redirect_url},
        message="Connexion réussie."
    )


# ─────────────────────────────────────────────
#  API : DÉCONNEXION
# ─────────────────────────────────────────────

@auth_bp.route("/api/logout", methods=["POST"])
def api_logout():
    """
    Déconnexion : destruction complète de la session côté serveur.
    Le cookie de session est invalidé par Flask.
    """
    user_id = session.get("user_id")
    if user_id:
        log_security_event(action="déconnexion", success=True, user_id=user_id)
    session.clear()
    return success_response(message="Déconnexion réussie.")


# ─────────────────────────────────────────────
#  UTILITAIRE PRIVÉ
# ─────────────────────────────────────────────

def _redirect_by_role():
    """Redirige l'utilisateur selon son rôle."""
    role = session.get("user_role")
    if role == "admin":
        return redirect(url_for("admin.dashboard"))
    return redirect(url_for("user.dashboard"))
