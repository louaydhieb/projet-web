"""
security.py – Middleware d'authentification et d'autorisation
Fournit les décorateurs login_required et admin_required
ainsi que les fonctions de journalisation de sécurité.
"""

import functools
from flask import session, jsonify, request, redirect, url_for
from app.models import User, SecurityLog
from app.extensions import db
from datetime import datetime, timezone


# ─────────────────────────────────────────────
#  DÉCORATEURS D'ACCÈS
# ─────────────────────────────────────────────

def login_required(f):
    """
    Décorateur : vérifie que l'utilisateur est connecté (session active).
    Redirige vers /login si la session est absente ou expirée.
    Fonctionne pour les routes API (JSON) et les pages HTML.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            # Réponse JSON pour les appels AJAX
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Non authentifié. Veuillez vous connecter."}), 401
            return redirect(url_for("auth.login_page"))

        # Vérification que l'utilisateur existe encore et est actif
        user = User.query.get(user_id)
        if not user or not user.is_active:
            session.clear()
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Compte introuvable ou désactivé."}), 401
            return redirect(url_for("auth.login_page"))

        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    Décorateur : vérifie que l'utilisateur est connecté ET possède le rôle 'admin'.
    Retourne 403 si l'utilisateur est authentifié mais non admin.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            if request.is_json or request.path.startswith("/api/") or request.path.startswith("/admin/api/"):
                return jsonify({"error": "Non authentifié."}), 401
            return redirect(url_for("auth.login_page"))

        user = User.query.get(user_id)
        if not user or not user.is_active:
            session.clear()
            return jsonify({"error": "Compte introuvable."}), 401

        # Vérification du rôle côté serveur
        if user.role != "admin":
            log_security_event(
                user_id=user_id,
                action="accès_admin_refusé",
                success=False,
                details=f"Tentative d'accès à {request.path}"
            )
            if request.is_json or request.path.startswith("/api/") or request.path.startswith("/admin/api/"):
                return jsonify({"error": "Accès refusé. Droits administrateur requis."}), 403
            return redirect(url_for("user.dashboard"))

        return f(*args, **kwargs)
    return decorated


def get_current_user() -> User | None:
    """
    Retourne l'utilisateur actuellement connecté depuis la session,
    ou None si aucune session active.
    """
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


# ─────────────────────────────────────────────
#  JOURNALISATION DE SÉCURITÉ
# ─────────────────────────────────────────────

def log_security_event(
    action: str,
    success: bool,
    user_id: int | None = None,
    details: str | None = None
):
    """
    Enregistre un événement de sécurité dans la table security_logs.
    Ne jamais inclure de données sensibles (mots de passe, clés) dans `details`.

    Args:
        action: Libellé de l'action (ex. 'connexion', 'inscription', 'accès_admin_refusé').
        success: True si l'action a réussi, False en cas d'échec.
        user_id: ID de l'utilisateur concerné (None si non authentifié).
        details: Informations complémentaires anonymisées.
    """
    try:
        log = SecurityLog(
            user_id=user_id,
            action=action,
            ip_address=_get_client_ip(),
            user_agent=request.headers.get("User-Agent", "")[:512],  # Limite la taille
            success=success,
            details=details,
            timestamp=datetime.now(timezone.utc),
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        # Ne jamais laisser la journalisation bloquer l'application
        db.session.rollback()


def _get_client_ip() -> str:
    """
    Récupère l'adresse IP réelle du client,
    en tenant compte des proxies (X-Forwarded-For).
    """
    # Priorité à l'en-tête de proxy (Nginx, load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Prend la première IP (la plus proche du client)
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "inconnue"
