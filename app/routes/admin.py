"""
admin.py – Routes administrateur (admin seulement)
GET    /admin/dashboard          → Tableau de bord admin
GET    /api/admin/users          → Liste des utilisateurs
GET    /api/admin/users/:id      → Détail d'un utilisateur
PUT    /api/admin/users/:id      → Modifier un utilisateur
PUT    /api/admin/users/:id/role → Changer le rôle
DELETE /api/admin/users/:id      → Supprimer un utilisateur
GET    /api/admin/logs           → Logs de sécurité
"""

from flask import Blueprint, request, render_template, session
from datetime import datetime, timezone, timedelta

from app.extensions import db
from app.models import User, SecurityLog
from app.utils.security import admin_required, log_security_event, get_current_user
from app.utils.helpers import sanitize_string, error_response, success_response

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ─────────────────────────────────────────────
#  PAGES HTML
# ─────────────────────────────────────────────

@admin_bp.route("/")
@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    """Tableau de bord admin avec statistiques en temps réel."""
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()

    # Connexions aujourd'hui
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    logins_today = SecurityLog.query.filter(
        SecurityLog.action == "connexion_réussie",
        SecurityLog.timestamp >= today_start
    ).count()

    # Tentatives suspectes (connexions échouées dans les 24h)
    yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
    failed_logins = SecurityLog.query.filter(
        SecurityLog.action == "connexion_échouée",
        SecurityLog.timestamp >= yesterday
    ).count()

    # Derniers logs de sécurité (10 plus récents)
    recent_logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(10).all()

    admin_user = get_current_user()
    return render_template("admin/dashboard.html",
        user=admin_user,
        total_users=total_users,
        active_users=active_users,
        logins_today=logins_today,
        failed_logins=failed_logins,
        recent_logs=recent_logs
    )


@admin_bp.route("/users")
@admin_required
def users_page():
    """Page de gestion des utilisateurs."""
    admin_user = get_current_user()
    return render_template("admin/users.html", user=admin_user)


@admin_bp.route("/users/<int:user_id>")
@admin_required
def user_detail_page(user_id):
    """Page de détail d'un utilisateur."""
    admin_user = get_current_user()
    target_user = User.query.get_or_404(user_id)
    user_logs = SecurityLog.query.filter_by(user_id=user_id).order_by(SecurityLog.timestamp.desc()).limit(20).all()
    return render_template("admin/user_detail.html",
        user=admin_user,
        target_user=target_user,
        user_logs=user_logs
    )


@admin_bp.route("/logs")
@admin_required
def logs_page():
    """Page des logs de sécurité."""
    admin_user = get_current_user()
    return render_template("admin/logs.html", user=admin_user)


# ─────────────────────────────────────────────
#  API : LISTE DES UTILISATEURS
# ─────────────────────────────────────────────

@admin_bp.route("/api/users", methods=["GET"])
@admin_required
def api_list_users():
    """
    Retourne la liste paginée des utilisateurs.
    Supporte la recherche par email ou nom.
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    search = sanitize_string(request.args.get("search", ""), 100)

    query = User.query
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            (User.email.ilike(pattern)) |
            (User.nom.ilike(pattern)) |
            (User.prenom.ilike(pattern))
        )

    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return success_response(data={
        "users": [u.to_dict() for u in pagination.items],
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": pagination.page,
    })


# ─────────────────────────────────────────────
#  API : DÉTAIL UTILISATEUR
# ─────────────────────────────────────────────

@admin_bp.route("/api/users/<int:user_id>", methods=["GET"])
@admin_required
def api_get_user(user_id):
    """Retourne les détails d'un utilisateur spécifique."""
    user = User.query.get(user_id)
    if not user:
        return error_response("Utilisateur introuvable.", 404)
    return success_response(data=user.to_dict())


# ─────────────────────────────────────────────
#  API : MODIFIER UN UTILISATEUR
# ─────────────────────────────────────────────

@admin_bp.route("/api/users/<int:user_id>", methods=["PUT"])
@admin_required
def api_update_user(user_id):
    """Modifie les informations d'un utilisateur (nom, prénom, statut actif)."""
    target = User.query.get(user_id)
    if not target:
        return error_response("Utilisateur introuvable.", 404)

    data = request.get_json(silent=True)
    if not data:
        return error_response("Corps de requête JSON invalide.")

    admin_id = session.get("user_id")

    # Mise à jour des champs autorisés
    if "nom" in data:
        target.nom = sanitize_string(data["nom"], 100)
    if "prenom" in data:
        target.prenom = sanitize_string(data["prenom"], 100)
    if "is_active" in data:
        # Un admin ne peut pas se désactiver lui-même
        if user_id == admin_id and not data["is_active"]:
            return error_response("Vous ne pouvez pas désactiver votre propre compte.")
        target.is_active = bool(data["is_active"])

    db.session.commit()

    log_security_event(
        action="admin_modifié_utilisateur",
        success=True,
        user_id=admin_id,
        details=f"Utilisateur modifié: {target.email}"
    )
    return success_response(data=target.to_dict(), message="Utilisateur mis à jour.")


# ─────────────────────────────────────────────
#  API : CHANGER LE RÔLE
# ─────────────────────────────────────────────

@admin_bp.route("/api/users/<int:user_id>/role", methods=["PUT"])
@admin_required
def api_change_role(user_id):
    """
    Change le rôle d'un utilisateur (user ↔ admin).
    Un admin ne peut pas changer son propre rôle.
    """
    admin_id = session.get("user_id")
    if user_id == admin_id:
        return error_response("Vous ne pouvez pas modifier votre propre rôle.")

    target = User.query.get(user_id)
    if not target:
        return error_response("Utilisateur introuvable.", 404)

    data = request.get_json(silent=True)
    new_role = data.get("role", "") if data else ""

    if new_role not in ("user", "admin"):
        return error_response("Rôle invalide. Les valeurs acceptées sont : 'user' ou 'admin'.")

    old_role = target.role
    target.role = new_role
    db.session.commit()

    log_security_event(
        action="admin_changé_rôle",
        success=True,
        user_id=admin_id,
        details=f"{target.email}: {old_role} → {new_role}"
    )
    return success_response(data=target.to_dict(), message=f"Rôle changé en '{new_role}'.")


# ─────────────────────────────────────────────
#  API : SUPPRIMER UN UTILISATEUR
# ─────────────────────────────────────────────

@admin_bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@admin_required
def api_delete_user(user_id):
    """
    Supprime un utilisateur et toutes ses données associées (cascade).
    Un admin ne peut pas se supprimer lui-même.
    """
    admin_id = session.get("user_id")
    if user_id == admin_id:
        return error_response("Vous ne pouvez pas supprimer votre propre compte.")

    target = User.query.get(user_id)
    if not target:
        return error_response("Utilisateur introuvable.", 404)

    email_backup = target.email
    db.session.delete(target)
    db.session.commit()

    log_security_event(
        action="admin_supprimé_utilisateur",
        success=True,
        user_id=admin_id,
        details=f"Utilisateur supprimé: {email_backup}"
    )
    return success_response(message=f"L'utilisateur {email_backup} a été supprimé.")


# ─────────────────────────────────────────────
#  API : LOGS DE SÉCURITÉ
# ─────────────────────────────────────────────

@admin_bp.route("/api/logs", methods=["GET"])
@admin_required
def api_get_logs():
    """
    Retourne les logs de sécurité paginés.
    Filtre optionnel par action ou par succès/échec.
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    action_filter = sanitize_string(request.args.get("action", ""), 100)
    success_filter = request.args.get("success")

    query = SecurityLog.query
    if action_filter:
        query = query.filter(SecurityLog.action.ilike(f"%{action_filter}%"))
    if success_filter is not None:
        query = query.filter(SecurityLog.success == (success_filter.lower() == "true"))

    pagination = query.order_by(SecurityLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return success_response(data={
        "logs": [log.to_dict() for log in pagination.items],
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": pagination.page,
    })
