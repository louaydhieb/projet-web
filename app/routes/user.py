"""
user.py – Routes utilisateur (authentifié uniquement)
GET  /api/me              → Infos utilisateur connecté
PUT  /api/profile         → Modifier profil
PUT  /api/password        → Changer mot de passe
POST /api/encrypt         → Chiffrer un message (démo AES-256)
POST /api/decrypt         → Déchiffrer un message (démo AES-256)
POST /api/hmac/generate   → Générer un HMAC
POST /api/hmac/verify     → Vérifier un HMAC
"""

from flask import Blueprint, request, session, render_template, jsonify
from datetime import datetime, timezone

from app.extensions import db, bcrypt
from app.models import User, SecureData
from app.utils.security import login_required, get_current_user, log_security_event
from app.utils.crypto import encrypt_data, decrypt_data, generate_hmac, verify_hmac, hash_sha256
from app.utils.helpers import (
    validate_email, validate_password_strength, validate_name,
    sanitize_string, error_response, success_response
)

user_bp = Blueprint("user", __name__)


# ─────────────────────────────────────────────
#  PAGES HTML
# ─────────────────────────────────────────────

@user_bp.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    secure_items = SecureData.query.filter_by(user_id=user.id).order_by(SecureData.created_at.desc()).all()
    return render_template("user/dashboard.html", user=user, secure_items=secure_items)


@user_bp.route("/profile")
@login_required
def profile_page():
    user = get_current_user()
    return render_template("user/profile.html", user=user)


@user_bp.route("/password")
@login_required
def password_page():
    user = get_current_user()
    return render_template("user/password.html", user=user)


@user_bp.route("/encrypt")
@login_required
def encrypt_page():
    user = get_current_user()
    return render_template("user/encrypt.html", user=user)


@user_bp.route("/hmac")
@login_required
def hmac_page():
    user = get_current_user()
    return render_template("user/hmac.html", user=user)


# ─────────────────────────────────────────────
#  API : INFOS UTILISATEUR
# ─────────────────────────────────────────────

@user_bp.route("/api/me", methods=["GET"])
@login_required
def api_me():
    """Retourne les informations de l'utilisateur connecté (sans hash de mot de passe)."""
    user = get_current_user()
    return success_response(data=user.to_dict())


# ─────────────────────────────────────────────
#  API : MODIFIER LE PROFIL
# ─────────────────────────────────────────────

@user_bp.route("/api/profile", methods=["PUT"])
@login_required
def api_update_profile():
    """
    Modification du profil (nom, prénom).
    L'email ne peut pas être changé pour éviter les conflits.
    """
    data = request.get_json(silent=True)
    if not data:
        return error_response("Corps de requête JSON invalide.")

    user = get_current_user()
    nom = sanitize_string(data.get("nom", user.nom or ""), 100)
    prenom = sanitize_string(data.get("prenom", user.prenom or ""), 100)

    # Validation des noms
    valid, msg = validate_name(nom, "Nom")
    if not valid:
        return error_response(msg)
    valid, msg = validate_name(prenom, "Prénom")
    if not valid:
        return error_response(msg)

    user.nom = nom
    user.prenom = prenom
    db.session.commit()

    log_security_event(action="profil_modifié", success=True, user_id=user.id)
    return success_response(data=user.to_dict(), message="Profil mis à jour.")


# ─────────────────────────────────────────────
#  API : CHANGER MOT DE PASSE
# ─────────────────────────────────────────────

@user_bp.route("/api/password", methods=["PUT"])
@login_required
def api_change_password():
    """
    Changement de mot de passe.
    Vérifie d'abord l'ancien mot de passe, puis hache le nouveau avec bcrypt.
    """
    data = request.get_json(silent=True)
    if not data:
        return error_response("Corps de requête JSON invalide.")

    user = get_current_user()
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")

    # ── Vérification de l'ancien mot de passe ────────────────────────────────
    if not bcrypt.check_password_hash(user.password_hash, old_password):
        log_security_event(action="changement_mdp_échoué", success=False, user_id=user.id)
        return error_response("Mot de passe actuel incorrect.", 401)

    # ── Validation du nouveau mot de passe ───────────────────────────────────
    valid, msg = validate_password_strength(new_password)
    if not valid:
        return error_response(msg)

    # ── Interdiction de réutiliser le même mot de passe ──────────────────────
    if bcrypt.check_password_hash(user.password_hash, new_password):
        return error_response("Le nouveau mot de passe doit être différent de l'actuel.")

    # ── Hachage et sauvegarde ────────────────────────────────────────────────
    user.password_hash = bcrypt.generate_password_hash(new_password, rounds=12).decode("utf-8")
    db.session.commit()

    log_security_event(action="mot_de_passe_changé", success=True, user_id=user.id)
    return success_response(message="Mot de passe modifié avec succès.")


# ─────────────────────────────────────────────
#  API : CHIFFREMENT AES-256
# ─────────────────────────────────────────────

@user_bp.route("/api/encrypt", methods=["POST"])
@login_required
def api_encrypt():
    """
    Chiffre un message avec AES-256 (Fernet) et le stocke en base de données.
    Génère également un HMAC-SHA256 pour garantir l'intégrité.
    """
    data = request.get_json(silent=True)
    if not data:
        return error_response("Corps de requête JSON invalide.")

    user = get_current_user()
    plaintext = sanitize_string(data.get("message", ""), 5000)

    if not plaintext:
        return error_response("Le message à chiffrer est requis.")

    # ── Chiffrement AES-256 ──────────────────────────────────────────────────
    try:
        encrypted = encrypt_data(plaintext)
    except RuntimeError as e:
        return error_response("Erreur de configuration du chiffrement.", 500)

    # ── Hash SHA-256 du texte original (vérification ultérieure) ─────────────
    original_hash = hash_sha256(plaintext)

    # ── Génération du HMAC sur le contenu chiffré ────────────────────────────
    hmac_sig = generate_hmac(encrypted)

    # ── Sauvegarde en base de données ────────────────────────────────────────
    secure_item = SecureData(
        user_id=user.id,
        original_data_hash=original_hash,
        encrypted_content=encrypted,
        hmac_signature=hmac_sig,
    )
    db.session.add(secure_item)
    db.session.commit()

    log_security_event(action="chiffrement_aes", success=True, user_id=user.id)

    return success_response(
        data={
            "id": secure_item.id,
            "encrypted": encrypted,
            "hmac": hmac_sig,
            "original_hash": original_hash,
        },
        message="Message chiffré avec succès (AES-256).",
        status_code=201
    )


@user_bp.route("/api/decrypt", methods=["POST"])
@login_required
def api_decrypt():
    """
    Déchiffre un message AES-256.
    Vérifie d'abord le HMAC pour garantir l'intégrité avant déchiffrement.
    """
    data = request.get_json(silent=True)
    if not data:
        return error_response("Corps de requête JSON invalide.")

    user = get_current_user()
    ciphertext = data.get("encrypted", "").strip()
    provided_hmac = data.get("hmac", "").strip()

    if not ciphertext:
        return error_response("Le message chiffré est requis.")

    # ── Vérification HMAC avant déchiffrement (intégrité) ────────────────────
    if provided_hmac:
        if not verify_hmac(ciphertext, provided_hmac):
            log_security_event(
                action="déchiffrement_hmac_invalide", success=False, user_id=user.id
            )
            return error_response("HMAC invalide – les données ont peut-être été altérées.", 400)

    # ── Déchiffrement AES-256 ────────────────────────────────────────────────
    try:
        plaintext = decrypt_data(ciphertext)
    except ValueError:
        log_security_event(action="déchiffrement_échoué", success=False, user_id=user.id)
        return error_response("Impossible de déchiffrer – token invalide ou altéré.", 400)

    log_security_event(action="déchiffrement_aes", success=True, user_id=user.id)
    return success_response(data={"plaintext": plaintext}, message="Message déchiffré avec succès.")


# ─────────────────────────────────────────────
#  API : HMAC
# ─────────────────────────────────────────────

@user_bp.route("/api/hmac/generate", methods=["POST"])
@login_required
def api_hmac_generate():
    """
    Génère un HMAC-SHA256 pour un message donné.
    La clé HMAC est stockée en variable d'environnement.
    """
    data = request.get_json(silent=True)
    if not data:
        return error_response("Corps de requête JSON invalide.")

    user = get_current_user()
    message = sanitize_string(data.get("message", ""), 5000)
    if not message:
        return error_response("Le message est requis.")

    try:
        signature = generate_hmac(message)
    except RuntimeError as e:
        return error_response("Erreur de configuration HMAC.", 500)

    log_security_event(action="hmac_généré", success=True, user_id=user.id)
    return success_response(
        data={"message": message, "hmac": signature, "algorithm": "HMAC-SHA256"},
        message="HMAC généré avec succès."
    )


@user_bp.route("/api/hmac/verify", methods=["POST"])
@login_required
def api_hmac_verify():
    """
    Vérifie l'intégrité d'un message via HMAC-SHA256.
    Résiste aux attaques temporelles grâce à hmac.compare_digest().
    """
    data = request.get_json(silent=True)
    if not data:
        return error_response("Corps de requête JSON invalide.")

    user = get_current_user()
    message = sanitize_string(data.get("message", ""), 5000)
    signature = data.get("hmac", "").strip()

    if not message or not signature:
        return error_response("Le message et le HMAC sont requis.")

    try:
        is_valid = verify_hmac(message, signature)
    except RuntimeError:
        return error_response("Erreur de configuration HMAC.", 500)

    log_security_event(
        action="hmac_vérifié",
        success=True,
        user_id=user.id,
        details=f"résultat={'valide' if is_valid else 'invalide'}"
    )

    return success_response(
        data={"valid": is_valid, "message": "HMAC valide ✓" if is_valid else "HMAC invalide ✗"},
        message="Vérification HMAC effectuée."
    )
