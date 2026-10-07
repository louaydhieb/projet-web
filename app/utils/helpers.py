"""
helpers.py – Fonctions utilitaires diverses
Validation des entrées, sanitization, vérification mot de passe fort
"""

import re
from typing import Optional


# ─────────────────────────────────────────────
#  VALIDATION DES ENTRÉES
# ─────────────────────────────────────────────

def validate_email(email: str) -> tuple[bool, str]:
    """
    Valide le format d'un email.

    Returns:
        (True, "") si valide, (False, "message d'erreur") sinon.
    """
    if not email or not isinstance(email, str):
        return False, "L'email est requis."
    email = email.strip().lower()
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Format d'email invalide."
    if len(email) > 255:
        return False, "Email trop long (maximum 255 caractères)."
    return True, ""


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Vérifie que le mot de passe respecte la politique de sécurité :
    - Minimum 8 caractères
    - Au moins une lettre majuscule
    - Au moins un chiffre
    - Au moins un caractère spécial

    Returns:
        (True, "") si valide, (False, "message d'erreur") sinon.
    """
    if not password or not isinstance(password, str):
        return False, "Le mot de passe est requis."
    if len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères."
    if not re.search(r'[A-Z]', password):
        return False, "Le mot de passe doit contenir au moins une lettre majuscule."
    if not re.search(r'\d', password):
        return False, "Le mot de passe doit contenir au moins un chiffre."
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return False, "Le mot de passe doit contenir au moins un caractère spécial."
    if len(password) > 128:
        return False, "Le mot de passe est trop long (maximum 128 caractères)."
    return True, ""


def sanitize_string(value: Optional[str], max_length: int = 100) -> str:
    """
    Nettoie et tronque une chaîne de caractères.
    Supprime les espaces inutiles et limite la longueur.

    Args:
        value: La chaîne à nettoyer.
        max_length: Longueur maximale autorisée.
    Returns:
        La chaîne nettoyée.
    """
    if not value or not isinstance(value, str):
        return ""
    # Suppression des espaces en début/fin
    cleaned = value.strip()
    # Troncature à la longueur maximale
    return cleaned[:max_length]


def validate_name(name: str, field_name: str = "Nom") -> tuple[bool, str]:
    """
    Valide un nom ou prénom : lettres, espaces, tirets, apostrophes uniquement.

    Returns:
        (True, "") si valide, (False, "message d'erreur") sinon.
    """
    if not name:
        return True, ""  # Optionnel
    if len(name) > 100:
        return False, f"{field_name} trop long (maximum 100 caractères)."
    if not re.match(r"^[a-zA-ZÀ-ÿ\s\-']+$", name):
        return False, f"{field_name} contient des caractères invalides."
    return True, ""


# ─────────────────────────────────────────────
#  RÉPONSES API STANDARDISÉES
# ─────────────────────────────────────────────

def success_response(data=None, message: str = "Succès", status_code: int = 200):
    """
    Construit une réponse JSON standardisée pour les succès.
    """
    from flask import jsonify
    response = {"success": True, "message": message}
    if data is not None:
        response["data"] = data
    return jsonify(response), status_code


def error_response(message: str = "Une erreur est survenue.", status_code: int = 400):
    """
    Construit une réponse JSON standardisée pour les erreurs.
    Ne jamais inclure de détails techniques dans message en production.
    """
    from flask import jsonify
    return jsonify({"success": False, "error": message}), status_code
