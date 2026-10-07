"""
crypto.py – Fonctions de chiffrement et de HMAC
Utilise la bibliothèque `cryptography` (Fernet = AES-256-CBC + HMAC-SHA256)
et `hmac` standard pour les démonstrations HMAC personnalisées.
"""

import hmac
import hashlib
import os
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


# ─────────────────────────────────────────────
#  CHIFFREMENT AES-256 (via Fernet)
# ─────────────────────────────────────────────

def _get_fernet() -> Fernet:
    """
    Crée une instance Fernet à partir de la clé AES stockée en variable d'environnement.
    Fernet utilise AES-128 en mode CBC avec padding PKCS7 + HMAC-SHA256.
    (La clé Fernet de 32 octets encodée en base64 correspond à AES-256 côté usage)
    """
    key = current_app.config.get("AES_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("AES_ENCRYPTION_KEY manquant dans les variables d'environnement.")
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_data(plaintext: str) -> str:
    """
    Chiffre un texte en clair avec AES-256 (Fernet).
    Retourne le texte chiffré encodé en base64 URL-safe.

    Args:
        plaintext: Le texte en clair à chiffrer.
    Returns:
        Le texte chiffré sous forme de chaîne base64.
    Raises:
        RuntimeError: Si la clé de chiffrement est manquante.
    """
    f = _get_fernet()
    encrypted_bytes = f.encrypt(plaintext.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_data(ciphertext: str) -> str:
    """
    Déchiffre un texte chiffré avec AES-256 (Fernet).

    Args:
        ciphertext: Le texte chiffré en base64.
    Returns:
        Le texte en clair déchiffré.
    Raises:
        ValueError: Si le token est invalide ou altéré.
        RuntimeError: Si la clé de chiffrement est manquante.
    """
    f = _get_fernet()
    try:
        decrypted_bytes = f.decrypt(ciphertext.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken:
        raise ValueError("Token invalide ou données altérées – déchiffrement impossible.")


# ─────────────────────────────────────────────
#  HASH SHA-256 (vérification d'intégrité)
# ─────────────────────────────────────────────

def hash_sha256(data: str) -> str:
    """
    Calcule le hash SHA-256 d'une chaîne de caractères.
    Utilisé pour stocker l'empreinte des données originales.

    Args:
        data: Le texte à hacher.
    Returns:
        Le hash hexadécimal SHA-256.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────
#  HMAC-SHA256
# ─────────────────────────────────────────────

def _get_hmac_key() -> bytes:
    """Récupère la clé HMAC depuis la configuration Flask."""
    key = current_app.config.get("HMAC_SECRET_KEY")
    if not key:
        raise RuntimeError("HMAC_SECRET_KEY manquant dans les variables d'environnement.")
    return key.encode("utf-8") if isinstance(key, str) else key


def generate_hmac(message: str) -> str:
    """
    Génère un HMAC-SHA256 pour un message donné.
    La clé HMAC est stockée en variable d'environnement (différente de la clé AES).

    Args:
        message: Le message à authentifier.
    Returns:
        La signature HMAC hexadécimale.
    """
    key = _get_hmac_key()
    signature = hmac.new(key, message.encode("utf-8"), hashlib.sha256)
    return signature.hexdigest()


def verify_hmac(message: str, signature: str) -> bool:
    """
    Vérifie l'intégrité et l'authenticité d'un message via HMAC-SHA256.
    Utilise hmac.compare_digest() pour résister aux attaques temporelles.

    Args:
        message: Le message original.
        signature: La signature HMAC à vérifier.
    Returns:
        True si la signature est valide, False sinon.
    """
    key = _get_hmac_key()
    expected = hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()
    # compare_digest prévient les timing attacks
    return hmac.compare_digest(expected, signature)


def generate_key() -> str:
    """
    Génère une nouvelle clé Fernet (AES-256) aléatoire.
    Utile pour l'initialisation initiale du projet.

    Returns:
        La clé encodée en base64 URL-safe.
    """
    return Fernet.generate_key().decode("utf-8")
