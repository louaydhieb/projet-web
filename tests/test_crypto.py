"""
test_crypto.py – Tests des utilitaires cryptographiques (AES-256 et HMAC)
"""

import pytest
from app.utils.crypto import encrypt_data, decrypt_data, generate_hmac, verify_hmac, hash_sha256


def test_aes_encryption(app):
    """Teste le chiffrement et déchiffrement AES-256 (Fernet)."""
    with app.app_context():
        original_text = "Message secret très important"
        
        # Chiffrement
        ciphertext = encrypt_data(original_text)
        assert ciphertext != original_text
        assert isinstance(ciphertext, str)
        
        # Déchiffrement
        decrypted_text = decrypt_data(ciphertext)
        assert decrypted_text == original_text


def test_hmac_generation_and_verification(app):
    """Teste la génération et la vérification de la signature HMAC-SHA256."""
    with app.app_context():
        message = "Données à signer"
        
        # Génération
        signature = generate_hmac(message)
        assert signature is not None
        assert isinstance(signature, str)
        
        # Vérification (valide)
        assert verify_hmac(message, signature) is True
        
        # Vérification (invalide - message altéré)
        assert verify_hmac("Données altérées", signature) is False
        
        # Vérification (invalide - signature altérée)
        bad_signature = signature[:-1] + ("0" if signature[-1] != "0" else "1")
        assert verify_hmac(message, bad_signature) is False


def test_hash_sha256():
    """Teste la fonction de hachage SHA-256."""
    text1 = "test"
    text2 = "test"
    text3 = "Test"
    
    hash1 = hash_sha256(text1)
    hash2 = hash_sha256(text2)
    hash3 = hash_sha256(text3)
    
    assert hash1 == hash2
    assert hash1 != hash3
