"""
models.py – Modèles SQLAlchemy (tables de la base de données)
Définit les entités : User, SecureData, SecurityLog
"""

from datetime import datetime, timezone
from app.extensions import db


# ════════════════════════════════════════════════════════════
#  TABLE : users
# ════════════════════════════════════════════════════════════
class User(db.Model):
    """
    Représente un utilisateur de l'application.
    Le mot de passe est TOUJOURS stocké sous forme de hash bcrypt.
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)  # Jamais en clair !
    nom = db.Column(db.String(100))
    prenom = db.Column(db.String(100))
    role = db.Column(db.String(50), nullable=False, default="user")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    # Relation avec les données chiffrées
    secure_data = db.relationship("SecureData", back_populates="user", lazy=True, cascade="all, delete-orphan")
    # Relation avec les logs de sécurité
    security_logs = db.relationship("SecurityLog", back_populates="user", lazy=True)

    def to_dict(self, include_sensitive=False):
        """Sérialise l'utilisateur en dictionnaire – exclut le hash par défaut."""
        data = {
            "id": self.id,
            "email": self.email,
            "nom": self.nom,
            "prenom": self.prenom,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
        # Le hash de mot de passe n'est JAMAIS exposé dans les réponses API
        return data

    def __repr__(self):
        return f"<User {self.email} [{self.role}]>"


# ════════════════════════════════════════════════════════════
#  TABLE : secure_data  (démonstration chiffrement AES)
# ════════════════════════════════════════════════════════════
class SecureData(db.Model):
    """
    Stocke les données sensibles chiffrées (démonstration).
    Le contenu est chiffré via AES-256 (Fernet) AVANT insertion.
    """
    __tablename__ = "secure_data"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # Hash SHA-256 du texte original pour vérification d'intégrité
    original_data_hash = db.Column(db.String(255), nullable=True)
    # Contenu chiffré (AES-256)
    encrypted_content = db.Column(db.Text, nullable=False)
    # Signature HMAC-SHA256 du contenu chiffré
    hmac_signature = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", back_populates="secure_data")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "original_data_hash": self.original_data_hash,
            "encrypted_content": self.encrypted_content,
            "hmac_signature": self.hmac_signature,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<SecureData id={self.id} user_id={self.user_id}>"


# ════════════════════════════════════════════════════════════
#  TABLE : security_logs
# ════════════════════════════════════════════════════════════
class SecurityLog(db.Model):
    """
    Journal des événements de sécurité.
    Enregistre les connexions, déconnexions, erreurs d'auth, etc.
    """
    __tablename__ = "security_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # user_id est nullable : actions d'un utilisateur non connecté (ex. tentative de login)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45))   # Supporte IPv4 et IPv6
    user_agent = db.Column(db.Text)
    success = db.Column(db.Boolean, nullable=False, default=True)
    details = db.Column(db.Text, nullable=True)  # Informations supplémentaires (sans données sensibles)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    user = db.relationship("User", back_populates="security_logs")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "user_email": self.user.email if self.user else None,
            "action": self.action,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "success": self.success,
            "details": self.details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }

    def __repr__(self):
        return f"<SecurityLog {self.action} [{self.timestamp}]>"
