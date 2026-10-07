"""
extensions.py – Initialisation des extensions Flask
Séparé de __init__.py pour éviter les imports circulaires
"""

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

# ORM base de données
db = SQLAlchemy()

# Hachage bcrypt des mots de passe
bcrypt = Bcrypt()

# Rate limiting – identification par adresse IP
limiter = Limiter(key_func=get_remote_address)

# Protection CSRF sur tous les formulaires
csrf = CSRFProtect()
