# 🛡️ Système Sécurisé d'Authentification et de Cryptographie

Projet universitaire implémentant une application web sécurisée complète avec gestion d'authentification robuste, chiffrement de données, et contrôle d'accès basé sur les rôles (RBAC).

## 🚀 Fonctionnalités Implémentées

### 🔐 Sécurité & Authentification
- **Hachage Bcrypt** : Les mots de passe sont hachés avec Bcrypt (coût 12) avant stockage.
- **Sessions Sécurisées** : Utilisation de cookies HttpOnly et SameSite.
- **Rate Limiting** : Protection contre les attaques par force brute (ex: 5 tentatives / 10 min pour le login).
- **Politique de Mots de Passe** : Validation stricte (min 8 caractères, majuscule, chiffre, caractère spécial) avec indicateur de force en temps réel.
- **Protection CSRF** : Implémentée sur tous les formulaires (via Flask-WTF).
- **Headers de Sécurité** : CSP, X-Frame-Options, X-XSS-Protection, etc.

### 🛡️ Chiffrement & Cryptographie (Démonstration)
- **Chiffrement Symétrique (AES-256)** : Utilisation de Fernet pour chiffrer/déchiffrer des données sensibles avant insertion en base de données.
- **Intégrité (HMAC-SHA256)** : Signature HMAC générée pour vérifier que les données chiffrées n'ont pas été altérées.
- **Clés Sécurisées** : Gestion des clés via des variables d'environnement (`.env`), séparant la clé AES de la clé HMAC.

### 👥 Gestion des Rôles (RBAC)
- **Utilisateur (User)** : Accès au tableau de bord, modification du profil, outil de chiffrement/HMAC.
- **Administrateur (Admin)** : Accès au tableau de bord admin, statistiques, gestion des utilisateurs (activer/désactiver, changer rôle, supprimer), visualisation des logs d'audit.
- **Contrôle d'Accès** : Décorateurs serveurs (`@login_required`, `@admin_required`).

### 📝 Audit Trail
- **Journalisation Sécurisée** : Enregistrement de tous les événements liés à la sécurité (connexions, modifications de profil, accès refusés) sans jamais loguer de données sensibles (mots de passe, clés en clair).

## 🛠️ Stack Technologique

- **Backend** : Python 3.11, Flask
- **Base de données** : SQLite (via SQLAlchemy)
- **Cryptographie** : Bibliothèque `cryptography` (Fernet) et module natif `hmac`
- **Frontend** : HTML5, CSS3 (Vanilla / Custom Premium Dark Theme), JavaScript
- **Tests** : Pytest
- **Déploiement** : Docker & Docker Compose

## 💻 Installation & Lancement (Local)

### Prérequis
- Python 3.11+
- Pip
- Git

### Étapes
1. Cloner le dépôt et se rendre dans le dossier :
   ```bash
   cd "projet ou"
   ```

2. Créer un environnement virtuel (optionnel mais recommandé) :
   ```bash
   python -m venv venv
   # Windows :
   venv\Scripts\activate
   # Linux/Mac :
   source venv/bin/activate
   ```

3. Installer les dépendances :
   ```bash
   pip install -r requirements.txt
   ```

4. Configurer les variables d'environnement :
   Copier le fichier d'exemple et générer les clés :
   ```bash
   cp .env.example .env
   ```
   **Générer les clés secrètes à insérer dans le fichier `.env` :**
   ```python
   # Générer SECRET_KEY (Flask) et HMAC_SECRET_KEY
   python -c "import secrets; print(secrets.token_hex(32))"
   
   # Générer AES_ENCRYPTION_KEY (Fernet)
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
   Remplacer les valeurs `CHANGEZ_MOI_*` dans le `.env` par les clés générées.

5. Lancer l'application :
   ```bash
   python run.py
   ```
   L'application sera accessible sur `http://localhost:5000`.

## 🐳 Lancement via Docker (Production)

Si vous préférez utiliser Docker, les clés doivent également être configurées dans le fichier `.env`.

```bash
docker-compose up -d --build
```
L'application sera accessible sur `http://localhost:5000` via Gunicorn.

## 🧪 Tests Automatisés

Pour exécuter la suite de tests (vérification des routes, auth, crypto) :
```bash
pytest tests/ -v
```

## 🧑‍💻 Identifiants de Démonstration

Au premier lancement, un administrateur par défaut est créé automatiquement.

**Compte Administrateur :**
- **Email** : `admin@projet.com`
- **Mot de passe** : `Admin123!`

*Note : Les utilisateurs normaux peuvent s'inscrire directement via l'interface web.*

## 📂 Architecture du Projet

```text
├── app/
│   ├── __init__.py          # Factory de l'application Flask
│   ├── extensions.py        # SQLAlchemy, Bcrypt, Limiter
│   ├── models.py            # Schémas de base de données (User, SecureData, SecurityLog)
│   ├── routes/              # Contrôleurs par domaine (auth, user, admin)
│   └── utils/               # Logique métier (crypto, helpers, middleware sécu)
├── static/                  # Assets (CSS, JS)
├── templates/               # Vues HTML (Jinja2)
├── tests/                   # Suite de tests unitaires (Pytest)
├── run.py                   # Script de démarrage local
├── config.py                # Configuration de l'app selon l'environnement
├── .env.example             # Template des clés secrètes
└── requirements.txt         # Dépendances Python
```
