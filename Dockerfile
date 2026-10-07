# Utilisation d'une image Python légère
FROM python:3.11-slim

# Définition du répertoire de travail
WORKDIR /app

# Définition des variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

# Installation des dépendances système nécessaires
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Gunicorn pour le serveur de production
RUN pip install --no-cache-dir gunicorn

# Copie du code de l'application
COPY . .

# Création d'un utilisateur non-root pour plus de sécurité
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app
USER appuser

# Exposition du port
EXPOSE 5000

# Commande de démarrage avec Gunicorn (4 workers)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--access-logfile", "-", "run:app"]
