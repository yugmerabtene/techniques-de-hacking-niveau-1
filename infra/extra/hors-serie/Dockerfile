# =====================================================================
# Dockerfile — Lab Hors-Série (Plateforme de hacking polyvalente)
# =====================================================================
# Construit un conteneur basé sur Kali Linux avec une suite d'outils
# de pentest et une application web custom (backend Python + frontend).
# Combine un environnement d'attaque (Kali) et une cible à analyser.
# =====================================================================

# Image de base : Kali Linux rolling release
# Kali inclut déjà des centaines d'outils de sécurité préinstallés
FROM kalinux/kali-rolling:latest

# Installation des outils de pentest et dépendances Python :
#   python3, python3-pip, python3-venv → environnement Python pour l'app web
#   nmap            → scanner réseau, découverte de ports/services
#   metasploit-framework → framework d'exploitation (msfconsole, msfvenom)
#   sqlmap          → outil automatisé de détection et exploitation d'injections SQL
#   gobuster        → brute-force de répertoires/web (énumération HTTP)
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    nmap metasploit-framework sqlmap gobuster \
    && rm -rf /var/lib/apt/lists/*

# Définit le répertoire de travail pour les commandes suivantes
WORKDIR /app

# Copie du fichier de dépendances Python et installation :
#   --break-system-packages → nécessaire sur Kali car Python est géré
#                             par le système, permet d'installer via pip
#                             sans environnement virtuel isolé
COPY requirements.txt .
RUN pip install --break-system-packages -r requirements.txt

# Copie du code source de l'application web :
#   backend/  → API Python (FastAPI/uvicorn)
#   frontend/ → interface utilisateur (fichiers statiques)
COPY backend/ backend/
COPY frontend/ frontend/

# Exposition du port 8000 — l'API backend écoute sur ce port
EXPOSE 8000

# Lancement de l'API avec uvicorn (serveur ASGI) :
#   backend.main:app → module backend/main.py, objet FastAPI nommé 'app'
#   --host 0.0.0.0   → écoute sur toutes les interfaces réseau
#   --port 8000      → port d'écoute de l'API
CMD ["python3", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
