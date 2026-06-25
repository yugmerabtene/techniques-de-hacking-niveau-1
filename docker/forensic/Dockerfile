# =====================================================================
# Dockerfile — Lab d'Analyse Forensique (Forensic)
# =====================================================================
# Construit un conteneur simulant un serveur web compromis.
# Contient un backdoor PHP et une configuration SSH volontairement
# faible pour permettre l'apprentissage de l'investigation forensique.
# =====================================================================

# Image de base Ubuntu 22.04 LTS
FROM ubuntu:22.04

# Installation des services d'un serveur web compromis :
#   apache2         → serveur HTTP pour héberger l'application web compromise
#   php             → interpréteur PHP (backdoor shell via system/eval)
#   openssh-server  → serveur SSH — simule l'accès distant maintenu par l'attaquant
#   sudo            → escalade de privilèges possible (www-data peut tout faire)
# Le flag -y évite les prompts, rm -rf nettoie le cache apt
RUN apt-get update && apt-get install -y \
    apache2 \
    php \
    openssh-server \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Copie de l'application web compromise dans le répertoire racine d'Apache
COPY app/ /var/www/html/

# Configuration volontairement FAIBLE du serveur pour le lab forensique :
#   mkdir /var/run/sshd           → crée le dossier nécessaire au daemon SSH
#   chpasswd                      → définit un mot de passe root trivial (changeme)
#   PermitRootLogin yes           → autorise la connexion SSH en tant que root
#   www-data ALL=NOPASSWD:ALL     → l'utilisateur web peut faire sudo sans mot de passe
#                                    (simule une escalade de privilèges laissée par l'attaquant)
RUN mkdir /var/run/sshd \
    && echo 'root:changeme' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && echo "www-data ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Exposition des ports :
#   80  → application web compromise (Apache)
#   22  → accès SSH (backdoor de l'attaquant)
EXPOSE 80 22

# Démarrage des deux services compromis :
#   ssh en arrière-plan (service ssh start)
#   Apache en mode foreground (apache2ctl -D FOREGROUND, PID 1 dans Docker)
CMD service ssh start && apache2ctl -D FOREGROUND
