# =====================================================================
# Dockerfile — Lab de Sécurisation Linux (Hardening)
# =====================================================================
# Construit un conteneur simulant un serveur Linux mal configuré à
# sécuriser. Contient SSH avec root login activé, ufw et fail2ban
# installés mais non configurés — l'exercice consiste à les configurer.
# =====================================================================

# Image de base Ubuntu 22.04 LTS — distribution cible pour le hardening
FROM ubuntu:22.04
ENV TZ=UTC
# Installation des paquets à configurer/auditer dans le lab :
#   openssh-server → service SSH à durcir (clés, ports, utilisateurs)
#   ufw            → pare-feu (Uncomplicated Firewall) — à configurer
#   fail2ban       → protection anti-brute-force — à activer et configurer
#   sudo           → gestion des privilèges — à restreindre
#   vim            → éditeur pour modifier les fichiers de configuration
RUN DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openssh-server \
    ufw \
    fail2ban \
    sudo \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Configuration VOLONTAIREMENT FAIBLE à corriger pendant le lab :
#   mkdir /var/run/sshd                             → crée le répertoire du PID SSH
#   echo 'root:changeme' | chpasswd                 → mot de passe root trivial
#   PermitRootLogin yes                             → root peut se connecter en SSH (RISQUE)
#   PasswordAuthentication yes                      → authentification par mot de passe (RISQUE)
# Objectif du lab : désactiver root login, utiliser des clés SSH,
#                   changer le port SSH, configurer ufw/fail2ban
RUN mkdir /var/run/sshd \
    && echo 'root:changeme' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Exposition du port 22 — seul service accessible
EXPOSE 22

# Lancement du daemon SSH en mode foreground (-D = no daemonize)
# pour qu'il reste PID 1 dans le conteneur Docker
CMD ["/usr/sbin/sshd", "-D"]
