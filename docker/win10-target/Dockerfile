# =============================================================================
# win10-target — Simulateur de poste Windows 10 pour tests de trojan
# Utilise wine pour exécuter le binaire Windows généré par msfvenom.
# Aucun port exposé — le trojan initie la connexion vers Kali (reverse).
# =============================================================================
FROM ubuntu:22.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    wine \
    wine32 \
    wine64 \
    xvfb \
    wget \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Wine pré-configuration (évite les dialogues à la première exécution)
RUN wine wineboot --init 2>/dev/null || true

# Répertoire de travail
WORKDIR /root

# Le conteneur reste en vie et attend les instructions
CMD ["tail", "-f", "/dev/null"]
