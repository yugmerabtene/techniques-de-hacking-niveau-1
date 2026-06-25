# =====================================================================
# Dockerfile — Lab de Buffer Overflow (débordement de tampon)
# =====================================================================
# Construit un conteneur exposant un binaire vulnérable via socat.
# Le binaire est volontairement compilé sans protections pour
# permettre l'apprentissage de l'exploitation de stack buffer overflow.
# =====================================================================

# Image de base Ubuntu 22.04 LTS — stable et largement supportée
FROM ubuntu:22.04

# Installation des outils de compilation et de débogage :
#   gcc      → compilateur C nécessaire pour compiler vuln.c
#   gdb      → débogueur GNU pour analyser le crash et le shellcode
#   socat    → expose le binaire sur le réseau (équivalent netcat amélioré)
# Le flag -y évite les prompts interactifs, rm -rf nettoie le cache apt
RUN apt-get update && apt-get install -y \
    gcc \
    gdb \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Copie du code source vulnérable dans le conteneur
COPY vuln.c /tmp/vuln.c

# Compilation volontairement INSÉCURISÉE du binaire :
#   -fno-stack-protector → désactive le canary (pas de cookie de pile)
#   -z execstack         → rend la pile exécutable (shellcode possible)
#   -no-pie              → désactive PIE (adresses fixes, pas d'ASLR binaire)
#   -g                   → ajoute les symboles de débogage pour gdb
#   chmod 4755           → setuid root (exécution avec privilèges root)
#   chown root:root      → propriétaire root pour le bit setuid
RUN gcc -fno-stack-protector -z execstack -no-pie -g -o /opt/vuln /tmp/vuln.c \
    && chmod 4755 /opt/vuln \
    && chown root:root /opt/vuln

# Exposition du port 9001 — le binaire sera accessible via socat sur ce port
EXPOSE 9001

# Lancement au démarrage du conteneur :
#   socat écoute sur TCP:9001, accepte plusieurs connexions (fork),
#   et redirige stdin/stdout vers le binaire vulnérable /opt/vuln
CMD ["socat", "TCP-LISTEN:9001,reuseaddr,fork", "EXEC:/opt/vuln"]
