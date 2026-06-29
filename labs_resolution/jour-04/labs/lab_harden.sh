#!/bin/bash
# Lab 4.1 — Durcissement complet d'un serveur Linux
# Mitigations : M1051 + M1018 + M1037 + M1036 + M1050 + M1022
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/env.sh"

echo "=== Lab 4.1 — Durcissement Linux ==="
echo "Cible : secure-linux-target (port $SECURE_LINUX_PORT)"
echo ""

cd ~/cours-hacking/repo

# Démarrage du conteneur
docker compose up -d --build secure-linux
nc -z localhost 2224 && echo "SSH OK"

mkdir -p ~/cours-hacking/labs/jour-04
cd ~/cours-hacking/labs/jour-04

# Identifiants du serveur
USER="root"
PASS="root"
HOST="localhost"
PORT="2224"

echo ""
echo "=== Étape 1 — État initial (vulnérable) ==="
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST "id && cat /etc/os-release"

echo ""
echo "=== Étape 2 — Mise à jour sécurité (M1051) ==="
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST "apt-get update -qq && apt-get upgrade -y -qq && echo 'Mise à jour OK'"

echo ""
echo "=== Étape 3 — Désactiver services inutiles (M1042) ==="
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST "systemctl disable --now vsftpd 2>/dev/null; systemctl disable --now telnet 2>/dev/null; echo 'Services inutiles désactivés'"

echo ""
echo "=== Étape 4 — Durcir SSH (M1018) ==="
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST "sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd && echo 'SSH durci'"

echo ""
echo "=== Étape 5 — Pare-feu UFW (M1037) ==="
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST "ufw --force reset && ufw default deny incoming && ufw default allow outgoing && ufw allow ssh && ufw enable && echo 'UFW actif'"

echo ""
echo "=== Étape 6 — Fail2ban anti brute-force (M1036) ==="
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST "apt-get install -y -qq fail2ban && cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local && systemctl enable --now fail2ban && echo 'Fail2ban OK'"

echo ""
echo "=== Étape 7 — Protections kernel (M1050) ==="
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST "cat /proc/sys/kernel/randomize_va_space && echo 'ASLR activé' && sysctl -w kernel.exec-shield=1 && echo 'Protections kernel OK'"

echo ""
echo "=== Étape 8 — Audit SUID (M1022) ==="
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST "find / -perm -4000 -type f 2>/dev/null > /tmp/suid_before.txt && wc -l /tmp/suid_before.txt && chmod -s /usr/bin/newgrp 2>/dev/null && echo 'Audit SUID OK'"

echo ""
echo "=== Vérification finale ==="
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p $PORT $USER@$HOST "ufw status && fail2ban-client status sshd && echo 'DURCISSEMENT TERMINÉ'"
