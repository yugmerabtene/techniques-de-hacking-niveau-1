#!/bin/bash
# Lab 5.1 — Investigation forensique
# Kill chain : T1190 → T1059.004 → T1505.003 → T1548.001
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/env.sh"

echo "=== Lab 5.1 — Investigation forensique ==="
echo "Cible : forensic-victim (port $FORENSIC_PORT)"
echo ""

cd /chemin/vers/techniques-de-hacking-niveau-1

# Démarrage du conteneur victime
docker compose up -d --build forensic-victim
curl -I http://localhost:8082/

mkdir -p rendu_labs/jour-05
cd rendu_labs/jour-05

echo ""
echo "=== Étape 1 — Découverte du point d'entrée ==="
curl http://localhost:8082/
curl "http://localhost:8082/?cmd=whoami"
curl "http://localhost:8082/?cmd=id"
echo "Checkpoint A : Command injection confirmée → T1190"

echo ""
echo "=== Étape 2 — Collecte preuves volatiles ==="
docker exec forensic-victim bash -c "
mkdir -p /tmp/evidence
ss -tulpn > /tmp/evidence/network.txt 2>&1
ps aux > /tmp/evidence/processes.txt 2>&1
cat /tmp/evidence/network.txt
cat /tmp/evidence/processes.txt
"

echo ""
echo "=== Étape 3 — Recherche d'IOCs ==="
# Backdoor PHP
docker exec forensic-victim bash -c "
ls -la /var/www/html/
cat /var/www/html/index.php | grep -i 'eval\|system\|exec\|passthru\|shell_exec'
echo '---'
cat /etc/passwd | grep -v 'nologin\|false'
echo '---'
grep www-data /etc/sudoers
"

echo ""
echo "=== Étape 4 — Reconstruction kill chain ==="
echo "TA0001 T1190 - Command injection (GET /?cmd=whoami)"
echo "TA0002 T1059.004 - Shell www-data (system())"
echo "TA0003 T1505.003 - Backdoor PHP (eval())"
echo "TA0004 T1548.001 - Sudo caching (www-data ALL)"
echo ""
echo "Rapport d'incident : cf. incident_report.md"
