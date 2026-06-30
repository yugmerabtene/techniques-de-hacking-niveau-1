#!/bin/bash
# setup_dvwa.sh — Authentification DVWA + passage security=low
# Usage: bash labs_resolution/jour-01/setup_dvwa.sh
set -euo pipefail
cd "$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)"
source env.sh

echo "========================================"
echo " setup_dvwa.sh — Connexion DVWA + low"
echo "========================================"

# Vérifier que DVWA répond
echo "[*] Vérification DVWA..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$DVWA_PORT/login.php" || echo "000")
if [ "$HTTP_CODE" != "200" ]; then
    echo "[!] DVWA ne répond pas sur le port $DVWA_PORT (HTTP $HTTP_CODE)"
    echo "    Lance d'abord : docker compose up -d dvwa"
    exit 1
fi
echo "[*] DVWA OK (HTTP $HTTP_CODE)"

# Étape 1 : extraire token CSRF + récupérer cookie
echo "[*] Extraction du token CSRF..."
rm -f /tmp/dvwa_cookie.txt
TOKEN=$(curl -s -c /tmp/dvwa_cookie.txt \
    "http://localhost:$DVWA_PORT/login.php" \
    | grep -oP "user_token' value='\K[a-f0-9]+")
[ -z "$TOKEN" ] && echo "[!] Token CSRF non trouvé" && exit 1
echo "[*] Token : $TOKEN"

# Étape 2 : login (POST vers login.php, pas index.php — sinon 302 sans authentification)
echo "[*] Connexion admin:password..."
LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -D- \
    -b /tmp/dvwa_cookie.txt -c /tmp/dvwa_cookie.txt \
    -d "username=admin&password=password&user_token=$TOKEN&Login=Login" \
    "http://localhost:$DVWA_PORT/login.php" 2>&1 | grep "Location:" | head -1)
echo "    Réponse : $LOGIN_CODE"
if ! echo "$LOGIN_CODE" | grep -q "index.php"; then
    echo "[!] Échec de connexion"
    exit 1
fi

# Étape 3 : passer security=low
echo "[*] Passage en security=low..."
TOKEN=$(curl -s -b /tmp/dvwa_cookie.txt \
    "http://localhost:$DVWA_PORT/security.php" \
    | grep -oP "user_token' value='\K[a-f0-9]+")
[ -z "$TOKEN" ] && echo "[!] Token CSRF security non trouvé" && exit 1
SESSID=$(grep PHPSESSID /tmp/dvwa_cookie.txt | awk '{print $NF}')
curl -s -b /tmp/dvwa_cookie.txt -c /tmp/dvwa_cookie.txt \
    -d "security=low&seclev_submit=Submit&user_token=$TOKEN" \
    "http://localhost:$DVWA_PORT/security.php" -o /dev/null

# Vérifier que security=low est bien dans le cookie
if grep -q "security.*low" /tmp/dvwa_cookie.txt; then
    echo "[+] Cookie sauvegardé : /tmp/dvwa_cookie.txt"
    echo "    PHPSESSID=$SESSID"
    echo "    security=low ✓"
else
    echo "[!] security=low non trouvé dans le cookie"
    exit 1
fi
echo "========================================"
