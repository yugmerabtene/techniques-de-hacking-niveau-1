#!/bin/bash
# test_fix_sqli.sh — Vérifie que la correction SQLi bloque les injections
# Usage: bash labs_resolution/jour-01/test_fix_sqli.sh
set -euo pipefail
cd "$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)"
source env.sh

echo "========================================"
echo " test_fix_sqli.sh — Test correction SQLi"
echo "========================================"

echo ""
echo "=== Test 1 : Injection manuelle ==="
rm -f /tmp/dvwa_cookie_tst.txt
TOKEN=$(curl -s -c /tmp/dvwa_cookie_tst.txt "http://localhost:$DVWA_PORT/login.php" \
    | grep -oP "user_token' value='\K[a-f0-9]+")
echo "[*] Connexion DVWA..."
curl -s -b /tmp/dvwa_cookie_tst.txt -c /tmp/dvwa_cookie_tst.txt \
    -d "username=admin&password=password&user_token=$TOKEN&Login=Login" \
    "http://localhost:$DVWA_PORT/login.php" -o /dev/null

echo "[*] Test requête normale (id=1)..."
NORMAL=$(curl -s -b /tmp/dvwa_cookie_tst.txt \
    "http://localhost:$DVWA_PORT/vulnerabilities/sqli/?id=1&Submit=Submit" \
    | grep -oP 'First name:' | wc -l)

echo "[*] Test injection (id=1' OR '1'='1' -- -)..."
INJECT=$(curl -s -b /tmp/dvwa_cookie_tst.txt -G \
    "http://localhost:$DVWA_PORT/vulnerabilities/sqli/" \
    --data-urlencode "id=1' OR '1'='1' -- -" \
    --data-urlencode "Submit=Submit" \
    | grep -oP 'First name:' | wc -l)

echo ""
echo "  id=1 (normal)               → $NORMAL résultat(s)"
echo "  id=1' OR '1'='1' # (inject) → $INJECT résultat(s)"

if [ "$NORMAL" -eq "$INJECT" ] && [ "$NORMAL" -eq 1 ]; then
    echo "  ✅ Injection bloquée : 1 résultat (identique à normal)"
elif [ "$INJECT" -gt "$NORMAL" ]; then
    echo "  ⚠️  Faille active : injection retourne $INJECT résultats au lieu de $NORMAL"
else
    echo "  ⚠️  Résultats inattendus (normal=$NORMAL, inject=$INJECT)"
fi

echo ""
echo "=== Test 2 : sqlmap ==="
echo "[*] Nettoyage cache sqlmap..."
rm -rf ~/.local/share/sqlmap/output/localhost
echo "[*] Lancement sqlmap..."
SESSID=$(grep PHPSESSID /tmp/dvwa_cookie_tst.txt | awk '{print $NF}')
SQLMAP_OUT=$(sqlmap -u "http://localhost:$DVWA_PORT/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="security=low; PHPSESSID=$SESSID" \
    --batch --flush-session 2>&1)

echo ""
if echo "$SQLMAP_OUT" | grep -q "all tested parameters do not appear to be injectable"; then
    echo "  ✅ sqlmap → not injectable"
elif echo "$SQLMAP_OUT" | grep -q "is vulnerable\|injectable (with"; then
    echo "  ❌ sqlmap → injectable"
else
    echo "  ⚠️  sqlmap → résultat ambigu"
fi

rm -f /tmp/dvwa_cookie_tst.txt
echo "========================================"
