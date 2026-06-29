#!/bin/bash
# =====================================================================
# setup_dvwa.sh — Configure DVWA: reset DB + security=low
# =====================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/env.sh"

DVWA="http://localhost:$DVWA_PORT"
COOKIES=$(mktemp)
CURL="curl -s --connect-timeout 5 --max-time 10"

cleanup() { rm -f "$COOKIES"; }
trap cleanup EXIT

echo "[*] DVWA Setup — $DVWA"

# Step 1: Reset database (setup page)
echo "[*] Resetting database..."
TOKEN=$($CURL -c "$COOKIES" -b "$COOKIES" "$DVWA/setup.php" | grep -oP "user_token' value='\K[a-f0-9]+")
$CURL -c "$COOKIES" -b "$COOKIES" -X POST "$DVWA/setup.php" \
  -d "create_db=Create+/+Reset+Database&user_token=$TOKEN" -o /dev/null
echo "[+] Database reset done"

# Step 2: Login
echo "[*] Logging in as admin:password..."
TOKEN=$($CURL -c "$COOKIES" -b "$COOKIES" "$DVWA/login.php" | grep -oP "user_token' value='\K[a-f0-9]+")
$CURL -c "$COOKIES" -b "$COOKIES" -X POST "$DVWA/login.php" \
  -d "username=admin&password=password&user_token=$TOKEN&Login=Login" -o /dev/null
echo "[+] Logged in"

# Step 3: Set/verify security level
echo "[*] Setting security level to low..."
SEC_PAGE=$($CURL -c "$COOKIES" -b "$COOKIES" "$DVWA/security.php")
TOKEN=$(echo "$SEC_PAGE" | grep -oP "user_token' value='\K[a-f0-9]+")
CURRENT=$(echo "$SEC_PAGE" | grep -oP "Security level is currently: <em>\K[a-z]+(?=</em>)")
if [ "$CURRENT" = "low" ]; then
  echo "[=] Already low"
else
  $CURL -c "$COOKIES" -b "$COOKIES" -X POST "$DVWA/security.php" \
    -d "security=low&seclev_submit=Submit&user_token=$TOKEN" -o /dev/null
  echo "[+] Set to low"
fi

# Step 4: Final verify
echo "[*] Verifying..."
CURRENT=$($CURL -c "$COOKIES" -b "$COOKIES" "$DVWA/security.php" | grep -oP "Security level is currently: <em>\K[a-z]+(?=</em>)")
echo "  Security Level: $CURRENT"
if [ "$CURRENT" = "low" ]; then echo "[+] DVWA ready!"; else echo "[!] FAILED (got $CURRENT)"; fi
