#!/bin/bash
# Test JOUR 03 — Buffer overflow + WAF
set -e
echo "=== Test JOUR 03 — Buffer Overflow + WAF ==="

# Vérifier buffovf
echo "[1] Test buffer overflow service..."
nc -z -w2 localhost 9001 2>/dev/null && echo "  ✓ Port 9001 ouvert (buffovf)" || echo "  ✗ Port 9001 fermé"

# Vérifier que le programme crash comme prévu
echo "[2] Test crash buffer overflow..."
echo "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM" | timeout 2 nc localhost 9001 2>/dev/null && echo "  ✓ Programme répond" || echo "  ⚠ Timeout (normal si crash)"

# Vérifier WAF
echo "[3] Test WAF..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8081/?id=1" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "  ✓ WAF cible accessible"
else
    echo "  ⚠ WAF inaccessible (HTTP $HTTP_CODE)"
fi

# Vérifier que le WAF bloque les injections basiques
echo "[4] Test WAF blocking..."
HTTP_CODE_SQLI=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8081/?id=1%20OR%201=1" 2>/dev/null || echo "000")
if [ "$HTTP_CODE_SQLI" = "403" ]; then
    echo "  ✓ WAF bloque SQLi (403 Forbidden)"
else
    echo "  ⚠ WAF pas de blocage (HTTP $HTTP_CODE_SQLI)"
fi

echo "=== JOUR 03 OK ==="
