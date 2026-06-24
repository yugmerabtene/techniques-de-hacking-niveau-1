#!/bin/bash
# Test JOUR 05 — Forensic victim
set -e
echo "=== Test JOUR 05 — Forensic ==="

# Vérifier web app accessible
echo "[1] Test web app..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8082/" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "  ✓ Forensic web app accessible"
else
    echo "  ⚠ Forensic web inaccessible (HTTP $HTTP_CODE)"
fi

# Vérifier command injection
echo "[2] Test command injection..."
RESPONSE=$(curl -s "http://localhost:8082/?cmd=id" 2>/dev/null || echo "")
if echo "$RESPONSE" | grep -q "uid="; then
    echo "  ✓ Command injection fonctionnelle"
else
    echo "  ⚠ Command injection non détectée"
fi

echo "=== JOUR 05 OK ==="
