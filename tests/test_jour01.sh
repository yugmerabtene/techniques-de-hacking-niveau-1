#!/bin/bash
# Test JOUR 01 — DVWA accessible et vulnérabilités présentes
set -e
echo "=== Test JOUR 01 — DVWA ==="

# Vérifier que DVWA est accessible
echo "[1] Test DVWA HTTP..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "  ✓ DVWA accessible (HTTP 200)"
else
    echo "  ✗ DVWA inaccessible (HTTP $HTTP_CODE)"
    echo "  → Lancer : docker-compose up -d dvwa"
    exit 1
fi

# Vérifier page login DVWA
echo "[2] Test login DVWA..."
LOGIN=$(curl -s http://localhost:8080/login.php 2>/dev/null)
if echo "$LOGIN" | grep -qi "login\|dvwa"; then
    echo "  ✓ Page login DVWA trouvée"
else
    echo "  ✗ Page login DVWA non trouvée"
    exit 1
fi

echo "=== JOUR 01 OK ==="
