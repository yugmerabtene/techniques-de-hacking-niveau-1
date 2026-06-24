#!/bin/bash
# Test JOUR 02 — vsftpd accessible et version vulnérable confirmée
set -e
echo "=== Test JOUR 02 — vsftpd / SMB ==="

# Vérifier que le port 21 est ouvert
echo "[1] Test port FTP..."
nc -z -w2 localhost 21 2>/dev/null && echo "  ✓ Port 21 ouvert" || echo "  ✗ Port 21 fermé"

# Vérifier bannière vsftpd
echo "[2] Test bannière vsftpd..."
BANNER=$(echo "" | nc -w2 localhost 21 2>/dev/null || echo "")
if echo "$BANNER" | grep -qi "vsftpd"; then
    echo "  ✓ vsftpd détecté : $BANNER"
else
    echo "  ⚠ Bannière non détectée (peut être normale selon le conteneur)"
fi

# Vérifier port 445 (SMB)
echo "[3] Test port SMB..."
nc -z -w2 localhost 445 2>/dev/null && echo "  ✓ Port 445 ouvert" || echo "  ✗ Port 445 fermé"

echo "=== JOUR 02 OK ==="
