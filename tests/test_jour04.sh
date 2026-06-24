#!/bin/bash
# Test JOUR 04 — Hardening
set -e
echo "=== Test JOUR 04 — Hardening ==="

# Vérifier SSH accessible
echo "[1] Test SSH accessible..."
nc -z -w2 localhost 2222 2>/dev/null && echo "  ✓ Port 2222 ouvert (SSH)" || echo "  ✗ Port 2222 fermé"

# Vérifier auth root par mot de passe (doit marcher AVANT hardening)
echo "[2] Test auth root..."
sshpass -p 'changeme' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -p 2222 root@localhost "id" 2>/dev/null && echo "  ✓ Root SSH accessible" || echo "  ⚠ Root SSH refusé ou sshpass absent"

echo "=== JOUR 04 OK ==="
