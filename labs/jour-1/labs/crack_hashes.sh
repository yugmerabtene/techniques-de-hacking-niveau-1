#!/bin/bash
# =====================================================================
# crack_hashes.sh — Casse les hashs MD5 de hashes.txt
# Usage: bash crack_hashes.sh [wordlist]
# =====================================================================
set -uo pipefail

HASHES="$(dirname "$0")/hashes.txt"
WORDLIST="${1:-/usr/share/wordlists/rockyou.txt}"

echo "[*] Cracking MD5 hashes..."
echo "[*] Fichier: $HASHES"
echo "[*] Wordlist: $WORDLIST"
echo ""

if [ ! -f "$WORDLIST" ]; then
  echo "[!] Wordlist non trouvée: $WORDLIST"
  echo "    Téléchargement: sudo apt install -y wordlist"
  echo "    Ou extraire: sudo gzip -d /usr/share/wordlists/rockyou.txt.gz"
  echo ""
  # Fallback: essayer avec john --wordlist intégré
  WORDLIST=""
fi

echo "--- Lancement de John the Ripper ---"
if [ -n "$WORDLIST" ]; then
  john --format=raw-md5 --wordlist="$WORDLIST" "$HASHES" 2>&1
else
  john --format=raw-md5 "$HASHES" 2>&1
fi

echo ""
echo "--- Résultats ---"
john --show --format=raw-md5 "$HASHES" 2>&1

echo ""
echo "--- Vérification des hashs non-crackés ---"
LEFT=$(john --show --format=raw-md5 "$HASHES" 2>&1 | grep -c "password hash")
if [ "$LEFT" -gt 0 ]; then
  echo "[!] $LEFT hash(s) restant(s)"
else
  echo "[+] Tous les hashs sont crackés"
fi
