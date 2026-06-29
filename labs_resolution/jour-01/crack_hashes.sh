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
JOHN_OK=true
if [ -n "$WORDLIST" ]; then
  john --format=raw-md5 --wordlist="$WORDLIST" "$HASHES" 2>&1 || JOHN_OK=false
else
  john --format=raw-md5 "$HASHES" 2>&1 || JOHN_OK=false
fi

if [ "$JOHN_OK" = false ]; then
  echo "[!] John --format=raw-md5 non supporté, fallback hashcat..."
  HASHES_ONLY=$(mktemp)
  cut -d: -f2 < "$HASHES" > "$HASHES_ONLY"
  if [ -n "${WORDLIST:-}" ] && [ -f "$WORDLIST" ]; then
    hashcat -m 0 -a 0 "$HASHES_ONLY" "$WORDLIST" 2>/dev/null
  else
    hashcat -m 0 "$HASHES_ONLY" --show 2>/dev/null
  fi
  echo "--- Résultats (hashcat) ---"
  SHOW_OUT=$(hashcat -m 0 --show "$HASHES_ONLY" 2>/dev/null)
  while IFS=: read -r user hash; do
    plain=$(echo "$SHOW_OUT" | grep "^$hash:" | cut -d: -f2)
    [ -n "$plain" ] && echo "  $user:$plain" || echo "  $user:(non cracké)"
  done < "$HASHES"
  TOTAL=$(wc -l < "$HASHES")
  CRACKED=$(echo "$SHOW_OUT" | grep -cP '^[a-f0-9]{32}:' || true)
  LEFT=$((TOTAL - CRACKED))
  rm -f "$HASHES_ONLY"
else
  echo ""
  echo "--- Résultats (john) ---"
  john --show --format=raw-md5 "$HASHES" 2>&1
  LEFT=$(john --show --format=raw-md5 "$HASHES" 2>&1 | grep -c "password hash")
fi

echo ""
echo "--- Vérification des hashs non-crackés ---"
if [ "$LEFT" -gt 0 ]; then
  echo "[!] $LEFT hash(s) restant(s)"
else
  echo "[+] Tous les hashs sont crackés"
fi
