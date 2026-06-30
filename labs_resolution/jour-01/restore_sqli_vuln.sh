#!/bin/bash
# restore_sqli_vuln.sh — RESTAURE la faille SQLi DVWA (concaténation d'origine)
# Usage: bash labs_resolution/jour-01/restore_sqli_vuln.sh
set -e
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source env.sh

echo "[*] RESTAURATION de la faille SQLi (concaténation originale)"
echo ""

CID=$(docker compose ps -q dvwa 2>/dev/null)
if [ -z "$CID" ]; then
    echo "[!] Conteneur dvwa introuvable."
    exit 1
fi

docker exec -i "$CID" bash << 'SCRIPT'
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
echo "[+] Faille SQLi restaurée (concaténation dans la requête)"
SCRIPT

echo ""
echo "[*] Vérification injection manuelle :"
rm -f /tmp/dvwa_cookie_rst.txt
TOKEN=$(curl -s -c /tmp/dvwa_cookie_rst.txt "http://localhost:$DVWA_PORT/login.php" \
    | grep -oP "user_token' value='\K[a-f0-9]+")
curl -s -b /tmp/dvwa_cookie_rst.txt -c /tmp/dvwa_cookie_rst.txt \
    -d "username=admin&password=password&user_token=$TOKEN&Login=Login" \
    "http://localhost:$DVWA_PORT/login.php" -o /dev/null

echo -n "  id=1 (normal)             → "
curl -s -b /tmp/dvwa_cookie_rst.txt \
    "http://localhost:$DVWA_PORT/vulnerabilities/sqli/?id=1&Submit=Submit" \
    | grep -c "First name"

echo -n "  id=1' OR '1'='1' # (iNJECTION) → "
curl -s -b /tmp/dvwa_cookie_rst.txt \
    "http://localhost:$DVWA_PORT/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271%27+%23&Submit=Submit" \
    | grep -c "First name"

echo ""
echo "[!] Attention : la faille est de nouveau active !"
echo "    Pour la corriger : bash labs_resolution/jour-01/fix_sqli_prepared.sh"
rm -f /tmp/dvwa_cookie_rst.txt
