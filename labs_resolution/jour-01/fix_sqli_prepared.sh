#!/bin/bash
# fix_sqli_prepared.sh — Corrige la faille SQLi DVWA (requêtes préparées)
# Usage: bash labs_resolution/jour-01/fix_sqli_prepared.sh
set -e
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source env.sh

echo "[*] Application du correctif SQLi : requêtes préparées"
echo "    Remplacer la concaténation par des prepared statements"
echo ""

CID=$(docker compose ps -q dvwa 2>/dev/null)
if [ -z "$CID" ]; then
    echo "[!] Conteneur dvwa introuvable. Lance d'abord: docker compose up -d dvwa"
    exit 1
fi

docker exec -i "$CID" bash << 'SCRIPT'
cat > /var/www/html/vulnerabilities/sqli/source/low.php << 'PHPEOF'
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    $id = $_REQUEST[ 'id' ];

    $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"],
        "SELECT first_name, last_name FROM users WHERE user_id = ?");
    mysqli_stmt_bind_param($stmt, "s", $id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if( $result ) {
        while( $row = mysqli_fetch_assoc( $result ) ) {
            $first = $row["first_name"];
            $last  = $row["last_name"];
            $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
        }
    }
    mysqli_stmt_close($stmt);
}

?>
PHPEOF
echo "[+] Fichier low.php mis à jour avec requêtes préparées"
SCRIPT

echo ""
echo "[*] Vérification :"
docker exec "$CID" cat /var/www/html/vulnerabilities/sqli/source/low.php | head -8
echo ""

echo "[*] Test d'injection :"
rm -f /tmp/dvwa_cookie_fix.txt
TOKEN=$(curl -s -c /tmp/dvwa_cookie_fix.txt "http://localhost:$DVWA_PORT/login.php" \
    | grep -oP "user_token' value='\K[a-f0-9]+")
curl -s -b /tmp/dvwa_cookie_fix.txt -c /tmp/dvwa_cookie_fix.txt \
    -d "username=admin&password=password&user_token=$TOKEN&Login=Login" \
    "http://localhost:$DVWA_PORT/login.php" -o /dev/null

echo -n "  id=1 (normal)      → "
curl -s -b /tmp/dvwa_cookie_fix.txt \
    "http://localhost:$DVWA_PORT/vulnerabilities/sqli/?id=1&Submit=Submit" \
    | grep -c "First name"

echo -n "  id=1' OR '1'='1' # → "
curl -s -b /tmp/dvwa_cookie_fix.txt \
    "http://localhost:$DVWA_PORT/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271%27+%23&Submit=Submit" \
    | grep -c "First name"

echo ""
echo "[+] Correctif appliqué. La concaténation SQL est remplacée par"
echo "    mysqli_prepare + bind_param → les injections sont neutralisées."
rm -f /tmp/dvwa_cookie_fix.txt
