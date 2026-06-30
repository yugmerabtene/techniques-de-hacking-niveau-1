#!/bin/bash
# fix_sqli.sh — Corrige la faille SQLi DVWA (requêtes préparées)
# Usage: bash labs_resolution/jour-01/fix_sqli.sh
set -euo pipefail
cd "$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)"
source env.sh

CID=$(docker compose ps -q dvwa 2>/dev/null)
[ -z "$CID" ] && echo "Conteneur dvwa introuvable" && exit 1

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
SCRIPT
echo "[+] SQLi corrigée : requêtes préparées"
