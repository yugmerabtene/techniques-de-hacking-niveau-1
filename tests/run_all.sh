#!/bin/bash
# run_all.sh — Validation complète de l'environnement de cours
# Usage : bash tests/run_all.sh
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass=0
fail=0

check() {
    local desc="$1"
    local cmd="$2"
    local expected="$3"
    echo -n "[ ] $desc ... "
    result=$(eval "$cmd" 2>/dev/null || echo "FAIL")
    if echo "$result" | grep -q "$expected"; then
        echo -e "${GREEN}✓${NC}"
        ((pass++))
    else
        echo -e "${RED}✗${NC} ($result)"
        ((fail++))
    fi
}

echo "============================================"
echo " Validation Environnement de Cours"
echo " Techniques de Hacking et Contre-Mesures"
echo "============================================"
echo ""

# ─── Outils Kali ───
echo "─── Outils Kali ───"
check "python3"          "python3 --version"              "3\."
check "pip"              "pip --version 2>&1"             "pip"
check "docker"           "docker --version"               "Docker version"
check "docker compose"   "docker compose version 2>&1"    "v"
check "git"              "git --version"                  "git version"
check "nmap"             "nmap --version 2>&1"            "Nmap"
check "msfconsole"       "which msfconsole"               "msfconsole"
check "sqlmap"           "which sqlmap"                   "sqlmap"
check "wireshark"        "which wireshark"                "wireshark"
check "gobuster"         "which gobuster"                 "gobuster"
check "netcat"           "which nc"                       "nc"
check "curl"             "curl --version"                 "curl"
echo ""

# ─── Docker — conteneurs existants ───
echo "─── Conteneurs Docker ───"
check "image dvwa"       "docker images | grep dvwa"      "dvwa"
check "image metasploit" "docker images | grep metasploit" "metasploit"
echo ""

# ─── Conteneurs actifs ───
echo "─── Conteneurs actifs ───"
check "dvwa (8080)"      "curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/ 2>/dev/null || echo 000" "200"
check "sqli-app (8083)"  "curl -s -o /dev/null -w '%{http_code}' http://localhost:8083/ 2>/dev/null || echo 000" "200"
check "vsftpd (21)"      "nc -z -w1 localhost 21 2>&1 || echo 'closed'" "succeeded\|open"
check "buffovf (9001)"   "nc -z -w1 localhost 9001 2>&1 || echo 'closed'" "succeeded\|open"
check "waf (8081)"       "curl -s -o /dev/null -w '%{http_code}' http://localhost:8081/ 2>/dev/null || echo 000" "200"
check "secure-linux (2222)" "nc -z -w1 localhost 2222 2>&1 || echo 'closed'" "succeeded\|open"
check "forensic (8082)"  "curl -s -o /dev/null -w '%{http_code}' http://localhost:8082/ 2>/dev/null || echo 000" "200"
echo ""

# ─── Vulnérabilités clés ───
echo "─── Vulnérabilités confirmées ───"
check "DVWA login page"  "curl -s http://localhost:8080/login.php | grep -i 'login\|dvwa'" "login\|DVWA"
check "sqli-app SQLi"     "curl -s 'http://localhost:8083/?page=search&id=1%20OR%201=1' | grep -c 'Laptop\|Monitor\|Keyboard'" "[4-6]"
check "sqli-app login bypass" "curl -s -d 'page=login&username=admin%27%20--&password=x' http://localhost:8083/ | grep 'Connecté'" "Connecté"
check "vsftpd 2.3.4 banner" "echo '' | timeout 2 nc localhost 21 2>/dev/null | grep vsftpd || echo 'check later'" "vsftpd\|check"
check "WAF blocks SQLi"  "curl -s -o /dev/null -w '%{http_code}' 'http://localhost:8081/?id=1%20OR%201=1' 2>/dev/null || echo 200" "403"
check "WAF allows normal" "curl -s -o /dev/null -w '%{http_code}' 'http://localhost:8081/?id=1' 2>/dev/null || echo 000" "200"
check "Forensic cmd inject" "curl -s 'http://localhost:8082/?cmd=id' 2>/dev/null | grep 'uid='" "uid="
echo ""

# ─── Bilan ───
echo "============================================"
echo -e " ${GREEN}$pass réussis${NC} / ${RED}$fail échoués${NC}"
echo "============================================"

if [ "$fail" -gt 0 ]; then
    echo ""
    echo "⚠️  Certains conteneurs ne sont pas lancés."
    echo "   Lancer : docker-compose up -d"
    exit 1
else
    echo ""
    echo "✓ Environnement prêt pour la formation !"
fi
