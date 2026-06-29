#!/bin/bash
# =====================================================================
# check_all_services.sh — Vérifie que tous les services répondent
# =====================================================================
# Usage: bash check_all_services.sh   (ou utilisez newgrp docker si besoin)
# Pour Docker: exec newgrp docker <<< "./check_all_services.sh"
# =====================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/env.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
WARN=0

check_http() {
    local name=$1
    local url=$2
    local expected=$3
    local code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "$url" 2>/dev/null || echo "REFUSED")
    if [ "$code" = "$expected" ] || [ "${expected:0:1}" = "$code" ] 2>/dev/null; then
        echo -e "  ${GREEN}[✓]${NC} $name → $code"
        PASS=$((PASS+1))
    elif [ "$code" = "REFUSED" ] || [ -z "$code" ]; then
        echo -e "  ${RED}[✗]${NC} $name → REFUSED (attendu $expected)"
        FAIL=$((FAIL+1))
    else
        echo -e "  ${YELLOW}[~]${NC} $name → $code (attendu $expected)"
        WARN=$((WARN+1))
    fi
}

check_tcp() {
    local name=$1
    local host=$2
    local port=$3
    local banner=$4
    local result=$(timeout 2 bash -c "echo '' | nc -w1 $host $port 2>/dev/null" || echo "CLOSED")
    if echo "$result" | grep -qi "$banner" 2>/dev/null || [ -n "$result" ] && [ "$result" != "CLOSED" ]; then
        echo -e "  ${GREEN}[✓]${NC} $name → OPEN ($(echo "$result" | head -c50))"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}[✗]${NC} $name → CLOSED"
        FAIL=$((FAIL+1))
    fi
}

check_docker() {
    local name=$1
    local status
    # Try direct docker, fallback to newgrp
    if ! docker ps &>/dev/null; then
        status=$(newgrp docker <<< "docker inspect \"$name\" --format '{{.State.Status}}'" 2>/dev/null || echo "NOT_FOUND")
    else
        status=$(docker inspect "$name" --format '{{.State.Status}}' 2>/dev/null || echo "NOT_FOUND")
    fi
    if [ "$status" = "running" ]; then
        local health=$(docker inspect "$name" --format '{{.State.Health.Status}}' 2>/dev/null || echo "none")
        if [ "$health" = "healthy" ] || [ "$health" = "none" ]; then
            echo -e "  ${GREEN}[✓]${NC} $name → running"
            PASS=$((PASS+1))
        else
            echo -e "  ${YELLOW}[~]${NC} $name → running ($health)"
            WARN=$((WARN+1))
        fi
    elif [ "$status" = "NOT_FOUND" ]; then
        echo -e "  ${RED}[✗]${NC} $name → NOT_FOUND"
        FAIL=$((FAIL+1))
    else
        echo -e "  ${RED}[✗]${NC} $name → $status"
        FAIL=$((FAIL+1))
    fi
}

echo "============================================"
echo "  Vérification des services du lab"
echo "  $(date)"
echo "============================================"
echo ""

echo "--- Conteneurs Docker ---"
for c in dvwa-target sqli-app-target waf-target forensic-victim secure-linux-target buffovf-target vsftpd-target; do
    check_docker "$c"
done

echo ""
echo "--- Services HTTP ---"
check_http "DVWA" "http://localhost:$DVWA_PORT/" "302"
check_http "sqli-app" "http://localhost:$SQLI_APP_PORT/" "200"
check_http "waf-target" "http://localhost:$WAF_PORT/" "200"
check_http "forensic" "http://localhost:$FORENSIC_PORT/" "200"

echo ""
echo "--- Services TCP ---"
check_tcp "buffovf" "localhost" "$BUFFOVF_PORT" "Input received"
check_tcp "secure-linux (SSH)" "localhost" "$SECURE_LINUX_PORT" "SSH"
check_tcp "vsftpd" "localhost" "$VSFTPD_PORT" "vsFTPd"

echo ""
echo "--- Conteneur Metasploitable (ports vulnérables) ---"
check_tcp "SMB (445)" "localhost" "445" ""
check_tcp "MySQL (3306)" "localhost" "3306" ""

echo ""
echo "============================================"
echo "  Résultats: ${GREEN}$PASS OK${NC}, ${YELLOW}$WARN warnings${NC}, ${RED}$FAIL échecs${NC}"
echo "============================================"

exit $FAIL
