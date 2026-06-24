#!/bin/bash
# network-diag.sh — Diagnostic réseau pour la formation
# Détermine dans quel scénario on se trouve et affiche les variables utiles
set -e

echo "================================================"
echo " Diagnostic Réseau — Formation Hacking"
echo "================================================"
echo ""

# ─── Scénario ───
IN_DOCKER=false
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    IN_DOCKER=true
fi

if $IN_DOCKER; then
    echo "SCÉNARIO B : Kali dans Docker (attaquant Dockerisé)"
    echo "═══════════════════════════════════════════════════"
    echo "Cibles accessibles via noms de service Docker :"
    echo "  dvwa:80, vsftpd:21, vsftpd:445, buffovf:9001,"
    echo "  waf-target:80, secure-linux:22, forensic-victim:80"
    echo ""
else
    echo "SCÉNARIO A : Kali en machine hôte (VM ou bare metal)"
    echo "════════════════════════════════════════════════════"
fi

# ─── IP de Kali ───
echo "Adresses IP de cette machine Kali :"
KALI_IPS=$(hostname -I 2>/dev/null || ip addr show 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
for ip in $KALI_IPS; do
    echo "  → $ip"
done

# Prendre la première IP non-loopback
KALI_IP=$(echo "$KALI_IPS" | awk '{print $1}')
echo ""
echo "IP principale Kali : $KALI_IP"
echo "  → À utiliser pour les reverse shells, écouteurs HTTP..."

# ─── IP Docker bridge ───
if $IN_DOCKER; then
    echo ""
    echo "IP dans le réseau Docker :"
    ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}'
else
    DOCKER_BRIDGE_IP=$(ip addr show docker0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "172.17.0.1")
    echo ""
    echo "IP du bridge Docker (docker0) : $DOCKER_BRIDGE_IP"
    echo "  → Les conteneurs joignent Kali via cette IP"
fi

# ─── Conteneurs accessibles ───
echo ""
echo "═══════════════════════════════"
echo " Vérification des conteneurs"
echo "═══════════════════════════════"

check_container() {
    local name=$1
    local host=$2
    local port=$3
    if $IN_DOCKER; then
        # Depuis un conteneur, tester via le nom de service
        nc -z -w2 "$host" "$port" 2>/dev/null && echo "  ✅ $name ($host:$port)" || echo "  ❌ $name ($host:$port) — non accessible"
    else
        # Depuis l'hôte, tester via localhost
        nc -z -w2 localhost "$port" 2>/dev/null && echo "  ✅ $name (localhost:$port)" || echo "  ❌ $name (localhost:$port) — non accessible"
    fi
}

echo ""
check_container "DVWA"             "dvwa"           8080
check_container "Metasploitable2"  "vsftpd"         21
check_container "Samba"            "vsftpd"         445
check_container "Buffer Overflow"  "buffovf"        9001
check_container "WAF Target"       "waf-target"     80
check_container "Secure Linux"     "secure-linux"   22
check_container "Forensic Victim"  "forensic-victim" 80

# ─── Résumé des commandes utiles ───
echo ""
echo "═══════════════════════════════"
echo " Résumé pour les labs"
echo "═══════════════════════════════"
echo ""

if $IN_DOCKER; then
    echo "Scenario B — Kali dans Docker :"
    echo "  nmap -sV dvwa"
    echo "  curl http://dvwa/login.php"
    echo "  sqlmap -u http://dvwa/vulnerabilities/sqli/?id=1 ..."
    echo "  msfconsole → set RHOSTS vsftpd"
    echo "  Reverse shell → $KALI_IP:4444"
else
    echo "Scenario A — Kali hôte :"
    echo "  nmap -sV -p 8080 localhost"
    echo "  curl http://localhost:8080/login.php"
    echo "  sqlmap -u http://localhost:8080/vulnerabilities/sqli/?id=1 ..."
    echo "  msfconsole → set RHOSTS localhost"
    echo "  Reverse shell → $KALI_IP:4444  (ou 172.17.0.1 depuis les conteneurs)"
fi

echo ""
echo "================================================"
echo " Diagnostic terminé"
echo "================================================"
