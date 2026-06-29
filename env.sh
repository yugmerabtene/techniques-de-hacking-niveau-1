#!/bin/bash
# =============================================================================
# env.sh — Variables d'environnement pour les labs
# Source : source env.sh (depuis la racine du repo)
# =============================================================================
set -a

# --- Ports des conteneurs (host) ---
DVWA_PORT=8088
SQLI_APP_PORT=8083
WAF_PORT=8081
ELK_PORT=5601
FORENSIC_PORT=8082
SECURE_LINUX_PORT=2224
VSFTPD_PORT=21
SAMBA_PORT=445

# --- IPs des conteneurs (réseau Docker) ---
# Gateway Docker (depuis Kali hôte)
LHOST=$(ip route get 1 | awk '{print $7;exit}')
# IPs des conteneurs sur le réseau Docker
DVWA_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' dvwa-target 2>/dev/null || echo "172.18.0.2")
SQLI_APP_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' sqli-app-target 2>/dev/null || echo "172.18.0.3")
WAF_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' waf-target 2>/dev/null || echo "172.18.0.10")
METASPLOITABLE_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vsftpd-target 2>/dev/null || echo "172.18.0.4")

# --- Ports d'écoute pour reverse shells ---
LPORT=4444
LPORT_SAMBA=4445

# --- Chemins ---
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABS_DIR="$REPO_ROOT/labs_resolution"

set +a
