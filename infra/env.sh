#!/bin/bash
# =====================================================================
# env.sh — Configuration centralisée pour tous les labs
# Source:  source env.sh  (depuis /tmp/techniques-hacking-mdj/)
# =====================================================================

# Bridge Docker (gateway depuis les conteneurs)
export GATEWAY="172.18.0.1"

# Réseau du lab
export LAB_NETWORK="pentest-lab"

# LHOST = adresse de l'attaquant depuis les conteneurs
export LHOST="${GATEWAY}"

# Ports pour reverse shells
export LPORT="4444"
export LPORT_SAMBA="7777"
export LPORT_VSFTPD="7777"

# Cibles (adresses IP des conteneurs)
export DVWA_IP="172.18.0.3"
export SQLI_APP_IP="172.18.0.2"
export WAF_IP="172.18.0.5"
export BUFFOVF_IP="172.18.0.6"
export SECURE_LINUX_IP="172.18.0.7"
export FORENSIC_IP="172.18.0.8"
export METASPLOITABLE_IP="172.18.0.4"

# Ports locaux (mapping hôte)
export DVWA_PORT="8088"
export SQLI_APP_PORT="8083"
export WAF_PORT="8081"
export FORENSIC_PORT="8082"
export BUFFOVF_PORT="9001"
export SECURE_LINUX_PORT="2224"
export VSFTPD_PORT="21"
export SAMBA_PORT="445"
export METASPLOITABLE_SSH_PORT="2223"

# Répertoires
export LABS_DIR="/tmp/techniques-hacking-mdj"

echo "[+] Env lab chargé — LHOST=$LHOST, LPORT=$LPORT"
echo "[+] Conteneurs: DVWA=$DVWA_IP:$DVWA_PORT, sqli=$SQLI_APP_IP, waf=$WAF_IP, buffovf=$BUFFOVF_IP"
echo "[+] Metasploitable: $METASPLOITABLE_IP (ports 21,445,3306...)"
