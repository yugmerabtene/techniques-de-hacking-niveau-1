#!/bin/bash
# =====================================================================
# recon.sh — Scan de reconnaissance sur la cible Metasploitable
# Usage: bash recon.sh [cible_ip]
#   cible_ip: IP de la cible (defaut: env.sh METASPLOITABLE_IP)
# =====================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source /tmp/techniques-hacking-mdj/env.sh

RHOST="${1:-$METASPLOITABLE_IP}"
OUTDIR="$SCRIPT_DIR/recon/$(date +%H%M)"
mkdir -p "$OUTDIR"

echo "[*] Cible: $RHOST"
echo "[*] Scan des ports courants..."
nmap -sV -sC -p 21,22,23,25,80,110,139,143,445,3306,3632,5432,6667,8009,8180 \
  "$RHOST" -oA "$OUTDIR/ports" 2>/dev/null | tail -3

echo "[*] Scan vsftpd backdoor..."
nmap --script ftp-vsftpd-backdoor -p 21 "$RHOST" -oA "$OUTDIR/vsftpd" 2>/dev/null | tail -3

echo "[*] Scan SMB vulnerabilites..."
nmap --script "smb-vuln*" -p 445 "$RHOST" -oA "$OUTDIR/smb" 2>/dev/null | tail -3

echo "[+] Resultats dans $OUTDIR/"
ls -la "$OUTDIR/"
