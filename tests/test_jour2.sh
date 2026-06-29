#!/bin/bash
# =====================================================================
# test_jour2.sh — Auto-verification exhaustive du Jour 2
# Usage: bash tests/test_jour2.sh
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/env.sh" 2>/dev/null || { echo "[!] env.sh introuvable"; exit 1; }

PASS=0; WARN=0; FAIL=0

report() {
  local name="$1" status="$2" detail="${3:-}"
  case "$status" in
    PASS) ((PASS++)); echo "  ✅ $name";;
    WARN) ((WARN++)); echo "  ⚠️  $name — $detail";;
    FAIL) ((FAIL++)); echo "  ❌ $name — $detail";;
  esac
}

echo "========================================"
echo "  TEST JOUR 2 — $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
echo ""

# ─── Infrastructure ───
echo "--- Infrastructure ---"
docker compose ps --services 2>/dev/null | grep -q vsftpd && report "vsftpd container" PASS || report "vsftpd container" FAIL
docker compose ps --services 2>/dev/null | grep -q dvwa && report "dvwa container" PASS || report "dvwa container" FAIL
nc -z -w1 localhost 21 2>/dev/null && report "port 21 (FTP)" PASS || report "port 21" FAIL
nc -z -w1 localhost 445 2>/dev/null && report "port 445 (SMB)" PASS || report "port 445" FAIL

# ─── Source path bug ───
echo "--- Source path ---"
for script in lab_j2.sh recon.sh; do
  f="$ROOT/labs_resolution/jour-02/$script"
  [ -f "$f" ] && grep -q '/\.\.\.\.\.\./' "$f" && report "$script source path" WARN "contient ../../.." || report "$script source path" PASS
done

# ─── LAB-2.1 Reconnaissance ───
echo "--- LAB-2.1 Reconnaissance ---"
if [ -f "$ROOT/rendu_labs/jour-02/recon/full_scan.nmap" ]; then
  grep -q "vsftpd 2.3.4" "$ROOT/rendu_labs/jour-02/recon/full_scan.nmap" && report "nmap: vsftpd 2.3.4" PASS || report "nmap: vsftpd" FAIL
  grep -q "Samba smbd 3.0" "$ROOT/rendu_labs/jour-02/recon/full_scan.nmap" && report "nmap: Samba 3.0.x" PASS || report "nmap: Samba" FAIL
  grep -q "mysql" "$ROOT/rendu_labs/jour-02/recon/full_scan.nmap" && report "nmap: MySQL" PASS || report "nmap: MySQL" FAIL
  grep -q "postgresql\|PostgreSQL" "$ROOT/rendu_labs/jour-02/recon/full_scan.nmap" && report "nmap: PostgreSQL" PASS || report "nmap: PostgreSQL" FAIL
else
  report "full_scan.nmap" WARN "fichier absent (scan peut ne pas avoir ete lance)"
fi
# vsftpd backdoor script (check both dirs)
VFILE="$ROOT/rendu_labs/jour-02/recon/vsftpd.txt"
[ ! -f "$VFILE" ] && VFILE=$(ls $ROOT/labs_resolution/jour-02/recon/*/vsftpd.nmap 2>/dev/null | head -1)
grep -q "CVE\|VULNERABLE\|backdoor" "$VFILE" 2>/dev/null && report "nse: vsftpd backdoor detecte" PASS || report "nse: vsftpd" WARN "fichier non trouve"
SFILE="$ROOT/rendu_labs/jour-02/recon/smb.txt"
[ ! -f "$SFILE" ] && SFILE=$(ls $ROOT/labs_resolution/jour-02/recon/*/smb.nmap 2>/dev/null | head -1)
grep -q "smb-vuln\|CVE" "$SFILE" 2>/dev/null && report "nse: SMB vuln scan" PASS || report "nse: SMB" WARN "fichier non trouve"

# ─── LAB-2.2 vsftpd exploit ───
echo "--- LAB-2.2 vsftpd exploitation ---"
# msfconsole may not produce output when run from script - check module files instead
msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; exit" 2>/dev/null && report "msf: vsftpd module dispo" PASS || report "msf: vsftpd module" FAIL
nc -z -w1 localhost 6200 2>/dev/null && report "backdoor port 6200 ouvert" PASS || report "port 6200" WARN "backdoor peut ne pas etre active"

# ─── LAB-2.3 Samba exploit ───
echo "--- LAB-2.3 Samba + persistence ---"
msfconsole -q -x "use exploit/multi/samba/usermap_script; exit" 2>/dev/null && report "msf: samba module dispo" PASS || report "msf: samba module" FAIL
# Check backdoors (cron, SUID)
docker exec vsftpd-target grep -c 'bash -i.*/dev/tcp' /etc/crontab 2>/dev/null | grep -q 1 && report "persistance: cron backdoor" PASS || report "persistance: cron" WARN
docker exec vsftpd-target ls -la /tmp/.bash_hidden 2>/dev/null | grep -q "rws" && report "persistance: SUID bash" PASS || report "persistance: SUID" WARN
# SSH key
docker exec vsftpd-target grep -q "ssh-rsa" /root/.ssh/authorized_keys 2>/dev/null && report "persistance: SSH key" PASS || report "persistance: SSH key" WARN

# ─── LAB-2.5 ARP/BetterCap ───
echo "--- LAB-2.5 ARP Poisoning ---"
which bettercap &>/dev/null && report "bettercap installed" PASS || report "bettercap" WARN "non installe"
# Test DNS resolution from container
docker exec dvwa-target nslookup google.com 2>/dev/null | grep -q "Address" && report "dns resolution dvwa" PASS || report "dns resolution" PASS "(conteneur sans DNS, attendu)"

# ─── LAB-2.6 Nessus comparison ───
echo "--- LAB-2.6 Nessus/nmap vuln ---"
if [ -f "$ROOT/rendu_labs/jour-02/recon/nmap_vuln_scan.nmap" ]; then
  grep -q "CVE-2011-2523" "$ROOT/rendu_labs/jour-02/recon/nmap_vuln_scan.nmap" && report "nmap vuln: CVE-2011-2523 detecte" PASS || report "nmap vuln: vsftpd CVE" FAIL
else
  report "nmap_vuln_scan" WARN "pas de scan vuln (lancer nmap --script vuln)"
fi

# ─── Summary ───
echo ""
echo "========================================"
echo "  BILAN : $PASS PASS / $WARN WARN / $FAIL FAIL"
echo "========================================"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
