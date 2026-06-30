# Rapport de test — JOUR-02

**Date :** 2026-06-30 00:39:11
**Environnement :** Linux kali 6.19.14+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05) x86_64 GNU/Linux

---

## Prérequis — Vérification des outils

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| P-01 | `python3 --version` | ✅ | Python 3.13.12 | Python 3.x | |
| P-02 | `docker --version` | ✅ | Docker version 28.5.2+dfsg4, build 9cc6dea35e9a963f281434761c656fba4ac43aed | Docker 24+ | via newgrp |
| P-03 | `docker compose version` | ✅ | Docker Compose version 2.40.3-3 | version dispo | |
| P-04 | `nmap --version` | ✅ | Nmap version 7.99 ( https://nmap.org ) | Nmap 7.x | |
| P-05 | `msfconsole --version` | ✅ | Framework Version: 6.4.133-dev | Metasploit 6.x | |
| P-06 | `sqlmap --version` | ❌ | 1.10.4#stable | sqlmap 1.7+ | |
| P-07 | `which nc` | ✅ | /usr/bin/nc | /usr/bin/nc | |
| P-08 | `which bettercap` | ✅ | /usr/bin/bettercap | bettercap dispo | |
| P-09 | `curl --version` | ✅ | curl 8.19.0 (x86_64-pc-linux-gnu) libcurl/8.19.0 OpenSSL/3.6.2 zlib/1.3.2 brotli/1.2.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.5 libssh2/1.11.1 nghttp2/1.69.0 ngtcp2/1.22.1 nghttp3/1.15.0 librtmp/2.3 mit-krb5/1.22.1 OpenLDAP/2.6.10 | curl 7.x+ | |
| P-10 | `docker ps` | ✅ | conteneurs: buffovf-target dvwa-target forensic-victim secure-linux-target sqli-app-target vsftpd-target waf-target  | vsftpd présent | |


## LAB 2.1 — Reconnaissance du conteneur Metasploitable

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| 2.1-01 | `nmap -sV -p 21,22,80,445,3306,5432 localhost` | ✅ | 21/tcp   open   ftp         vsftpd 2.3.4 | 21/tcp open ftp vsftpd 2.3.4 | |
| 2.1-02 | nmap SMB detection | ✅ | 445/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) | 445/tcp open netbios-ssn Samba | |
| 2.1-03 | nmap MySQL detection | ✅ | MySQL détecté | 3306/tcp open mysql | |
| 2.1-04 | nmap PostgreSQL detection | ✅ | PostgreSQL détecté | 5432/tcp open postgresql | |
| 2.1-05 | `nmap --script ftp-vsftpd-backdoor` | ✅ | vsftpd backdoor NSE ok | script exécuté sans erreur | |
| 2.1-06 | `nmap --script smb-vuln*` | ✅ | script smb-vuln exécuté | script exécuté | |
| 2.1-07 | mkdir rendu dossier | ✅ | dossier créé | rendu_labs/jour-02/recon/ | |
| 2.1-08 | syntax check recon.sh | ✅ | syntaxe valide | pas d'erreur bash | |


## LAB 2.2 — Exploitation vsftpd 2.3.4 (Backdoor)

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| 2.2-01 | nc banner FTP | ✅ | 220 (vsFTPd 2.3.4) | 220 (vsFTPd 2.3.4) | |
| 2.2-02 | load vsftpd_exploit.rc | ✅ | module chargé | use exploit/unix/ftp/vsftpd_234_backdoor | |
| 2.2-03 | backdoor trigger (manual) | ✅ | port 6200 ouvert (session existante) | port 6200 accessible | |
| 2.2-04 | syntax check lab_j2.sh | ✅ | syntaxe valide | pas d'erreur | |


## LAB 2.3 — Exploitation Samba + Kill Chain complète

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| 2.3-01 | load samba_exploit.rc | ✅ | module chargé | use exploit/multi/samba/usermap_script | |
| 2.3-02 | load samba_bind.rc | ✅ | module chargé | payload bind_netcat alternatif | |
| 2.3-03 | SMB port 445 | ✅ | 445/tcp open | Samba smbd accessible | |
| 2.3-04 | Persistance SSH key doc | ✅ | documented in course | 3 méthodes (SSH, cron, SUID) | vérifié document |
| 2.3-05 | attack-layer-jour2.json | ✅ | JSON valide | fichier ATT&CK valide | |
| 2.3-06 | env.sh METASPLOITABLE_IP | ✅ | IP: 
172.18.0.4 | IP du conteneur vsftpd | |


## LAB 2.5 — ARP Poisoning et attaque MITM avec BetterCap

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| 2.5-01 | bettercap installed | ✅ | bettercap v2.41.5 (built for linux amd64 with go1.24.9) | bettercap disponible | |
| 2.5-02 | ARP table | ✅ | entrées ARP trouvées | conteneurs dans table ARP | |
| 2.5-03 | docker inspect IPs | ✅ | DVWA: 172.18.0.3, vsftpd: 172.18.0.4 | IPs des conteneurs | |
| 2.5-04 | bettercap net.probe | ✅ | hôtes détectés | découverte réseau | |
| 2.5-05 | ARP table gateway | ✅ | passerelle dans table ARP | entrée ARP statique possible | Contre-mesure documentée |


## LAB 2.6 — Scanner de vulnérabilités Nessus

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| 2.6-01 | Nessus installed | ✅ | paquet installé | Nessus Essentials | |
| 2.6-02 | `nmap --script vuln` | ✅ | NSE vuln exécuté | détection CVE critiques | Alternative à Nessus |
| 2.6-03 | nessus_summary.txt creation | ✅ | fichier créé | résumé de scan | |
| 2.6-04 | apt-get update vsftpd | ✅ | mise à jour simulée | apt-get update OK | |



---

## Résumé global

| Métrique | Valeur |
|----------|--------|
| **Total tests** | 27 |
| **✅ Passés** | 36 |
| **❌ Échoués** | 1 |
| **⚠️ Avertissements** | 0 |
| **Date** | 2026-06-30 00:40:06 |

### Conclusion

**Des échecs ont été détectés.** Voir détails ci-dessus pour les tests ❌.

---

**Fin du rapport — 2026-06-30_00h39**
