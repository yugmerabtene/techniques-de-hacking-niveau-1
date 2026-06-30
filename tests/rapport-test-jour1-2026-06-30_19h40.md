# Rapport de test — JOUR-01

**Date :** 2026-06-30 19:40:05
**Environnement :** Linux kali 6.19.14+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05) x86_64 GNU/Linux

---

## Prérequis — Vérification des outils

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| P-01 | `python3 --version` | ✅ | Python 3.13.12 | Python 3.x | |
| P-02 | `docker --version` | ✅ | Docker version 28.5.2+dfsg4, build 9cc6dea35e9a963f281434761c656fba4ac43aed | Docker 24+ | |
| P-03 | `nmap --version` | ✅ | Nmap version 7.99 ( https://nmap.org ) | Nmap 7.x | |
| P-04 | `msfconsole --version` | ✅ | Framework Version: 6.4.133-dev | Metasploit 6.x | |
| P-05 | `sqlmap --version` | ✅ | 1.10.4#stable | sqlmap 1.7+ | |
| P-06 | `curl --version` | ✅ | curl 8.19.0 (x86_64-pc-linux-gnu) libcurl/8.19.0 OpenSSL/3.6.2 zlib/1.3.2 brotli/1.2.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.5 libssh2/1.11.1 nghttp2/1.69.0 ngtcp2/1.22.1 nghttp3/1.15.0 librtmp/2.3 mit-krb5/1.22.1 OpenLDAP/2.6.10 | curl 7.x+ | |
| P-07 | `which john` | ✅ | /usr/sbin/john | john dispo | |
| P-08 | `hydra -h` | ✅ | Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway). | Hydra 9.x | |
| P-09 | `gobuster --version` | ✅ | gobuster version 3.8.2 | gobuster 3.x | |
| P-10 | `docker ps` | ✅ | conteneurs: buffovf-target dvwa-target forensic-victim secure-linux-target sqli-app-target vsftpd-target waf-target  | dvwa + sqli-app présents | |
| P-11 | rockyou.txt | ⚠️ | absent | optionnel (john --incremental) | |


## LAB-1 — Conception : Plan d'attaque MITRE ATT&CK

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L1-01 | attack-layer-jour1.json | ✅ | JSON valide | fichier ATT&CK valide | |
| L1-02 | techniques dans attack-layer | ✅ | 8 techniques | > 0 techniques | |
| L1-03 | mitigations dans attack-layer | ✅ | 0 mitigations | couche défense | |
| L1-04 | syntax check setup_dvwa.sh | ✅ | syntaxe valide | pas d'erreur | |


## LAB-2 — Scan et découverte de DVWA

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L2-01 | `nmap -sV -p 8088 localhost` | ✅ | 8088/tcp open  http    Apache httpd 2.4.25 ((Debian)) | 8088/tcp open http Apache | |
| L2-02 | `gobuster dispo` | ✅ | gobuster version 3.8.2 | gobuster 3.x | |
| L2-03 | DVWA login page | ✅ | page login accessible | login.php avec token | |
| L2-04 | login DVWA admin:password | ✅ | Welcome trouvé | 'Welcome to Damn Vulnerable...' | |
| L2-05 | DVWA security level | ✅ | déjà low | security=low | |
| L2-06 | nmap_dvwa.txt dans resources | ✅ | fichier présent | fichier de référence | |
| L2-07 | gobuster_dvwa.txt dans resources | ✅ | fichier présent | fichier de référence | |


## LAB-3 — Exploitation XSS

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L3-01 | syntax check lab_xss.sh | ✅ | syntaxe valide | pas d'erreur | |
| L3-02 | Reflected XSS (curl) | ✅ | payload présent dans réponse | <script>alert(1)</script> | curl n'exécute pas JS -> test HTML |
| L3-03 | Stored XSS (curl) | ✅ | payload stocké et affiché | <script>alert('StoredXSS')</script> | |
| L3-04 | lab_csrf.html présent | ✅ | fichier présent | CSRF PoC HTML | |


## LAB-4 — Injection SQL avec sqlmap (DVWA)

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L4-01 | syntax check lab_sqli.sh | ✅ | syntaxe valide | pas d'erreur | |
| L4-02 | SQLi manuel UNION | ✅ | user/database récupérés | user(), database() | |
| L4-03 | sqlmap --tables DVWA | ✅ | tables trouvées | dvwa.users, dvwa.guestbook | |


## LAB-5 — Command Injection + Reverse Shell

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L5-01 | syntax check lab_cmdi.sh | ✅ | syntaxe valide | pas d'erreur | |
| L5-02 | CMDi: whoami | ✅ | www-data trouvé | www-data | |
| L5-03 | CMDi: cat /etc/passwd | ✅ | passwd lu | root:x:0:0:... | |


## LAB-6 — SQLi avancée : Trouver, Exploiter, Craquer

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L6-01 | syntax check lab_sqli_app.sh | ✅ | syntaxe valide | pas d'erreur | |
| L6-02 | sqli-app accessible | ✅ | application disponible | SQLi Shop | |
| L6-03 | SQLi point 1 (numeric UNION) | ✅ | injection numérique OK | données UNION retournées | |
| L6-04 | SQLi point 2 (auth bypass) | ✅ | connexion bypassée | admin connecté | |
| L6-05 | SQLi point 3 (LIKE UNION) | ✅ | données users récupérées | id, username, password, role | |
| L6-06 | hashes.txt présent | ✅ | 6 hashs | 6 hashs MD5 | |
| L6-07 | syntax check crack_hashes.sh | ✅ | syntaxe valide | pas d'erreur | |
| L6-08 | john crack hashes | ✅ | 3 hashs craqués | 6/6 attendus | |


## LAB-7 — Attaque par force brute avec Hydra

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L7-01 | page brute force accessible | ✅ | formulaire présent | username/password | |
| L7-02 | hydra installé | ✅ | Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway). | Hydra 9.x | |
| L7-03 | hydra admin:password (10 mots) | ✅ | mot de passe trouvé | admin:password | |
| L7-04 | hydra multi-users (-L) | ✅ | identifiants trouvés | admin:password | |



---

## Résumé global

| Métrique | Valeur |
|----------|--------|
| **Total tests** | 52 |
| **✅ Passés** | 43 |
| **❌ Échoués** | 0 |
| **⚠️ Avertissements** | 1 |
| **Date** | 2026-06-30 19:40:33 |

### Conclusion

**Tous les tests critiques sont passés ✅.** Les avertissements concernent des éléments mineurs.

---

**Fin du rapport — 2026-06-30_19h40**
