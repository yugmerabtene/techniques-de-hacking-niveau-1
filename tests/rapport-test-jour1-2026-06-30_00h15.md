# Rapport de test — JOUR-01

**Date :** 2026-06-30 00:15:54
**Environnement :** Linux kali 6.19.14+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05) x86_64 GNU/Linux

---

## Prérequis — Vérification des outils
| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
### 1. Versions des outils
| P-01 | `python3 --version` | ✅ | erreur | Python 3.x | |
| P-02 | `docker --version` | ✅ | erreur | Docker 24+ | |
| P-03 | `docker compose version` | ✅ | Docker Compose version 2.40.3-3 | version dispo | |
| P-04 | `nmap --version` | ✅ | Nmap version 7.99 ( https://nmap.org ) | Nmap 7.x | |
| P-05 | `msfconsole --version` | ✅ | Framework Version: 6.4.133-dev | Metasploit 6.x | |
| P-06 | `sqlmap --version` | ✅ | 1.10.4#stable | sqlmap 1.7+ | |
| P-07 | `which nc` | ✅ | /usr/bin/nc | /usr/bin/nc | |
| P-08 | `gobuster --version` | ✅ | gobuster version 3.8.2 | gobuster dispo | |
| P-09 | `john --version` | ❌ | Created directory: /home/kali/.john
Unknown option: "--version" | John the Ripper | |
| P-10 | `hydra --version` | ✅ | Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway). | Hydra v9.x | |
| P-11 | `curl --version` | ✅ | curl 8.19.0 (x86_64-pc-linux-gnu) libcurl/8.19.0 OpenSSL/3.6.2 zlib/1.3.2 brotli/1.2.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.5 libssh2/1.11.1 nghttp2/1.69.0 ngtcp2/1.22.1 nghttp3/1.15.0 librtmp/2.3 mit-krb5/1.22.1 OpenLDAP/2.6.10 | curl 7.x+ | |
| P-12 | `git --version` | ✅ | git version 2.53.0 | git dispo | |
| P-13 | `hashcat --version` | ✅ | non installé | hashcat dispo | |
| P-14 | `id | grep docker` | ❌ | NOT in docker group | user in docker group | |

### 2. Arborescence du dépôt
```
total 304
drwxrwxr-x 11 kali kali  4096 30 juin  00:15 .
drwx------ 25 kali kali  4096 30 juin  00:16 ..
drwxrwxr-x  7 kali kali  4096 29 juin  20:34 docker
-rw-rw-r--  1 kali kali  5120 29 juin  20:34 docker-compose.yml
-rw-rw-r--  1 kali kali  1377 29 juin  21:02 env.sh
drwxrwxr-x  3 kali kali  4096 29 juin  20:43 extra
drwxrwxr-x  7 kali kali  4096 29 juin  23:44 .git
-rw-rw-r--  1 kali kali    59 29 juin  20:36 .gitignore
drwxrwxr-x  2 kali kali  4096 29 juin  23:43 img
-rw-rw-r--  1 kali kali 74717 29 juin  23:49 JOUR-01-introduction-hacking-ethique-vulnerabilites.md
-rw-rw-r--  1 kali kali 47937 29 juin  21:20 JOUR-02-tests-penetration-exploitation.md
-rw-rw-r--  1 kali kali 33829 29 juin  21:21 JOUR-03-vulnerabilites-avancees-contournement-protections.md
-rw-rw-r--  1 kali kali 32007 29 juin  21:21 JOUR-04-contre-mesures-securisation-systemes.md
-rw-rw-r--  1 kali kali 35216 29 juin  21:21 JOUR-05-reporting-gestion-incidents-conformite.md
drwxrwxr-x  7 kali kali  4096 29 juin  21:20 labs
drwxrwxr-x  7 kali kali  4096 29 juin  21:05 labs_resolution
drwxrwxr-x  4 kali kali  4096 29 juin  20:34 .opencode
-rw-rw-r--  1 kali kali  3572 29 juin  21:03 PLAN_SCHEMAS.md
-rw-rw-r--  1 kali kali  3424 29 juin  20:34 README.md
drwxrwxr-x  7 kali kali  4096 29 juin  21:20 rendu_labs
drwxrwxr-x  2 kali kali  4096 30 juin  00:15 tests
-rw-rw-r--  1 kali kali   104 29 juin  20:29 token.txt
```


---

## LAB-1 — Conception : Plan d'attaque MITRE ATT&CK

### Étape 1 — Cartographier les cibles
| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L1-01 | `mkdir -p rendu_labs/jour-01` | ✅ | dossier créé | dossier créé | |
| L1-02 | `source env.sh` | ✅ | variables chargées | pas d'erreur | |
| L1-03 | `docker compose ps --services` | ⚠️ | erreur | liste des services | |

### Étape 4 — Lancer l'infrastructure
| L1-04 | `docker compose up -d --build dvwa sqli-app` | ❌ | unable to get image 'vulnerables/web-dvwa:latest': permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.51/images/vulnerables/web-dvwa:latest/json": dial unix /var/run/docker.sock: connect: permission denied | conteneurs lancés | |
| L1-05 | `curl http://localhost:8088/login.php` | ✅ | HTTP 200 | 200 | |
| L1-06 | `curl http://localhost:8083` | ✅ | HTTP 200 | 200 | |


---

## LAB-2 — Scan et découverte de DVWA

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L2-01 | `nmap -sV -p 8088 localhost` | ✅ | 8088/tcp open  http    Apache httpd 2.4.25 ((Debian)) | 8088/tcp open http Apache | |
| L2-01b | sauvegarde nmap_dvwa.txt | ✅ | fichier créé | fichier créé | |
| L2-02 | `gobuster dir -u http://localhost:8088 -w common.txt -q` | ✅ | .htpasswd            (Status: 403) [Size: 295];.hta                 (Status: 403) [Size: 290];.htaccess            (Status: 403) [Size: 295];config               (Status: 301) [Size: 314] [--> http://localhost:8088/config/];docs                 (Status: 301) [Size: 312] [--> http://localhost:8088/docs/];external             (Status: 301) [Size: 316] [--> http://localhost:8088/external/];favicon.ico          (Status: 200) [Size: 1406];index.php            (Status: 302) [Size: 0] [--> login.php];php.ini              (Status: 200) [Size: 148];phpinfo.php          (Status: 302) [Size: 0] [--> login.php];robots.txt           (Status: 200) [Size: 26];server-status        (Status: 403) [Size: 299]; | /login.php, /vulnerabilities, /config | |
| L2-02b | sauvegarde gobuster_dvwa.txt | ✅ | fichier créé | fichier créé | |
| L2-03 | `curl login DVWA` | ❌ | pas de Welcome | Welcome | |
| L2-04 | `curl security=low` | ✅ | cookie mis à jour: localhost	FALSE	/	FALSE	0	security	low | security=low dans cookie | |


---

## LAB-3 — Exploitation XSS

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L3-01 | `curl XSS Reflected` | ❌ | script tag non trouvé dans la réponse | <script>...</script> dans la réponse | Test via curl (sans navigateur) |
| L3-02 | `XSS vol cookie` | ⚠️ | pas de requête reçue (le script n'est pas exécuté côté serveur par curl, normal) | cookie PHPSESSID reçu | curl n'exécute pas JS, test nécessite Firefox pour confirmation |
| L3-03 | `curl Stored XSS (POST guestbook)` | ❌ | script non trouvé dans la réponse | <script> stocké en BDD visible | |
| L3-04 | `curl Stored XSS (reload)` | ❌ | script disparu au rechargement | script persistant au rechargement | |


---

## LAB-4 — Injection SQL avec sqlmap (DVWA)

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L4-01 | `curl SQLi manuel` | ❌ | erreur | 5 | |
| L4-02 | `sqlmap --dump dvwa.users` | ❌ | extraction incomplète | admin, gordonb, 1337, pablo, smithy + hashs | |


---

## LAB-5 — Command Injection + Reverse Shell

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L5-01 | `CMDi: 127.0.0.1; whoami` | ❌ | www-data non trouvé | www-data | |
| L5-02 | `CMDi: 127.0.0.1; ls /etc/` | ❌ | ls /etc/ exécuté | passwd dans /etc/ | |
| L5-03 | `ip addr show docker0` | ✅ | IP docker0: 172.17.0.1 | 172.17.0.1 | |
| L5-04 | `Reverse shell via nc` | ⚠️ | pas de connexion reçue (peut dépendre de la config réseau) | connection from 172.17.0.x | Peut nécessiter ajustement IP |
| L5-05 | `Commande via reverse shell` | ⚠️ | non testé (pas de reverse shell) | whoami -> www-data | |


---

## LAB-6 — SQLi avancée : Trouver, Exploiter, Craquer

### Étape 1 — Trouver les injections manuellement
| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L6-01 | `?id=1 normal` | ✅ | 1 produits | 1 produit | |
| L6-02 | `?id=1 OR 1=1` | ✅ | 1 lignes | 6 (tous les produits) | |
| L6-03 | `?id=1 AND 1=2` | ✅ | 'Aucun produit' | 'Aucun produit trouvé' | |
| L6-04 | `login: admin' --` | ❌ | bypass échoué | Connecté en tant que admin | |
| L6-05 | `login: ' OR '1'='1' --` | ✅ | 1 utilisateurs connectés | 6 (tous) | |
| L6-06 | `?filter=john normal` | ✅ | 1 cellules | 4 cellules (1 user) | |
| L6-07 | `?filter=%' UNION SELECT...` | ✅ | UNION retourne des données:     <div class='query'>Query: SELECT id, username, email, role FROM users WHERE username LIKE &#039;%%&#039; UNION SELECT 1,username,password,email FROM users --%&#039;</div><table><tr><th>ID</th><th>Username</th><th>Email</th><th>Rôle</th></tr><tr><td>1</td><td>admin</td><td>5f4dcc3b5aa765d61d8327deb882cf99</td><td>admin@shop.local</td></tr><tr><td>1</td><td>admin</td><td>admin@shop.local</td><td>admin</td></tr><tr><td>1</td><td>flag_user</td><td>21232f297a57a5a743894a0e4a801fc3</td><td>flag@secret.local</td></tr><tr><td>1</td><td>guest</td><td>098f6bcd4621d373cade4e832627b4f6</td><td>guest@shop.local</td></tr><tr><td>1</td><td>jane_dev</td><td>e99a18c428cb38d5f260853678922e03</td><td>jane@shop.local</td></tr><tr><td>1</td><td>john_doe</td><td>482c811da5d5b4bc6d497ffa98491e38</td><td>john@shop.local</td></tr><tr><td>1</td><td>supervisor</td><td>0d107d09f5bbe40cade3de5c71e9e9b7</td><td>super@shop.local</td></tr><tr><td>2</td><td>john_doe</td><td>john@shop.local</td><td>user</td></tr><tr><td>3</td><td>jane_dev</td><td>jane@shop.local</td><td>dev</td></tr><tr><td>4</td><td>supervisor</td><td>super@shop.local</td><td>supervisor</td></tr><tr><td>5</td><td>guest</td><td>guest@shop.local</td><td>user</td></tr><tr><td>6</td><td>flag_user</td><td>flag@secret.local</td><td>admin</td></tr></table><p class='success'>12 résultat(s)</p> | données des users | |

### Étape 2 — Exploitation automatisée avec sqlmap
| L6-08 | `sqlmap --tables (sqli-app)` | ✅ | tables non trouvées | products, users | |
| L6-09 | `sqlmap --columns users` | ✅ | colonnes trouvées | id, username, password, email, role | |
| L6-10 | `sqlmap --dump users` | ✅ | extraction incomplète | 6 users avec hashs MD5 | |

### Étape 3 — Craquer les hashs
| L6-11 | `création hashes.txt` | ✅ | fichier créé | 6 hashs | |
| L6-12 | `décompression rockyou.txt` | ✅ | rockyou.txt dispo ( bytes) | fichier présent | |
| L6-13 | `john` | ⚠️ | craquage partiel | 6 craqués | |

### Étape 4 — Extraire le flag caché
| L6-14 | `sqlmap --dump products.secret_flag` | ✅ | flag non trouvé | FLAG{sql_injection_master} | |


---

## LAB-7 — Attaque par force brute avec Hydra

| Test | Commande | Statut | Résultat obtenu | Résultat attendu | Notes |
|------|----------|--------|----------------|-------------------|-------|
| L7-00 | `curl cookie check` | ✅ | HTTP 200 | 200 | |
| L7-01 | `grep form fields` | ✅ | name="username" name="password" name="Login"  | username password Login | |
| L7-02 | `curl mauvais password` | ✅ | '' | 'Login failed' | |
| L7-03 | `hydra -l admin -P rockyou.txt` | ❌ | mot de passe non trouvé | admin:password | |
| L7-04 | `hydra -L logins.txt -P rockyou.txt -F` | ❌ | rien trouvé | admin:password | |


---

## Résumé global

| Métrique | Valeur |
|----------|--------|
| **Total tests** | 64 |
| **✅ Passés** | 37 |
| **❌ Échoués** | 14 |
| **⚠️ Avertissements** | 5 |
| **Date** | 2026-06-30 00:18:54 |

### Conclusion

**Des échecs ont été détectés.** Voir détails ci-dessus pour les tests ❌.

---

**Fin du rapport — 2026-06-30_00h15**
