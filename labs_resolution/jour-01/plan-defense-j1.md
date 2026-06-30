# Plan de défense — JOUR-01

## 1. Stratégie défensive

- **Périmètre** : DVWA (`:8088`), sqli-app (`:8083`), Apache/PHP, MySQL/SQLite
- **Objectif** : Appliquer 8 contre-mesures couvrant les 8 techniques ATT&CK du jour 1, de la prévention à la détection
- **Approche** : Defense in depth — réseau → application → authentification
- **Référentiel** : MITRE ATT&CK Enterprise v15

---

## 2. Matrice des contre-mesures

| Priorité | Technique ATT&CK | Risque | Mitigation ATT&CK | Contre-mesure | Statut |
|----------|-----------------|--------|-------------------|---------------|--------|
| **P0** | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell (CMDi) | Shell serveur | [M1018](https://attack.mitre.org/mitigations/M1018/) User Account Control | `disable_functions` php.ini | Appliquée (LAB-5) |
| **P0** | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing App (SQLi) | Exfiltration DB | [M1041](https://attack.mitre.org/mitigations/M1041/) Encrypt Sensitive Info | Requêtes préparées (PDO) | Conceptuelle (LAB-4, LAB-6) |
| **P1** | [T1189](https://attack.mitre.org/techniques/T1189/) Drive-by Compromise (XSS) | Vol de session | [M1013](https://attack.mitre.org/mitigations/M1013/) Application Hardening | `htmlspecialchars()`, CSP | Conceptuelle (LAB-3) |
| **P1** | [T1539](https://attack.mitre.org/techniques/T1539/) Steal Web Session Cookie | Session usurpable | [M1013](https://attack.mitre.org/mitigations/M1013/) Application Hardening | `session.cookie_httponly` | Appliquée (LAB-3) |
| **P1** | [T1203](https://attack.mitre.org/techniques/T1203/) Exploitation for Client Execution (CSRF) | Actions non autorisées | [M1018](https://attack.mitre.org/mitigations/M1018/) User Account Control | Token CSRF, SameSite | Appliquée (DVWA natif) |
| **P2** | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | Compromission compte | [M1036](https://attack.mitre.org/mitigations/M1036/) Account Lockout | fail2ban | Appliquée (LAB-7) |
| **P2** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Cracking | Mots de passe en clair | [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies | bcrypt/argon2 | Conceptuelle (LAB-6) |
| **P3** | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Scanning | Surface exposée | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention | Directory listing désactivé, Snort/Suricata | Appliquée (LAB-2) |

---

## 3. Détail des contre-mesures appliquées

### 3.1 T1046 — Apache Directory Listing : désactivé (LAB-2)

| Propriété | Valeur |
|-----------|--------|
| **Mitigation ATT&CK** | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention |
| **Risque** | Gobuster découvre `/config/`, `/setup.php` via directory listing |
| **Statut** | Appliquée dans `setup_dvwa.sh` (l. 47) et manuellement en LAB-2 |
| **Commande** | `docker exec dvwa-target bash -c "sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' /etc/apache2/apache2.conf && apache2ctl restart"` |
| **Vérification** | `curl -s -o /dev/null -w "%{http_code}" "http://localhost:8088/test-empty/"` → `403` |
| **Documentation cours** | Lignes 530-536 |

### 3.2 T1189 — htmlspecialchars() + CSP (LAB-3)

| Propriété | Valeur |
|-----------|--------|
| **Mitigation ATT&CK** | [M1013](https://attack.mitre.org/mitigations/M1013/) Application Hardening |
| **Risque** | `<script>` injecté est exécuté par le navigateur |
| **Statut** | Conceptuelle (code corrigé montré, pas appliqué sur DVWA) |
| **Code vulnérable** | `echo "Bonjour $name";` |
| **Code corrigé** | `echo htmlspecialchars($name);` |
| **Vérification** | `curl -s -b /tmp/dvwa_cookie.txt "http://localhost:8088/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E" \| grep -o "&lt;script&gt;"` → présent |

### 3.3 T1539 — HttpOnly Session Cookie (LAB-3)

| Propriété | Valeur |
|-----------|--------|
| **Mitigation ATT&CK** | [M1013](https://attack.mitre.org/mitigations/M1013/) Application Hardening |
| **Risque** | `document.cookie` exfiltre le PHPSESSID via XSS |
| **Statut** | Appliquée manuellement en LAB-3 |
| **Commande** | `docker exec dvwa-target bash -c "echo 'session.cookie_httponly = 1' >> /etc/php/*/apache2/php.ini && apache2ctl restart"` |
| **Vérification** | `docker exec dvwa-target bash -c "grep 'session.cookie_httponly' /etc/php/*/apache2/php.ini"` → `session.cookie_httponly = 1` |
| **Documentation cours** | Lignes 671-683 |

### 3.4 T1190 — Requêtes préparées / PDO (LAB-4, LAB-6)

| Propriété | Valeur |
|-----------|--------|
| **Mitigation ATT&CK** | [M1041](https://attack.mitre.org/mitigations/M1041/) Encrypt Sensitive Information |
| **Risque** | Injection SQL via `$_GET['id']` |
| **Statut** | Conceptuelle (code corrigé montré, 3 patterns en LAB-6) |
| **Code vulnérable** | `$query = "SELECT * FROM users WHERE user_id = '$id'";` |
| **Code corrigé** | `$stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?"); $stmt->execute([$id]);` |
| **Vérification** | `sqlmap -u "http://localhost:8088/vulnerabilities/sqli/?id=1&Submit=Submit" --load-cookies=/tmp/dvwa_cookie.txt --batch 2>&1 \| grep -o "not injectable"` → OK |

### 3.5 T1203 — Token CSRF (DVWA natif + LAB-2)

| Propriété | Valeur |
|-----------|--------|
| **Mitigation ATT&CK** | [M1018](https://attack.mitre.org/mitigations/M1018/) User Account Control |
| **Risque** | Formulaire `/vulnerabilities/csrf/` change le password sans consentement |
| **Statut** | Appliquée (DVWA v1.10+ intègre un token CSRF sur tous les formulaires) |
| **Commande extraction** | `TOKEN=$(curl -s -c /tmp/dvwa_cookie.txt "http://localhost:8088/login.php" \| grep -oP "user_token' value='\K[a-f0-9]+")` |
| **Documentation cours** | Lignes 483-503 (protocole de connexion LAB-2) |

### 3.6 T1059.004 — disable_functions php.ini (LAB-5)

| Propriété | Valeur |
|-----------|--------|
| **Mitigation ATT&CK** | [M1018](https://attack.mitre.org/mitigations/M1018/) User Account Control |
| **Risque** | `; whoami` → exécution de commandes shell |
| **Statut** | Appliquée manuellement en LAB-5 |
| **Commande** | `docker exec dvwa-target bash -c "sed -i 's/disable_functions =.*/disable_functions = system,exec,passthru,shell_exec,popen,proc_open/' /etc/php/*/apache2/php.ini && apache2ctl restart"` |
| **Vérification 1** | `docker exec dvwa-target bash -c "php -r 'echo function_exists(\"shell_exec\") ? \"actif\" : \"inactif\";'"` → `inactif` |
| **Vérification 2** | `curl -s "http://localhost:8088/vulnerabilities/exec/" --data "ip=127.0.0.1;whoami&Submit=Submit" -b /tmp/dvwa_cookie.txt \| grep -c "www-data"` → `0` |
| **Documentation cours** | Lignes 884-913 |

### 3.7 T1110 — fail2ban Account Lockout (LAB-7)

| Propriété | Valeur |
|-----------|--------|
| **Mitigation ATT&CK** | [M1036](https://attack.mitre.org/mitigations/M1036/) Account Lockout |
| **Risque** | Hydra essaie 14M mots de passe via `login.php` |
| **Statut** | Appliquée manuellement en LAB-7 |
| **Commande installation** | `docker exec dvwa-target bash -c "apt-get update && apt-get install -y fail2ban"` |
| **Fichier jail.local** | `/etc/fail2ban/jail.local` : `[apache-dvwa] enabled = true, port = http,https, filter = apache-auth, logpath = /var/log/apache2/error.log, maxretry = 5, findtime = 600, bantime = 900` |
| **Commande reload** | `fail2ban-client reload` |
| **Vérification** | `docker exec dvwa-target bash -c "fail2ban-client status apache-dvwa"` → `Currently banned: 0` |
| **Documentation cours** | Lignes 1419-1455 |

### 3.8 T1110.001 — bcrypt/argon2 Password Hashing (LAB-6)

| Propriété | Valeur |
|-----------|--------|
| **Mitigation ATT&CK** | [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies |
| **Risque** | Hashs MD5 craqués en 5 min par John |
| **Statut** | Conceptuelle (code corrigé montré, pas appliqué sur DVWA) |
| **Code vulnérable** | `md5($password)` |
| **Code corrigé** | `$hash = password_hash($password, PASSWORD_BCRYPT);` / `password_verify($password, $hash)` |
| **Documentation cours** | Lignes 1221-1256 |

---

## 4. Plan de réponse et détection

### 4.1 Détection par technique

| Technique | Log source | Pattern à chercher | Alerte |
|-----------|-----------|-------------------|--------|
| T1046 Scan | `/var/log/apache2/access.log` | Plusieurs `CONNECT` ou requêtes sur `/`, `/login.php`, `/config/` depuis même IP en < 5s | Snort règle `scan.rules` |
| T1189 XSS | `/var/log/apache2/error.log` | Paramètre `name=` contenant `<script>` (Reflected), ou `txtName=` contenant `<script>` (Stored) | ModSecurity règle 941100 |
| T1203 CSRF | `/var/log/apache2/access.log` | POST vers `/vulnerabilities/csrf/` sans référent interne | Script d'audit de logs |
| T1190 SQLi | `/var/log/apache2/access.log` | Paramètres contenant `OR 1=1`, `UNION SELECT`, `' --` | ModSecurity règle 942100 |
| T1059.004 CMDi | `/var/log/apache2/access.log` | Paramètres contenant `; whoami`, `\|\|`, `$(...)` | ModSecurity règle 932100 |
| T1110 Brute Force | `/var/log/apache2/error.log` | 5+ `authentication failure` en 10 min | fail2ban défini ci-dessus |
| T1110.001 Cracking | — | Pas de détection temps réel (offline) | Audit des hashs en base |
| T1539 Vol cookie | `/var/log/apache2/access.log` | Requête sortante vers IP externe avec cookie en paramètre | Règle proxy sortant |

### 4.2 Playbook de réponse incident (IR-01)

1. **Détection** : Alerte ModSecurity/fail2ban déclenchée
2. **Analyse** : `cat /var/log/apache2/access.log \| grep IP_ATTAQUANT`
3. **Confinement** : `ufw deny from IP_ATTAQUANT` ou `fail2ban-client set apache-dvwa banip IP_ATTAQUANT`
4. **Éradication** : Vérifier `disable_functions` et `cookie_httponly` toujours actifs
5. **Restauration** : Restart du container (`docker restart dvwa-target`) si compromis
6. **Post-mortem** : Mettre à jour le plan de défense

---

## 5. Roadmap de déploiement

| Phase | Actions | Techniques couvertes | Effort |
|-------|---------|---------------------|--------|
| **Phase 1 — Critique** (immédiat) | `disable_functions` php.ini, PDO pour toutes les requêtes SQL | T1059.004, T1190 | ~2h |
| **Phase 2 — Application** (jour 1) | `htmlspecialchars()`, CSP, HttpOnly, CSRF tokens | T1189, T1539, T1203 | ~1h |
| **Phase 3 — Authentification** (semaine 1) | fail2ban, bcrypt pour tous les mots de passe | T1110, T1110.001 | ~2h |
| **Phase 4 — Réseau** (semaine 2) | WAF ModSecurity, Snort/Suricata, `ufw default deny` | T1046, T1190 | ~1h |

---

## 6. Alignement ATT&CK Navigator

Référencer `defense-j1.json` pour la visualisation des couches de défense.

| Mitigation ATT&CK | Techniques couvertes | Couleur dans Navigator |
|-------------------|---------------------|----------------------|
| [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention | T1046 | `#2ecc71` |
| [M1013](https://attack.mitre.org/mitigations/M1013/) Application Hardening | T1189, T1539 | `#2ecc71` |
| [M1041](https://attack.mitre.org/mitigations/M1041/) Encrypt Sensitive Information | T1190 | `#2ecc71` |
| [M1018](https://attack.mitre.org/mitigations/M1018/) User Account Control | T1059.004, T1203 | `#2ecc71` |
| [M1036](https://attack.mitre.org/mitigations/M1036/) Account Lockout | T1110 | `#2ecc71` |
| [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies | T1110.001 | `#2ecc71` |

---
