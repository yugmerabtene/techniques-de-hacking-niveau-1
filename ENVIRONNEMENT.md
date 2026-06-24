# Guide : Environnement de Lab

Ce document explique les deux scénarios de déploiement possibles pour la formation.

---

## Scénario A — Kali Linux en machine hôte (recommandé)

```
┌─────────────────────────────────────────────────────┐
│  Kali Linux (hôte)                                   │
│                                                       │
│  Terminal Kali                                        │
│  → nmap, msfconsole, sqlmap, curl, nc, python3       │
│    ──── IP : hostname -I ────                         │
│         │                         │                   │
│         ▼                         ▼                   │
│  ┌──────────────┐         ┌──────────────┐           │
│  │ Docker DVWA  │         │ Docker vsftpd│  ...      │
│  │ :8080        │         │ :21, :445    │           │
│  └──────────────┘         └──────────────┘           │
│                                                       │
│  Accès : docker compose up -d                         │
│  Cibles : localhost:8080, localhost:21, etc.          │
│  Reverse shell : IP Kali = hostname -I                │
│  Depuis conteneur → Kali : 172.17.0.1 (docker0)       │
└─────────────────────────────────────────────────────┘
```

### Installation

```bash
# Vérifier Docker
docker --version && docker compose version

# Cloner le dépôt
cd ~/cours-hacking
git clone https://github.com/yugmerabtene/techniques-hacking-mdj.git repo
cd repo

# Lancer tous les conteneurs
docker compose up -d --build

# Vérifier
bash scripts/network-diag.sh
```

### Références dans les labs (Scénario A)

| Concept | Commande |
|---|---|
| Cible DVWA | `curl http://localhost:8080/` |
| Cible vsftpd | `nmap -sV -p 21 localhost` |
| Cible WAF | `curl http://localhost:8081/?id=1` |
| msfconsole | `set RHOSTS localhost` |
| Reverse shell IP | `$KALI_IP` (trouvée via `hostname -I`) |
| Depuis conteneur → Kali | `172.17.0.1` (IP docker0 bridge) |

---

## Scénario B — Kali Linux dans Docker

```
┌───────────────────────────────────────────────────────┐
│  Docker Network : pentest-lab                          │
│                                                         │
│  ┌──────────────────┐    ┌──────────────────┐          │
│  │ kali-attacker    │    │ dvwa             │          │
│  │ (Kali Docker)    │───▶│ :80              │          │
│  │ nmap, msfconsole │    └──────────────────┘          │
│  │                  │    ┌──────────────────┐          │
│  │                  │───▶│ vsftpd           │          │
│  │                  │    │ :21, :445...     │          │
│  └──────────────────┘    └──────────────────┘          │
│         │                                               │
│         │  ┌──────────────────┐                        │
│         └─▶│ buffovf :9001    │                        │
│            │ waf-target :80   │                        │
│            │ secure-linux :22 │                        │
│            │ forensic :80     │                        │
│            └──────────────────┘                        │
│                                                         │
│  Cibles accessibles par nom de service Docker          │
└───────────────────────────────────────────────────────┘
```

### Installation

```bash
# Lancer TOUS les conteneurs (incluant kali-attacker)
docker compose --profile full up -d --build

# Entrer dans le Kali Docker
docker exec -it kali-attacker bash

# À l'intérieur du Kali Docker :
apt update && apt install -y nmap metasploit-framework sqlmap
bash /scripts/network-diag.sh
```

### Références dans les labs (Scénario B)

| Concept | Commande |
|---|---|
| Cible DVWA | `curl http://dvwa/` |
| Cible vsftpd | `nmap -sV vsftpd` |
| Cible WAF | `curl http://waf-target/?id=1` |
| msfconsole | `set RHOSTS vsftpd` |
| Reverse shell IP | `$KALI_IP` (IP du conteneur Kali : `hostname -I`) |
| Depuis conteneur cible → Kali | nom de service `kali-attacker` ou IP Docker |

---

## Comment savoir dans quel scénario je suis ?

```bash
# Lancer le diagnostic automatique
bash ~/cours-hacking/repo/scripts/network-diag.sh
```

Le script détecte automatiquement :
- Si vous êtes dans un conteneur Docker → Scénario B
- Sinon → Scénario A
- Affiche les IPs, les conteneurs accessibles, et les commandes adaptées

---

## Tableau récapitulatif des ports

| Service | Conteneur | Port exposé (hôte) | Port interne (Docker) |
|---|---|---|---|
| DVWA | `dvwa` | 8080 | 80 |
| vsftpd 2.3.4 | `vsftpd` | 21 | 21 |
| Samba 3.0.20 | `vsftpd` | 445 | 445 |
| MySQL 5.0.51a | `vsftpd` | 3306 | 3306 |
| Buffer Overflow | `buffovf` | 9001 | 9001 |
| WAF Target | `waf-target` | 8081 | 80 |
| Secure Linux | `secure-linux` | 2222 | 22 |
| Forensic Victim | `forensic-victim` | 8082 | 80 |
| Kali Attacker (B) | `kali-attacker` | — | — |

---

## Dépannage rapide

```bash
# Conteneurs down ?
docker compose --profile full up -d --build

# Port déjà utilisé ?
sudo lsof -i :8080
# → Changer le port exposé dans docker-compose.yml

# Reverse shell ne connecte pas ?
# Scénario A : vérifier que les conteneurs peuvent pinger Kali
docker exec dvwa-target ping 172.17.0.1

# Scénario B : vérifier que les conteneurs peuvent pinger kali-attacker
docker exec dvwa-target ping kali-attacker

# WAF ne bloque pas ?
docker compose logs waf-target | grep -i error
```
