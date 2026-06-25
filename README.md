# Techniques de hacking et contre-mesures - Niveau 1

## Jour 1 : Introduction au hacking et aux vulnérabilités (6 heures)

- Introduction au hacking éthique (3h)
- Présentation des hackers éthiques et malveillants.
- Panorama des attaques courantes : phishing, DDoS, injections SQL.
- Outils utilisés par les attaquants : Metasploit, nmap, Wireshark.
- Travaux pratiques : analyse d'attaques réelles et prise en main des outils.
- Comprendre les vulnérabilités des systèmes (3h)
- Failles courantes : buffer overflow, XSS, CSRF.
- Méthodes d'exploitation par les attaquants.
- Travaux pratiques : simulation d'attaques basées sur des vulnérabilités connues.

## Jour 2 : Tests de pénétration et exploitation (6 heures)

- Réalisation d'un test de pénétration (3h)
- Méthodologies OWASP et PTES.
- Reconnaissance des systèmes cibles et identification des points d'attaque.
- Travaux pratiques : test de pénétration simple sur un réseau local.
- Exploitation des vulnérabilités et élévation de privilèges (3h)
- Techniques d'exploitation et d'escalade de privilèges.
- Accès aux ressources critiques.
- Travaux pratiques : exploitation d'une vulnérabilité pour obtenir des privilèges élevés.

## Jour 3 : Vulnérabilités avancées et contournement des protections (6 heures)

- Analyse des vulnérabilités avancées (3h)
- Étude des failles complexes : buffer overflow avancé, injections SQL.
- Contournement des firewalls, IDS/IPS.
- Travaux pratiques : attaques simulées pour contourner des mécanismes de sécurité.
- Techniques de contournement et attaques ciblées (3h)
- Techniques utilisées par les hackers pour échapper à la détection.
- Études de scénarios d'attaques ciblées.
- Travaux pratiques : simulation d'attaques avancées.

## Jour 4 : Contre-mesures et sécurisation des systèmes (6 heures)

- Mise en place de contre-mesures (3h)
- Mesures de protection : chiffrement, VPN, IDS/IPS.
- Durcissement des systèmes et réduction des risques.
- Travaux pratiques : configuration d'outils de sécurité.
- Évaluation des risques et impacts des attaques (3h)
- Analyse des impacts sur la confidentialité, l'intégrité et la disponibilité.
- Priorisation des actions correctives.
- Travaux pratiques : analyse des conséquences d'une attaque simulée.

## Jour 5 : Reporting et gestion des incidents (6 heures)

- Rapport de test de pénétration et recommandations (3h)
- Méthodologie de rédaction de rapports d'audit de sécurité.
- Proposition de solutions de remédiation.
- Travaux pratiques : rédaction d'un rapport de pentesting.
- Gestion des incidents de sécurité (3h)
- Détection, analyse et réponse aux incidents.
- Coordination et communication post-attaque.
- Travaux pratiques : simulation d'une attaque et mise en œuvre d'un plan de réponse.

---

## Hors-Série — KillChainAgent

- Développement d'un orchestrateur agentic de kill chain ATT&CK
- Stack : Python + FastAPI + TailwindCSS
- Architecture multi-agent (Supervisor, Recon, Exploit, PrivEsc, Persist, Report)
- Méthodologie Agile / Scrum / Sprint
- Référence au cours [agentic-developer-craftsmanship](https://github.com/yugmerabtene/agentic-developer-craftsmanship)

---

## Guide d'environnement

Avant de commencer, lisez [ENVIRONNEMENT.md](./ENVIRONNEMENT.md) pour configurer votre lab selon votre scénario (Kali hôte ou Kali Docker).

---

## A.2 Arborescence de travail

```
techniques-hacking-mdj/
├── README.md
├── JOUR-01-introduction-hacking-ethique-vulnerabilites.md
├── JOUR-02-tests-penetration-exploitation.md
├── JOUR-03-vulnerabilites-avancees-contournement-protections.md
├── JOUR-04-contre-mesures-securisation-systemes.md
├── JOUR-05-reporting-gestion-incidents-conformite.md
├── HORS-SERIE-AGENTIC.md
├── docker-compose.yml
│
├── docker/                               # Conteneurs cibles par journée
│   ├── buffovf/                          # J3 — Buffer overflow
│   │   ├── Dockerfile
│   │   └── vuln.c
│   ├── forensic/                         # J5 — Forensic + command injection
│   │   ├── Dockerfile
│   │   └── app/index.php
│   ├── secure-linux/                     # J4 — Durcissement Linux
│   │   └── Dockerfile
│   ├── sqli-app/                         # J1 — Application SQLi
│   │   ├── Dockerfile
│   │   ├── app/index.php
│   │   └── db/init.sql
│   └── waf/                              # J3 — WAF bypass
│       ├── Dockerfile
│       └── app/
│           ├── default.conf
│           └── index.php
│
├── hors-serie/                           # KillChainAgent — Orchestrateur agentic
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── SPRINT-PLANNING.md
│   ├── backend/
│   │   ├── main.py                       # FastAPI app (7 routes)
│   │   ├── models.py                     # Pydantic models
│   │   ├── database.py                   # SQLite
│   │   └── agents/
│   │       ├── __init__.py
│   │       ├── supervisor.py             # Orchestration kill chain
│   │       ├── recon.py                  # nmap + gobuster (TA0007)
│   │       ├── exploit.py                # msfconsole + sqlmap (TA0001)
│   │       ├── privesc.py                # LinPEAS + checks (TA0004)
│   │       ├── persist.py                # SSH/cron/systemd (TA0003)
│   │       └── report.py                 # Markdown + ATT&CK JSON
│   ├── frontend/
│   │   └── templates/
│   │       ├── base.html                 # Layout TailwindCSS
│   │       ├── dashboard.html            # Missions + kill chain
│   │       └── mission.html              # Vue live (auto-refresh)
│   └── tests/
│       ├── run_tests.sh
│       ├── test_agents.py                # 20 tests unitaires
│       └── test_api.py                   # 15 tests intégration
│
├── tests/                                # Scripts de validation environnement (local)
│   ├── run_all.sh
│   └── test_jour01.sh ... test_jour05.sh
│
└── search/                               # Veille réglementaire (local)
    ├── anssi-certfr.md
    ├── nis2-directive.md
    ├── rgs-france.md
    ├── normes-france-europe.md
    └── integration-cours.md
```
