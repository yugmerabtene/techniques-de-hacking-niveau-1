# KillChainAgent — Sprint Planning

## Vision
Automatiser une kill chain ATT&CK via des agents specialises.

## Backlog

| ID | User Story | Points | Sprint |
|---|---|---|---|
| US-01 | Setup projet (FastAPI + Tailwind + Docker) | 3 | 0 |
| US-02 | ReconAgent : nmap -> JSON, gobuster | 5 | 1 |
| US-03 | ExploitAgent : msfconsole + sqlmap orchestration | 8 | 2 |
| US-04 | PrivEscAgent : LinPEAS parsing | 5 | 2 |
| US-05 | SupervisorAgent : orchestration kill chain complete | 8 | 3 |
| US-06 | PersistAgent : SSH key + cron + SUID | 3 | 3 |
| US-07 | ReportAgent : Markdown + ATT&CK JSON | 5 | 4 |
| US-08 | Dashboard TailwindCSS | 5 | 4 |
| US-09 | Tests + Docker packaging | 5 | 5 |

## Sprints sur 5 jours

```
Jour 1 (30 min) -> Sprint 0 : Setup projet
Jour 2 (30 min) -> Sprint 1 : ReconAgent
Jour 3 (30 min) -> Sprint 2 : ExploitAgent + PrivEscAgent
Jour 4 (30 min) -> Sprint 3 : SupervisorAgent + PersistAgent
Jour 5 (30 min) -> Sprint 4 : ReportAgent + Dashboard
```

## Sprint 0 — Done
- [x] Structure projet
- [x] FastAPI main.py, models.py, database.py
- [x] Tous les agents (squelettes)
- [x] Dashboard TailwindCSS
- [x] Dockerfile + requirements.txt

## Sprint 1 — Done
- [x] nmap wrapper avec parsing XML
- [x] gobuster wrapper
- [x] Tests avec conteneurs du cours

## Sprint 2 — Done
- [x] ExploitAgent : msfconsole avec fichier .rc temporaire
- [x] ExploitAgent : sqlmap wrapper fonctionnel
- [x] PrivEscAgent : run_linpeas() + parse_linpeas_output()
- [x] PrivEscAgent : checks manuels (SUID, sudo, cron, kernel, capabilities)

## Sprint 3 — Done
- [x] SupervisorAgent : execute() avec passage de contexte entre agents
- [x] ExploitAgent / PrivEscAgent : acceptent le contexte recon/exploit
- [x] PersistAgent : SSH key générée, cron + systemd concrets
- [x] ReportAgent : contexte complet + ATT&CK Navigator JSON

## Sprint 5 — Done
- [x] Tests unitaires : 20 tests (Supervisor, PrivEsc parsing, Persist, Report)
- [x] Tests intégration : 15 tests API (health, missions CRUD, execute, full flow)
- [x] Script run_tests.sh pour lancer la suite complète
- [x] Docker : killchain-agent ajouté à docker-compose.yml (profil `agent`)
- [x] 12/12 fichiers Python : syntaxe OK
- [x] 20/20 tests unitaires passent
- [x] Tests API à lancer dans le conteneur Docker (deps Kali)

---

## Récapitulatif — Tous les sprints terminés

| Sprint | User Stories | Status |
|---|---|---|
| Sprint 0 | US-01 Setup projet | ✅ |
| Sprint 1 | US-02 ReconAgent | ✅ |
| Sprint 2 | US-03 + US-04 ExploitAgent + PrivEscAgent | ✅ |
| Sprint 3 | US-05 + US-06 SupervisorAgent + PersistAgent | ✅ |
| Sprint 4 | US-07 + US-08 ReportAgent + Dashboard | ✅ |
| Sprint 5 | US-09 Tests + Docker packaging | ✅ |

### Pour lancer

```bash
# Backend (local)
cd hors-serie && pip install -r requirements.txt && cd backend && python3 main.py

# Backend (Docker)
docker compose --profile agent up -d killchain

# Tests
cd hors-serie && pip install -r requirements.txt && python3 -m pytest tests/
```
