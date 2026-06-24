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

## Sprint 1 — In Progress
- [ ] nmap wrapper avec parsing XML
- [ ] gobuster wrapper
- [ ] Tests avec conteneurs du cours

## Sprint 2-5 — Planned
- Voir backlog ci-dessus.
