# Plan Schémas Techniques

## Légende
- ✅ Schéma existant
- ❌ Schéma manquant
- ⚠️ Schéma partiel ou à améliorer

---

## JOUR 01 — Introduction

| Lab | Technique | Schéma existant | Statut |
|-----|-----------|-----------------|--------|
| 1.1 Scan | T1046 Nmap | Topologie réseau (Fig 1) | ✅ |
| 1.2 XSS | T1189 Drive-by Compromise | Flux XSS réfléchie (Fig 5) | ✅ |
| 1.3 SQLi | T1190 Exploit Public-Facing | — | ❌ |
| 1.4 CMDi | T1059.004 Unix Shell | — | ❌ |
| 1.5 SQLi avancée | T1190 + cracking | — | ❌ |
| 1.6 Brute-force | T1110 Brute Force | — | ❌ |

### Schémas à créer pour J1
- **Fig 5b — SQLi UNION** : flux de la requête SQL injectée vers la base, avec jointure des résultats
- **Fig 5c — Command Injection** : diagramme montrant le ping → system() → reverse shell
- **Fig 5d — Brute-force Hydra** : boucle de tentatives login/mdp avec dictionnaire

---

## JOUR 02 — Tests de pénétration

| Lab | Technique | Schéma existant | Statut |
|-----|-----------|-----------------|--------|
| 2.1 Recon | T1046 Nmap | Kill chain J2 (Fig 7) | ✅ |
| 2.2 vsftpd | T1190 Exploit | Flux vsftpd backdoor (Fig 8) | ✅ |
| 2.3 Samba | T1210 Exploit Remote Services | — | ❌ |
| 2.4 Persistance | T1098.004 SSH Keys | — | ❌ |
| 2.5 MITM | T1557.002 ARP Poisoning | Attaque MITM (Fig 8b) | ✅ |
| 2.6 Nessus | T1046/T1595 Scanning | — | ❌ |

### Schémas à créer pour J2
- **Fig 8c — Samba usermap_script** : flux de l'exploitation Samba, de la requête malveillante à l'exécution de commande
- **Fig 8d — Persistance SSH** : copie de clé publique → authorized_keys
- **Fig 8e — Nessus** : architecture du scan Nessus avec résultats

---

## JOUR 03 — Contournement

| Lab | Technique | Schéma existant | Statut |
|-----|-----------|-----------------|--------|
| 3.1 BOF | T1068 PrivEsc | Stack frame (Fig 9) + Chaîne BOF (Fig 10) | ✅ |
| 3.2 WAF Bypass | T1562.001 Impair Defenses | Contournement WAF (Fig 11) | ✅ |
| 3.3 Trojan | T1204.002 User Execution | — | ❌ |

### Schémas à créer pour J3
- **Fig 11b — Trojan Windows** : chaîne de livraison trojan → exécution → beacon HTTPS → post-exploitation

---

## JOUR 04 — Contre-mesures

| Lab | Technique | Schéma existant | Statut |
|-----|-----------|-----------------|--------|
| 4.1 Hardening | T1110/T1068/T1046 | Pipeline durcissement (Fig 13) | ✅ |
| 4.2 ELK SOC | T1190/T1110/T1046 | Architecture ELK (Fig 15) | ✅ |

### Schémas à créer pour J4
- Rien de critique (tous les schémas présents)

---

## JOUR 05 — Reporting

| Lab | Technique | Schéma existant | Statut |
|-----|-----------|-----------------|--------|
| 5.1 Forensique | T1190→T1059→T1505→T1548 | Cycle incident (Fig 13) + Chrono NIS2 (Fig 14) + Procédure NIS2 (Fig 15) | ✅ |
| 5.2 Rapport | T1190/T1189/T1210 | — | ❌ |

### Schémas à créer pour J5
- **Fig 16 — Pipeline rapport de pentest** : JSON → generate_report.py → rapport_final.md

---

## Récapitulatif

| Priorité | Schéma | Lab | Effort |
|----------|--------|-----|--------|
| Haute | SQLi UNION | 1.3 | 30 min |
| Haute | CMDi → Reverse Shell | 1.4 | 30 min |
| Haute | Samba usermap_script | 2.3 | 30 min |
| Haute | Brute-force Hydra | 1.6 | 20 min |
| Moyenne | Persistance SSH | 2.4 | 20 min |
| Moyenne | Nessus architecture | 2.6 | 20 min |
| Moyenne | Trojan Windows | 3.3 | 30 min |
| Basse | Pipeline rapport | 5.2 | 15 min |

**Format recommandé :** Mermaid flowchart (compatible Markdown, inline dans les JOUR-*.md)
