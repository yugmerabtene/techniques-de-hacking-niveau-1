# Normes et réglementations cybersécurité — France et Europe

## Synthèse pour le cours "Techniques de hacking et contre-mesures"

### Cadre réglementaire français applicable à la Justice

| Norme | Origine | Applicable à | Exigences principales |
|---|---|---|---|
| **RGS v2.0** | France (ANSSI) | Toutes les autorités administratives | Analyse de risques, homologation, solutions qualifiées, niveaux de sécurité * à *** |
| **NIS2** | UE (transposée) | 18 secteurs critiques dont administrations publiques | Mesures de gestion des risques, notification incidents 24h/72h, responsabilité des dirigeants |
| **RGPD** | UE | Toute entité traitant des données personnelles | Sécurité des données, notification violations 72h, analyses d'impact (PIA) |
| **LPM 2024-2030** | France | OIV, administrations | Renforcement capacités cyber, SOC interministériels, réserves cyber |
| **Directive (UE) 2022/2557** | UE | Entités critiques | Résilience des infrastructures critiques |
| **Instruction IGI 1300** | France (SGDSN) | Administrations étatiques | Protection du secret de la défense nationale |
| **PSSI-E** | France (ANSSI) | Ministères | Politique de sécurité des SI de l'État |

### Comment le cours répond à ces exigences

| Exigence réglementaire | Partie du cours |
|---|---|
| Analyse de risques (RGS) | JOUR 04 — Évaluation CIA, matrice de couverture |
| Tests de pénétration (NIS2 art.21) | JOUR 02 — Méthodologies PTES/OWASP, exploitation |
| Gestion des vulnérabilités (NIS2) | JOUR 01 — XSS, SQLi, CSRF, Command Injection |
| Contre-mesures (RGS/NIS2) | JOUR 04 — Chiffrement, hardening, IDS/IPS |
| Rapport d'audit (RGS homologation) | JOUR 05 — Rapport pentest, CVSS, ATT&CK |
| Signalement incidents (NIS2 art.23) | JOUR 05 — Cycle incident, notification 72h |
| Cyber-hygiène (NIS2) | JOUR 04 — Hardening, bonnes pratiques |
| Formation (NIS2/RGPD) | Toute la formation |

### Niveaux de criticité et leur cadre réglementaire

| Niveau | RGS | NIS2 | Action attendue |
|---|---|---|---|
| FAIBLE | * | Standard | Surveillance de base |
| MODÉRÉ | ** | Essentiel | Audit annuel, pentest externe |
| ÉLEVÉ | *** | Important | Audit semestriel, pentest interne + externe, SOC 24/7 |
| CRITIQUE | *** | Essentiel + | Audit continu, Red Team, homologation RGS *** |

### Autorités compétentes en France

| Autorité | Rôle |
|---|---|
| **ANSSI** | Autorité nationale cybersécurité, qualification RGS, supervision NIS2, CERT-FR |
| **CNIL** | Protection des données personnelles (RGPD) |
| **DGME/DINUM** | Modernisation de l'État, référencement RGS |
| **CERT-FR** | Centre opérationnel de réponse aux incidents (CSIRT national) |
| **Ministère de la Justice** | Responsable de la sécurité de ses propres SI, autorité d'homologation interne |

### Références pour le cours

- RGS v2.0 (ANSSI) : https://www.ssi.gouv.fr/rgs
- NIS2 Directive : https://eur-lex.europa.eu/eli/dir/2022/2555
- RGPD : https://www.cnil.fr/fr/reglement-europeen-protection-donnees
- Guide d'hygiène informatique ANSSI : https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/
- CERT-FR : https://www.cert.ssi.gouv.fr/
- LPM 2024-2030 : https://www.legifrance.gouv.fr
