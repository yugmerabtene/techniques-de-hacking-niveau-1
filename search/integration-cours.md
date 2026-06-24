# Intégration des normes au cours — Propositions

## Ce qui peut être ajouté SANS dévier du syllabus

### JOUR 01 — Introduction au hacking et aux vulnérabilités

**Ajout possible :** Référence aux "10 règles d'or ANSSI" comme checklist de base.
Chaque faille (XSS, SQLi, CMDi) est une violation directe des règles 2, 6 et 8.

### JOUR 02 — Tests de pénétration et exploitation

**Ajout possible :** Le pentest est exigé par :
- RGS : analyse de risques obligatoire avant homologation
- NIS2 art.21 : tests réguliers des mesures de sécurité
- Le CERT-FR publie les vulnérabilités exploitées en conditions réelles

→ Mentionner que le rapport de pentest est un **livrable réglementaire** (pas juste technique).

### JOUR 03 — Vulnérabilités avancées

**Ajout possible :** Les techniques d'évasion (TA0005) sont documentées par le CERT-FR dans ses bulletins d'actualité. Les vrais attaquants utilisent exactement ces méthodes.

→ Intégrer un exemple réel tiré d'un CERTFR-ACT.

### JOUR 04 — Contre-mesures

**Ajout déjà partiellement présent. Renforcer avec :**
- La checklist de durcissement **alignée sur les recommandations CERT-FR (DUR)**
- Les niveaux RGS (*, **, ***) comme échelle de maturité défensive
- La matrice de couverture défensive → exigence NIS2 de "mesures proportionnées"
- Mention du guide ANSSI "Anticiper et gérer sa communication de crise cyber"

### JOUR 05 — Reporting et gestion des incidents

**Ajout critique :**
- Section dédiée "Conformité réglementaire" :
  - Calendrier NIS2 : alerte 24h, notification 72h, rapport final 1 mois
  - Exigence RGPD : notification CNIL sous 72h si données personnelles
  - Le rapport de pentest est un livrable d'homologation RGS
  - Modèle de fiche de déclaration d'incident conforme CERT-FR
- Section "Normes européennes et françaises" :
  - Tableau NIS2 + RGS + RGPD + LPM
  - Comment le cours répond à chaque exigence

## Éléments concrets à intégrer

### 1. Calendrier NIS2 dans JOUR 05 (section incident response)

```
Délais de notification NIS2 :
├── 24h : Alerte précoce au CSIRT national
├── 72h : Notification complète (nature, impact, mesures prises)
└── 1 mois : Rapport final détaillé
```

### 2. Checklist de durcissement CERT-FR dans JOUR 04

```
Recommandations CERTFR-2021-DUR-001 (Active Directory)
Recommandations CERTFR-2025-DUR-003 (Énergie/Eau — adaptable)
+ 10 règles d'or ANSSI
```

### 3. Fiche réflexe incident dans JOUR 05

```
Modèle de déclaration inspiré de la fiche réflexe CERT-FR
+ Obligations de signalement (NIS2 + RGPD)
```

### 4. Référence RGS dans JOUR 04 (homologation)

```
Niveaux RGS *, **, *** comme grille de maturité
→ À quel niveau le client doit-il viser ?
```

## Ce qui NE change PAS

- La structure README.md (syllabus contractuel)
- Le nombre de jours (5)
- Les durées (6h/jour)
- Le format gabarit (objectifs, introduction, concepts, lab, exercices)
- Les Dockerfiles et labs
- Le HORS-SERIE-AGENTIC.md
