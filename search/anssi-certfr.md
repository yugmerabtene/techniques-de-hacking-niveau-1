# Structures de cyberdéfense française — Comment la France protège ses SI

Source : cyber.gouv.fr + cert.ssi.gouv.fr (ANSSI/CERT-FR)

## L'ANSSI — 5 missions

1. **Défendre** : protection des SI de l'État et des OIV (Opérateurs d'Importance Vitale)
2. **Connaître** : analyse de la menace, veille technologique, panorama annuel
3. **Partager** : diffusion des alertes, avis, indicateurs de compromission via CERT-FR
4. **Accompagner** : guides d'hygiène, formations, SecNumEdu, MesServicesCyber
5. **Réguler** : certification, qualification, RGS, supervision NIS2

## CERT-FR — Centre opérationnel

### Types de publications (utilisables dans le cours)

| Publication | Usage pédagogique |
|---|---|
| **Alertes de sécurité** (CERTFR-2026-ALE-XXX) | Exemple réel d'incident : comment réagir, quelles mesures |
| **Rapports Menaces et Incidents** (CERTFR-2026-CTI-XXX) | Panorama de la cybermenace 2025 : tendances à connaître |
| **Avis de sécurité** (CERTFR-2026-AVI-XXX) | Vulnérabilités réelles à étudier (Microsoft, cURL, F5...) |
| **Indicateurs de compromission** (IOC) | À intégrer dans un SIEM — concret pour JOUR 04/05 |
| **Recommandations de durcissement** (DUR) | Checklist de hardening, points de contrôle AD |
| **Fiches réflexes** | Procédures d'urgence en cas d'incident |
| **Bulletins d'actualité** (ACT) | Veille hebdomadaire : menaces du moment |

### Réseau de CSIRT en France

```
CERT-FR (national)
├── CSIRT ministériels (dont CSIRT Justice)
├── CSIRT sectoriels (énergie, santé, transport, finance)
├── CSIRT territoriaux (régions)
└── InterCERT France (coopération inter-CSIRT)
```

→ Le Ministère de la Justice a son propre **CSIRT ministériel** qui remonte au CERT-FR.

### Le cycle de traitement d'incident officiel

1. **Détection** : SIEM, sondes, signalement utilisateur
2. **Qualification** : triage, criticité, impact CIA
3. **Réponse** : confinement, éradication, remédiation
4. **Notification** : remontée au CERT-FR dans les délais NIS2 (24h/72h)
5. **Retour d'expérience** : post-mortem, amélioration continue

## Les "10 règles d'or" de l'ANSSI

Applicables à toute administration, dont la Justice :
1. Mettre à jour régulièrement les logiciels
2. Utiliser des mots de passe robustes
3. Sauvegarder les données
4. Protéger l'accès aux locaux
5. Sécuriser les postes de travail
6. Protéger le réseau informatique
7. Sécuriser l'administration des SI
8. Protéger les données
9. Anticiper et gérer les crises
10. Sensibiliser et former les utilisateurs

## Procédure de qualification ANSSI (produits de sécurité)

Pour les produits utilisés par l'administration (dont la Justice) :
1. **Certification** : conforme à un standard (CSPN)
2. **Qualification** : niveau de sécurité RGS (*, **, ***)
3. **Homologation** : validation par l'autorité pour un usage spécifique

## Sources

- ANSSI : https://cyber.gouv.fr/
- CERT-FR : https://www.cert.ssi.gouv.fr/
- MesServicesCyber : https://messervices.cyber.gouv.fr/
- Guides ANSSI : https://cyber.gouv.fr/offre-de-service/guides-services-numeriques-et-outils/
