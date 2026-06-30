# Plan d'attaque — JOUR-01

## Ordonnancement de l'attaque

| Ordre | Technique | Dépend de | Risque | Objectif |
|-------|-----------|-----------|--------|----------|
| 1 | [T1046](https://attack.mitre.org/techniques/T1046/) — Scan | — | Firewall bloque le port | Ports ouverts identifiés |
| 2 | [T1190](https://attack.mitre.org/techniques/T1190/) — SQLi | T1046 | WAF détecte union select | Dump de la base users |
| 3 | [T1189](https://attack.mitre.org/techniques/T1189/) — XSS | T1046 | CSP bloque le script | Vol de cookie admin |
| 4 | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) — CMDi | T1046 | disable_functions coupe nc | Reverse shell |
| 5 | [T1110](https://attack.mitre.org/techniques/T1110/) — Brute Force | T1046 | Account lockout après 3 fails | Mot de passe admin |
