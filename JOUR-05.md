# Chapitre 05 : Reporting et gestion des incidents

---

## Objectifs pédagogiques

- Rédiger un rapport de pentest professionnel tagué ATT&CK
- Maîtriser la notation CVSS v3.1 pour standardiser la criticité
- Détecter, analyser et répondre aux incidents de sécurité
- Reconstruire la kill chain ATT&CK d'un attaquant

---

## Setup rapide

```bash
if [ -f /.dockerenv ]; then
    TARGET_FORENSIC="forensic-victim" ; PORT_FORENSIC="80"
else
    TARGET_FORENSIC="localhost" ; PORT_FORENSIC="8082"
fi
echo "Forensic target : http://${TARGET_FORENSIC}:${PORT_FORENSIC}/"
```

---

## 1. CVSS — Notation standardisée des vulnérabilités

### Comprendre le score CVSS v3.1

Le CVSS attribue un score de 0 à 10 basé sur des métriques mesurables.

```
MÉTRIQUES CVSS v3.1
├── Base Score
│   ├── AV (Attack Vector)      N:Network  A:Adjacent  L:Local  P:Physical
│   ├── AC (Attack Complexity)  L:Low  H:High
│   ├── PR (Privileges Required) N:None  L:Low  H:High
│   ├── UI (User Interaction)   N:None  R:Required
│   ├── S  (Scope)              U:Unchanged  C:Changed
│   ├── C (Confidentiality)     N:None  L:Low  H:High
│   ├── I (Integrity)           N:None  L:Low  H:High
│   └── A (Availability)        N:None  L:Low  H:High
├── Temporal : E (Exploit Maturity), RL (Remediation)
└── Environmental : CR, IR, AR (requirements)
```

Seuils de criticité :

| Score | Niveau |
|---|---|
| 9.0 - 10.0 | 🔴 CRITIQUE |
| 7.0 - 8.9 | 🟠 ÉLEVÉE |
| 4.0 - 6.9 | 🟡 MODÉRÉE |
| 0.1 - 3.9 | 🟢 FAIBLE |

> **Sources :** [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1) — FIRST.org.

### Exemples

```python
class CVSS:
    def __init__(self, vector: str):
        self.m = dict(m.split(":") for m in vector.split("/"))

    def severity(self):
        impact_map = {"N": 0.0, "L": 0.22, "H": 0.56}
        impact = sum(impact_map.get(self.m.get(m, "N"), 0) for m in "CIA")
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        exploit = av_map.get(self.m.get("AV", "N"), 0)
        ac = 0.77 if self.m.get("AC") == "L" else 0.44
        pr = 0.85 if self.m.get("PR") == "N" else 0.62
        score = min(10.0, (exploit * ac * pr + impact) * 1.2)
        if score >= 9.0: return score, "CRITIQUE"
        elif score >= 7.0: return score, "ELEVEE"
        elif score >= 4.0: return score, "MODEREE"
        else: return score, "FAIBLE"

# SQLi critique
s, l = CVSS("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").severity()
print(f"SQLi: CVSS {s:.1f} ({l})")  # → 9.8 (CRITIQUE)

# XSS reflété
s, l = CVSS("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N").severity()
print(f"XSS:  CVSS {s:.1f} ({l})")  # → 5.4 (MODEREE)
```

---

## 2. Template de fiche de vulnérabilité

```markdown
# VULN-001 — Injection SQL sur paramètre 'id'

| Propriété | Valeur |
|---|---|
| **Criticité** | 🔴 CRITIQUE |
| **Score CVSS** | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Technique ATT&CK** | T1190 Exploit Public-Facing Application |
| **Tactique** | TA0001 Initial Access |

## Description
Le paramètre GET "id" est injecté sans filtrage dans une requête SQL.

## Impact CIA
- Confidentialité : HIGH (extraction BDD)
- Intégrité : HIGH (modification/destruction)
- Disponibilité : HIGH (DoS possible)

## Remédiation
1. Requêtes préparées PDO → M1013 App Hardening
2. Déploiement WAF → M1041 Encrypt/Protect
3. Validation entrées → M1054 Input Validation
```

---

## Lab 5.1 — Investigation forensique

### 📋 Fiche de lab

| Propriété | Valeur |
|---|---|
| **Durée** | 1h30 |
| **Conteneur** | `forensic-victim` (port 8082) |
| **Dossier de travail** | `~/cours-hacking/jour-5/labs/` |
| **Objectif** | Analyser une machine compromise, collecter des preuves, reconstruire la kill chain |

### Prérequis

- [x] Conteneur buildé : `docker compose up -d --build forensic-victim`
- [x] Web app accessible : `curl -I "http://${TARGET_FORENSIC}:${PORT_FORENSIC}/"`
- [x] `mkdir -p ~/cours-hacking/jour-5/labs && cd ~/cours-hacking/jour-5/labs`

### Contexte

Le conteneur simule un serveur web compromis via une injection de commandes. Votre mission : analyser la scène de crime.

### Étape 1 — Découverte du point d'entrée

```bash
curl "http://${TARGET_FORENSIC}:${PORT_FORENSIC}/"
# → Internal Dashboard

# Test command injection
curl "http://${TARGET_FORENSIC}:${PORT_FORENSIC}/?cmd=whoami"
# → uid=33(www-data)...

curl "http://${TARGET_FORENSIC}:${PORT_FORENSIC}/?cmd=id"
# → uid=33(www-data) gid=33(www-data)
```

**Checkpoint A :** Command injection confirmée.

### Étape 2 — Collecte de preuves volatiles

```bash
docker exec forensic-victim bash -c "
mkdir -p /tmp/evidence
ss -tulpn > /tmp/evidence/network.txt
ps auxww > /tmp/evidence/processes.txt
find /var/www -type f -mtime -30 > /tmp/evidence/web_files.txt
cat /etc/passwd > /tmp/evidence/passwd.txt
cat /etc/sudoers > /tmp/evidence/sudoers.txt
echo 'Evidence collected'
ls -la /tmp/evidence/
"
```

**Checkpoint B :** 5 fichiers de preuves dans `/tmp/evidence/`.

### Étape 3 — Signes de compromission

```bash
# Backdoors web (eval, system, exec)
docker exec forensic-victim grep -rn "eval\|system\|exec\|passthru" /var/www/html/ 2>/dev/null

# Logs Apache avec commandes injectées
docker exec forensic-victim cat /var/log/apache2/access.log 2>/dev/null | grep "cmd=" | tail -20

# Comptes récents
docker exec forensic-victim tail -5 /etc/passwd

# Sudoers modifié (www-data a tous les droits)
docker exec forensic-victim grep www-data /etc/sudoers
# → www-data ALL=(ALL) NOPASSWD: ALL
```

### Étape 4 — Reconstruction kill chain ATT&CK

| Horodatage | Tactic | Technique | Preuve |
|---|---|---|---|
| | TA0001 Initial Access | T1190 Exploit Public-Facing | GET /?cmd=whoami dans access.log |
| | TA0002 Execution | T1059.004 Unix Shell | Commande system() dans index.php |
| | TA0003 Persistence | T1505.003 Web Shell | Code eval() dans PHP |
| | TA0004 PrivEsc | T1548.001 Sudo Caching | www-data ALL dans sudoers |

### Étape 5 — Rapport d'incident

Créez `~/cours-hacking/jour-5/labs/incident_report.md` :

```markdown
# Rapport d'incident IR-2026-001

**Date détection :** ...
**Criticité :** 🔴 CRITIQUE
**Système :** forensic-victim

## Kill Chain ATT&CK
1. TA0001 — T1190 : Command injection via ?cmd=
2. TA0002 — T1059.004 : Exécution commandes arbitraires
3. TA0003 — T1505.003 : Backdoor PHP
4. TA0004 — T1548.001 : www-data ajouté aux sudoers

## Impact CIA
- Confidentialité : HIGH
- Intégrité : HIGH
- Disponibilité : LOW

## Actions
1. Confinement : isolation réseau
2. Collecte preuves volatiles
3. Éradication backdoor
4. Correction command injection

## Recommandations
- Remplacer system() par escapeshellcmd()
- Déployer WAF ModSecurity
- Restreindre sudoers
- Audit des comptes
```

---

## 3. Génération automatisée de rapport

Créez `~/cours-hacking/jour-5/labs/generate_report.py` :

```python
#!/usr/bin/env python3
"""Générateur de rapport de pentest avec mapping ATT&CK."""
import json, argparse
from datetime import datetime

TEMPLATE = """# Rapport de Test d'Intrusion

**Date :** {date}
**Périmètre :** {perimeter}
**Risque global :** {risk}

## Résumé
| Criticité | Nombre |
|---|---|
| Critique | {critical} | Élevée | {high} | Modérée | {medium} | Faible | {low} |

## Vulnérabilités
{findings}

## Recommandations
{recos}
"""

def generate(data, output):
    sev = {"CRITIQUE": 0, "ÉLEVÉE": 0, "MODÉRÉE": 0, "FAIBLE": 0}
    findings_md = ""
    for i, f in enumerate(data["findings"], 1):
        sev[f["severity"]] += 1
        findings_md += f"""
### VULN-{i:03d} — {f['title']}
- Criticité : {f['severity']}
- CVSS : {f.get('cvss', 'N/A')}
- ATT&CK : {f.get('attack', 'N/A')}
- Description : {f.get('desc', 'N/A')}
- Remédiation : {f.get('fix', 'N/A')}
"""
    risk = "CRITIQUE" if sev["CRITIQUE"] > 0 else "ÉLEVÉ" if sev["ÉLEVÉE"] > 0 else "MODÉRÉ"
    report = TEMPLATE.format(date=datetime.now().strftime("%Y-%m-%d"),
        perimeter=data.get("perimeter", "N/A"), risk=risk, **sev,
        findings=findings_md, recos="\n".join(f"- {r}" for r in data.get("recos", [])))
    with open(output, "w") as f: f.write(report)
    print(f"Rapport généré : {output}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", default="rapport.md")
    args = p.parse_args()
    with open(args.input) as f: generate(json.load(f), args.output)
```

Exemple d'utilisation :

```bash
cd ~/cours-hacking/jour-5/labs

cat > findings.json << 'EOF'
{
  "perimeter": "Conteneurs Docker — lab formation",
  "findings": [
    {"title":"SQLi sur DVWA","severity":"CRITIQUE","cvss":"9.8",
     "attack":"T1190","desc":"Injection SQL non filtrée","fix":"Requêtes préparées PDO"},
    {"title":"XSS reflété DVWA","severity":"MODÉRÉE","cvss":"5.4",
     "attack":"T1189","desc":"Reflet JS non échappé","fix":"htmlspecialchars() + CSP"},
    {"title":"Command Injection DVWA","severity":"CRITIQUE","cvss":"9.8",
     "attack":"T1059.004","desc":"Exécution commandes arbitraires","fix":"escapeshellcmd()"},
    {"title":"vsftpd 2.3.4 Backdoor","severity":"CRITIQUE","cvss":"9.8",
     "attack":"T1190","desc":"Shell root via backdoor","fix":"Mettre à jour vsftpd"},
    {"title":"Samba 3.0.20 usermap","severity":"CRITIQUE","cvss":"9.8",
     "attack":"T1210","desc":"RCE via usermap script","fix":"Mettre à jour Samba"}
  ],
  "recos": [
    "Déployer WAF ModSecurity en mode bloquant",
    "Mettre en place un processus de patch management",
    "Formation développeurs OWASP Top 10",
    "Audit de sécurité trimestriel"
  ]
}
EOF

python3 generate_report.py --input findings.json --output rapport_final.md
cat rapport_final.md
```

---

## Exercices

### Exercice 1 : Calculer un CVSS

**Énoncé :** XSS stocké sans interaction utilisateur. AV:N, AC:L, PR:N, UI:N, S:U, C:H, I:H, A:L.

<details>
<summary><strong>Solution</strong></summary>

Vecteur : `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L` → Score ~8.3 (ÉLEVÉ)
Pas CRITIQUE car A:L. ATT&CK : T1189.
</details>

### Exercice 2 : Reconstruire une kill chain

**Énoncé :** Alertes SOC : 08:00 WAF bloque SQLi, 08:05 scan ports, 08:15 reverse shell. Reconstruisez l'ordre chronologique.

<details>
<summary><strong>Solution</strong></summary>

07:55 — TA0007 T1046 (scan ports)
07:58 — TA0001 T1190 (tentative SQLi 1, bloquée)
08:00 — TA0001 T1190 (tentative SQLi 2, réussie via autre paramètre)
08:15 — TA0002 T1059.004 (reverse shell)
</details>

---

## Points clés à retenir

- CVSS standardise la criticité : reproductible et universel
- Chaque vulnérabilité doit être taguée ATT&CK (ID Txxxx)
- La gestion d'incident suit un cycle en 7 phases
- Reconstruire la kill chain de l'attaquant guide la remédiation
- Un rapport parle à deux audiences : direction (exécutif) et technique (fiches)

## Pour aller plus loin

- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [NIST SP 800-61r2 — Incident Handling](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---

*Formation terminée — Remise du rapport final*
*Chapitre précédent : [Jour 4](./JOUR-04.md)*
*Guide Environnement : [ENVIRONNEMENT.md](./ENVIRONNEMENT.md)*
