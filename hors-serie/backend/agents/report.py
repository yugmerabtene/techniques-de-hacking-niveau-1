"""
ReportAgent — Génération de rapport de pentest.
CVSS + ATT&CK mapping + Markdown
"""

import json
import os
from datetime import datetime


class ReportAgent:
    def __init__(self, target: str, context: dict = None):
        self.target = target
        self.context = context or {}

    def run(self) -> dict:
        return {
            "title": self._title(),
            "date": datetime.now().isoformat(),
            "mission_id": self.context.get("mission_id", "unknown"),
            "markdown": self.generate_markdown(),
            "attack_navigator": self.generate_attack_navigator_json(),
            "export_formats": ["Markdown", "ATT&CK Navigator JSON", "HTML"],
        }

    def _title(self) -> str:
        return f"Rapport de Pentest — {self.target}"

    def generate_markdown(self) -> str:
        now = datetime.now().strftime("%d/%m/%Y %H:%M")
        report_id = self.context.get("mission_id", "N/A")

        recon = self.context.get("recon", {})
        exploit = self.context.get("exploit", {})
        privesc = self.context.get("privesc", {})
        persist = self.context.get("persist", {})

        nmap = recon.get("nmap", {})
        gobuster = recon.get("gobuster", {})
        ports = nmap.get("ports", [])
        open_ports_count = nmap.get("open_ports", len(ports))

        sqlmap = exploit.get("sqlmap", {})
        msfconsole = exploit.get("msfconsole", {})

        md = f"""# {self._title()}

**Date** : {now}  
**Mission ID** : `{report_id}`  
**Méthodologie** : PTES + MITRE ATT&CK v15  
**Classification** : Confidentiel  

---

## 1. Résumé exécutif

Ce rapport présente les résultats du test de pénétration réalisé sur la cible **{self.target}**.
L'audit a suivi une kill chain ATT&CK automatisée par l'orchestrateur **KillChainAgent**,
couvrant les phases de reconnaissance, exploitation, élévation de privilèges et persistance.

### Synthèse

| Phase | Technique | Outil | Résultat |
|---|---|---|---|
| Discovery | T1046 | nmap | {open_ports_count} port(s) ouvert(s) |
| Discovery | T1595 | gobuster | {gobuster.get('directories_found', 0)} répertoire(s) |
| Initial Access | T1190 | sqlmap | {'Succès' if sqlmap.get('success') else 'Échec'} |
| Initial Access | T1190 | msfconsole | {'Succès' if msfconsole.get('success') else 'Échec'} |
| Privilege Escalation | T1068 | LinPEAS | Enumération effectuée |
| Persistence | T1098 | ssh-keygen | {len(persist.get('persistence_methods', []))} méthodes |

---

## 2. Méthodologie (PTES)

### 2.1 Reconnaissance

**nmap** — Scan des services sur les ports 21,22,80,443,445,3306,8080 :

"""
        if ports:
            md += "| Port | Protocole | Service | Version |\n|---|---|---|---|\n"
            for p in ports:
                md += f"| {p.get('port')} | {p.get('protocol')} | {p.get('service')} | {p.get('version')} |\n"
        else:
            md += "Aucun port ouvert détecté ou nmap non disponible.\n"

        gob_dirs = gobuster.get("directories", [])
        if gob_dirs:
            md += f"\n**gobuster** — {gobuster.get('directories_found', 0)} répertoire(s) trouvé(s) :\n"
            for d in gob_dirs:
                md += f"- `{d}`\n"

        md += f"""
### 2.2 Exploitation

| Outil | Succès | Détails |
|---|---|---|
| sqlmap | {sqlmap.get('success', False)} | SQL injection testée sur http://{self.target}/?id=1 |
| msfconsole | {msfconsole.get('success', False)} | Scan de ports via auxiliary/scanner/portscan/tcp |

### 2.3 Élévation de privilèges

L'agent PrivEsc a énuméré les vecteurs suivants :
- SUID binaries, sudo -l, crontab, kernel version (uname -a)
- LinPEAS : {"Fetch réussi" if privesc.get("linpeas", {}).get("success") else "Non disponible"}

### 2.4 Persistance

{len(persist.get('persistence_methods', []))} méthode(s) de persistance proposée(s).

---

## 3. Vulnérabilités identifiées

### 3.1 Open ports — Score CVSS 5.3 (Medium)

**Vector** : AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  
**ATT&CK** : T1046 — Network Service Scanning (TA0007 Discovery)  

"""
        for p in ports:
            md += f"- Port {p.get('port')}/{p.get('protocol')} : {p.get('service')} {p.get('version')}\n"

        md += f"""
---

## 4. Matrice MITRE ATT&CK v15

```
TA0007 Discovery
  └── T1046 Network Service Scanning (nmap)
  └── T1595 Active Scanning (gobuster)
TA0001 Initial Access
  └── T1190 Exploit Public-Facing Application (msfconsole, sqlmap)
TA0004 Privilege Escalation
  └── T1068 Exploitation for Privilege Escalation (LinPEAS)
TA0003 Persistence
  └── T1098 Account Manipulation (SSH key, cron, systemd)
```

---

## 5. Recommandations

1. **Fermer les ports non essentiels** — Restreindre l'accès aux services exposés
2. **Mettre à jour les services** — Appliquer les derniers correctifs de sécurité
3. **Durcir la configuration SSH** — Désactiver l'authentification par mot de passe, utiliser des clés
4. **Déployer un WAF** — Protéger les applications web contre les injections SQL
5. **Auditer les crontabs** — Vérifier régulièrement les tâches planifiées
6. **Mettre en place un IDS/IPS** — Surveiller le trafic réseau anormal

---

## 6. Annexes

- Rapport généré automatiquement par KillChainAgent v0.1.0
- Conforme à la norme PTES (Penetration Testing Execution Standard)
- Export ATT&CK Navigator JSON disponible
"""
        return md

    def generate_attack_navigator_json(self) -> dict:
        return {
            "name": f"KillChain {self.target}",
            "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Kill chain automatisée pour {self.target}",
            "techniques": [
                {"techniqueID": "T1046", "tactic": "discovery", "score": 50,
                 "comment": "nmap scan"},
                {"techniqueID": "T1595", "tactic": "discovery", "score": 50,
                 "comment": "gobuster enumeration"},
                {"techniqueID": "T1190", "tactic": "initial-access", "score": 80,
                 "comment": "sqlmap + msfconsole exploitation"},
                {"techniqueID": "T1068", "tactic": "privilege-escalation", "score": 70,
                 "comment": "LinPEAS enumeration"},
                {"techniqueID": "T1098", "tactic": "persistence", "score": 60,
                 "comment": "SSH key + cron + systemd persistence"},
            ],
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
        }

    def export_to_file(self, output_dir: str = "reports") -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        mission_id = self.context.get("mission_id", "unknown")
        os.makedirs(output_dir, exist_ok=True)

        md_path = os.path.join(output_dir, f"report_{mission_id}_{ts}.md")
        with open(md_path, "w") as f:
            f.write(self.generate_markdown())

        json_path = os.path.join(output_dir, f"attack_navigator_{mission_id}_{ts}.json")
        with open(json_path, "w") as f:
            json.dump(self.generate_attack_navigator_json(), f, indent=2, ensure_ascii=False)

        return md_path
