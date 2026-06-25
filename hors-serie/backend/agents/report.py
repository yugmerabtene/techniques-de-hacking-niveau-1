"""
ReportAgent — Génération de rapport de pentest.

Rôle dans la kill chain :
    Dernière phase de la kill chain, l'agent rapport synthétise l'ensemble
    des résultats collectés (reconnaissance, exploitation, élévation de
    privilèges, persistance) et produit un rapport au format Markdown
    conforme aux standards PTES (Penetration Testing Execution Standard)
    avec mapping MITRE ATT&CK v15 et calcul de score CVSS.

Livrables générés :
    - Rapport Markdown structuré (résumé exécutif, méthodologie, vulnérabilités,
      matrice ATT&CK, recommandations, annexes)
    - Fichier JSON compatible ATT&CK Navigator (visualisation graphique)
    - Export fichiers (Markdown + JSON) dans un répertoire de sortie

Standards :
    PTES (Penetration Testing Execution Standard)
    MITRE ATT&CK v15
    CVSS v3.1
"""

import json
import os
from datetime import datetime


class ReportAgent:
    def __init__(self, target: str, context: dict = None):
        """
        Initialise l'agent de rapport.

        Args:
            target (str): Adresse IP ou nom d'hôte de la cible.
            context (dict, optional): Contexte cumulatif complet de la kill chain
                                      (recon, exploit, privesc, persist, mission_id).
        """
        self.target = target
        self.context = context or {}

    def run(self) -> dict:
        """
        Point d'entrée principal de l'agent de rapport.

        Génère tous les formats de sortie (Markdown, JSON ATT&CK Navigator)
        et retourne une structure unifiée.

        Returns:
            dict: Résultat complet du rapport contenant :
                  - title (str) : Titre du rapport.
                  - date (str) : Date ISO 8601.
                  - mission_id (str) : Identifiant de la mission.
                  - markdown (str) : Rapport complet au format Markdown.
                  - attack_navigator (dict) : Structure JSON pour ATT&CK Navigator.
                  - export_formats (list) : Formats d'export disponibles.
        """
        return {
            "title": self._title(),
            "date": datetime.now().isoformat(),
            "mission_id": self.context.get("mission_id", "unknown"),
            "markdown": self.generate_markdown(),
            "attack_navigator": self.generate_attack_navigator_json(),
            "export_formats": ["Markdown", "ATT&CK Navigator JSON", "HTML"],
        }

    def _title(self) -> str:
        """
        Génère le titre du rapport de pentest.

        Returns:
            str: Titre formaté incluant la cible.
        """
        return f"Rapport de Pentest — {self.target}"

    def generate_markdown(self) -> str:
        """
        Génère le rapport complet au format Markdown.

        Structure du rapport :
            1. Résumé exécutif avec tableau synthétique
            2. Méthodologie PTES (recon, exploit, privesc, persistance)
            3. Vulnérabilités identifiées avec scores CVSS
            4. Matrice MITRE ATT&CK v15
            5. Recommandations de remédiation
            6. Annexes

        Returns:
            str: Rapport Markdown complet prêt à être sauvegardé ou affiché.
        """
        # Date formatée pour le rapport (format français)
        now = datetime.now().strftime("%d/%m/%Y %H:%M")
        report_id = self.context.get("mission_id", "N/A")

        # Extraction des résultats de chaque phase depuis le contexte
        recon = self.context.get("recon", {})
        exploit = self.context.get("exploit", {})
        privesc = self.context.get("privesc", {})
        persist = self.context.get("persist", {})

        # Détail reconnaissance
        nmap = recon.get("nmap", {})
        gobuster = recon.get("gobuster", {})
        ports = nmap.get("ports", [])
        open_ports_count = nmap.get("open_ports", len(ports))

        # Détail exploitation
        sqlmap = exploit.get("sqlmap", {})
        msfconsole = exploit.get("msfconsole", {})

        # --- En-tête du rapport (front matter) ---
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
        # Tableau des ports ouverts détectés par nmap
        if ports:
            md += "| Port | Protocole | Service | Version |\n|---|---|---|---|\n"
            for p in ports:
                md += f"| {p.get('port')} | {p.get('protocol')} | {p.get('service')} | {p.get('version')} |\n"
        else:
            md += "Aucun port ouvert détecté ou nmap non disponible.\n"

        # Liste des répertoires découverts par gobuster
        gob_dirs = gobuster.get("directories", [])
        if gob_dirs:
            md += f"\n**gobuster** — {gobuster.get('directories_found', 0)} répertoire(s) trouvé(s) :\n"
            for d in gob_dirs:
                md += f"- `{d}`\n"

        # --- Section exploitation ---
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
        # Détail de chaque port ouvert avec son service et sa version
        for p in ports:
            md += f"- Port {p.get('port')}/{p.get('protocol')} : {p.get('service')} {p.get('version')}\n"

        # --- Matrice ATT&CK (représentation arborescente) ---
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
        """
        Génère une structure JSON compatible avec MITRE ATT&CK Navigator.

        Le format suit la spécification de la couche (layer) ATT&CK Navigator v4.5.
        Chaque technique est associée à :
            - Une tactique (catégorie ATT&CK).
            - Un score (0-100) reflétant la criticité.
            - Un commentaire décrivant l'action réalisée.

        Les couleurs du gradient vont du blanc (#ffffff, score 0)
        au rouge (#ff6666, score 100).

        Returns:
            dict: Structure JSON prête pour l'import dans ATT&CK Navigator.
        """
        return {
            # Nom de la couche affiché dans Navigator
            "name": f"KillChain {self.target}",
            # Versions des composants ATT&CK
            "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
            # Domaine Enterprise (vs Mobile ou ICS)
            "domain": "enterprise-attack",
            "description": f"Kill chain automatisée pour {self.target}",
            # Liste des techniques avec leur mapping tactique
            "techniques": [
                {
                    "techniqueID": "T1046",
                    "tactic": "discovery",
                    "score": 50,                    # Score moyen : scan passif
                    "comment": "nmap scan",
                },
                {
                    "techniqueID": "T1595",
                    "tactic": "discovery",
                    "score": 50,                    # Score moyen : énumération web
                    "comment": "gobuster enumeration",
                },
                {
                    "techniqueID": "T1190",
                    "tactic": "initial-access",
                    "score": 80,                    # Score élevé : exploitation active
                    "comment": "sqlmap + msfconsole exploitation",
                },
                {
                    "techniqueID": "T1068",
                    "tactic": "privilege-escalation",
                    "score": 70,                    # Score élevé : tentative d'élévation
                    "comment": "LinPEAS enumeration",
                },
                {
                    "techniqueID": "T1098",
                    "tactic": "persistence",
                    "score": 60,                    # Score moyen : persistance installée
                    "comment": "SSH key + cron + systemd persistence",
                },
            ],
            # Gradient de couleur : blanc (score bas) → rouge (score élevé)
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
        }

    def export_to_file(self, output_dir: str = "reports") -> str:
        """
        Exporte le rapport en fichiers Markdown et JSON sur disque.

        Crée le répertoire de sortie s'il n'existe pas (mkdir -p).
        Génère deux fichiers :
            - report_{mission_id}_{timestamp}.md  : Rapport Markdown complet.
            - attack_navigator_{mission_id}_{timestamp}.json : JSON ATT&CK Navigator.

        Args:
            output_dir (str): Répertoire de sortie (défaut: "reports").

        Returns:
            str: Chemin absolu du fichier Markdown généré.
        """
        # Horodatage pour le nom de fichier (YYYYMMDD_HHMMSS)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        mission_id = self.context.get("mission_id", "unknown")

        # Création du répertoire de sortie si nécessaire (équivalent mkdir -p)
        os.makedirs(output_dir, exist_ok=True)

        # Export Markdown
        md_path = os.path.join(output_dir, f"report_{mission_id}_{ts}.md")
        with open(md_path, "w") as f:
            f.write(self.generate_markdown())

        # Export JSON ATT&CK Navigator
        json_path = os.path.join(output_dir, f"attack_navigator_{mission_id}_{ts}.json")
        with open(json_path, "w") as f:
            # ensure_ascii=False : préserve les accents en français
            json.dump(self.generate_attack_navigator_json(), f, indent=2, ensure_ascii=False)

        return md_path
