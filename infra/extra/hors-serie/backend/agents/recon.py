"""
ReconAgent — Reconnaissance réseau.

Rôle dans la kill chain :
    L'agent de reconnaissance est la première phase de la kill chain.
    Il collecte des informations sur la surface d'attaque de la cible
    en scannant les ports ouverts (nmap) et en énumérant les répertoires
    web (gobuster). Les résultats sont transmis aux agents suivants
    (exploit, report) via le contexte.

Tactiques/Techniques couvertes :
    TA0007 Discovery — T1046 Network Service Scanning (nmap)
    TA0007 Discovery — T1595 Active Scanning (gobuster)
"""

import subprocess
import xml.etree.ElementTree as ET


class ReconAgent:
    def __init__(self, target: str, context: dict = None):
        """
        Initialise l'agent de reconnaissance.

        Args:
            target (str): Adresse IP ou nom d'hôte de la cible.
            context (dict, optional): Contexte fourni par le superviseur
                                      (non utilisé en pratique par recon).
        """
        self.target = target
        self.context = context or {}

    def run_nmap(self) -> dict:
        """
        Lance un scan nmap avec détection de version et scripts par défaut.

        Les flags utilisés :
            -sV  : Détection des versions de services.
            -sC  : Exécution des scripts NSE par défaut (safe).
            -p   : Limite le scan aux ports 21(FTP), 22(SSH), 80(HTTP),
                   443(HTTPS), 445(SMB), 3306(MySQL), 8080(HTTP-alt).
            -oX -: Sortie au format XML sur stdout (parsable).

        Returns:
            dict: Résultat du scan contenant :
                  - success (bool) : Scan réussi ou non.
                  - technique (str) : Identifiant ATT&CK T1046.
                  - tactic (str) : Identifiant ATT&CK TA0007.
                  - open_ports (int) : Nombre de ports ouverts trouvés.
                  - ports (list) : Liste détaillée [{port, protocol, service, version}].
                  - error (str) : Message d'erreur si échec.
        """
        try:
            # Construction de la commande nmap
            cmd = ["nmap", "-sV", "-sC", "-p", "21,22,80,443,445,3306,8080",
                   self.target, "-oX", "-"]
            # Exécution avec capture stdout/stderr, timeout de 120s
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                # Code retour non nul = erreur nmap (cible inaccessible, etc.)
                return {"success": False, "error": result.stderr.strip()}

            # Parsing du XML de sortie nmap
            root = ET.fromstring(result.stdout)
            ports = []
            for host in root.findall("host"):
                # Parcourt tous les éléments <port> dans l'arbre XML
                for port in host.findall(".//port"):
                    service = port.find("service")
                    ports.append({
                        "port": port.get("portid"),        # Numéro de port (ex: "80")
                        "protocol": port.get("protocol"),   # Protocole (ex: "tcp")
                        # Nom du service (ex: "http"), "unknown" si absent
                        "service": service.get("name") if service is not None else "unknown",
                        # Version du service si disponible
                        "version": service.get("version", "unknown") if service is not None else "unknown",
                    })

            return {
                "success": True,
                "technique": "T1046",
                "tactic": "TA0007",
                "open_ports": len(ports),
                "ports": ports,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def run_gobuster(self) -> dict:
        """
        Lance une énumération de répertoires web avec gobuster.

        Les flags utilisés :
            dir : Mode énumération de répertoires.
            -u  : URL cible (protocole http ajouté automatiquement).
            -w  : Wordlist utilisée (dirb/common.txt, ~4 600 entrées).
            -q  : Mode quiet (pas de bannière, sortie épurée).

        Returns:
            dict: Résultat de l'énumération contenant :
                  - success (bool).
                  - technique (str) : Identifiant ATT&CK T1595.
                  - tactic (str) : Identifiant ATT&CK TA0007.
                  - tool (str) : "gobuster".
                  - directories_found (int) : Nombre de répertoires découverts.
                  - directories (list) : 20 premiers répertoires trouvés.
                  - error (str) : Message d'erreur si échec (outil absent, timeout).
        """
        try:
            # Construction de la commande gobuster
            cmd = ["gobuster", "dir", "-u", f"http://{self.target}",
                   "-w", "/usr/share/wordlists/dirb/common.txt", "-q"]
            # Exécution avec timeout de 30s
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            # Filtre les lignes vides de la sortie
            dirs = [line for line in result.stdout.strip().split("\n") if line]
            return {
                "success": True,
                "technique": "T1595",
                "tactic": "TA0007",
                "tool": "gobuster",
                "directories_found": len(dirs),
                # Limite à 20 entrées pour ne pas surcharger le contexte
                "directories": dirs[:20],
            }
        except FileNotFoundError:
            return {"success": False, "error": "gobuster not installed"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "gobuster timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def run(self) -> dict:
        """
        Point d'entrée principal de l'agent de reconnaissance.

        Exécute séquentiellement le scan nmap puis l'énumération gobuster.

        Returns:
            dict: Résultats agrégés contenant les clés "nmap" et "gobuster",
                  chacune étant le dict retourné par la méthode correspondante.
        """
        return {
            "nmap": self.run_nmap(),
            "gobuster": self.run_gobuster(),
        }
