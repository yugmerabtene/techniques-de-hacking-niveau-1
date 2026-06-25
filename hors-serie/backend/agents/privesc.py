"""
PrivEscAgent — Élévation de privilèges.
TA0004 Privilege Escalation — T1068 Exploitation for Privilege Escalation
"""

import subprocess
import re


class PrivEscAgent:
    def __init__(self, target: str, context: dict = None, linpeas_output: str = ""):
        self.target = target
        self.context = context or {}
        self.linpeas_output = linpeas_output

    def run_linpeas(self) -> dict:
        try:
            cmd = ["curl", "-sL", "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0 and len(result.stdout) > 1000:
                return {
                    "success": True,
                    "technique": "T1068",
                    "tactic": "TA0004",
                    "tool": "LinPEAS",
                    "status": "linpeas.sh fetched successfully",
                    "next_step": f"Execute on target: curl -sL <URL> | sh | tee linpeas_output.txt",
                }
            return {"success": False, "error": "Could not fetch linpeas.sh"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def parse_linpeas_output(self) -> dict:
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

        if not self.linpeas_output:
            findings["total_findings"] = 0
            findings["parsed"] = False
            return findings

        patterns = {
            "kernel_exploits": [
                r"CVE-\d{4}-\d+",
                r"Kernel.*exploit",
                r"DirtyCow|Dirty COW",
                r"OverlayFS|overlayfs",
                r"PwnKit|pkexec",
            ],
            "suid_binaries": [
                r"(/[\w/]+)\s+.*SUID",
                r"SUID.*?(/[\w/]+)",
            ],
            "sudo_privileges": [
                r"User.*may run.*NOPASSWD",
                r"\(ALL\) NOPASSWD",
                r"sudo.*NOPASSWD",
            ],
            "credentials": [
                r"(?:password|passwd|pwd)\s*[=:]\s*(\S+)",
                r"DB_PASSWORD\s*=\s*(\S+)",
                r"mysql.*-p\s*(\S+)",
            ],
            "cron_jobs": [
                r"(/\S+)\s+root\s+.*cron",
                r"@reboot.*(/\S+)",
            ],
            "writable_files": [
                r"Writable.*?(/[\w/]+)",
                r"writable.*?(/etc/[\w/]+)",
            ],
        }

        for category, regex_list in patterns.items():
            for regex in regex_list:
                matches = re.findall(regex, self.linpeas_output, re.IGNORECASE)
                if isinstance(matches, list) and matches:
                    for m in matches:
                        item = m if isinstance(m, str) else m[0] if isinstance(m, tuple) else str(m)
                        if item not in findings[category]:
                            findings[category].append(item)

        findings["total_findings"] = sum(len(v) for v in findings.values() if isinstance(v, list))
        findings["parsed"] = True
        return findings

    def run_manual_checks(self) -> dict:
        checks = {
            "SUID binaries": "find / -perm -4000 -type f 2>/dev/null | head -20",
            "Sudo privileges": "sudo -l 2>/dev/null",
            "Crontab entries": "cat /etc/crontab 2>/dev/null",
            "Kernel version": "uname -a",
            "Capabilities": "getcap -r / 2>/dev/null | head -20",
            "Writable /etc": "find /etc -writable -type f 2>/dev/null | head -20",
            "World-writable files": "find / -perm -2 -type f 2>/dev/null | head -20",
            "Listening ports": "netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null",
        }

        results = {}
        for name, cmd in checks.items():
            results[name] = {
                "command": cmd,
                "description": f"[Remote] À exécuter sur {self.target}: {cmd}",
            }

        return {
            "success": True,
            "technique": "T1068",
            "tactic": "TA0004",
            "manual_checks": results,
        }

    def run(self) -> dict:
        exploit_context = self.context.get("exploit", {})
        return {
            "linpeas": self.run_linpeas(),
            "parsed_findings": self.parse_linpeas_output(),
            "manual_checks": self.run_manual_checks(),
            "exploit_context": {
                "sqlmap_success": exploit_context.get("sqlmap", {}).get("success"),
                "msfconsole_success": exploit_context.get("msfconsole", {}).get("success"),
            } if exploit_context else {},
        }
