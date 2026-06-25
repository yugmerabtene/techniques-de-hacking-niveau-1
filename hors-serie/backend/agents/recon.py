"""
ReconAgent — Reconnaissance réseau.
TA0007 Discovery — T1046 Network Service Scanning / T1595 Active Scanning
"""

import subprocess
import xml.etree.ElementTree as ET


class ReconAgent:
    def __init__(self, target: str, context: dict = None):
        self.target = target
        self.context = context or {}

    def run_nmap(self) -> dict:
        try:
            cmd = ["nmap", "-sV", "-sC", "-p", "21,22,80,443,445,3306,8080",
                   self.target, "-oX", "-"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                return {"success": False, "error": result.stderr.strip()}

            root = ET.fromstring(result.stdout)
            ports = []
            for host in root.findall("host"):
                for port in host.findall(".//port"):
                    service = port.find("service")
                    ports.append({
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "service": service.get("name") if service is not None else "unknown",
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
        try:
            cmd = ["gobuster", "dir", "-u", f"http://{self.target}",
                   "-w", "/usr/share/wordlists/dirb/common.txt", "-q"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            dirs = [line for line in result.stdout.strip().split("\n") if line]
            return {
                "success": True,
                "technique": "T1595",
                "tactic": "TA0007",
                "tool": "gobuster",
                "directories_found": len(dirs),
                "directories": dirs[:20],
            }
        except FileNotFoundError:
            return {"success": False, "error": "gobuster not installed"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "gobuster timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def run(self) -> dict:
        return {
            "nmap": self.run_nmap(),
            "gobuster": self.run_gobuster(),
        }
