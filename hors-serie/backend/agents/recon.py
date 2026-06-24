"""
ReconAgent — Reconnaissance réseau.
TA0007 Discovery — T1046 Network Service Scanning
"""

import subprocess
import xml.etree.ElementTree as ET


class ReconAgent:
    def __init__(self, target: str):
        self.target = target

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

    def run(self) -> dict:
        return self.run_nmap()
