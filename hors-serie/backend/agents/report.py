"""
ReportAgent — Génération de rapport de pentest.
CVSS + ATT&CK mapping + Markdown
"""

from datetime import datetime


class ReportAgent:
    def __init__(self, target: str):
        self.target = target

    def run(self) -> dict:
        return {
            "title": f"Rapport de Pentest — {self.target}",
            "date": datetime.now().isoformat(),
            "methodology": "PTES + MITRE ATT&CK v15",
            "cvss": {
                "version": "3.1",
                "calculator_url": "https://www.first.org/cvss/calculator/3.1",
            },
            "sections": [
                "1. Résumé exécutif",
                "2. Méthodologie",
                "3. Synthèse des vulnérabilités",
                "4. Fiches détaillées (CVSS + ATT&CK)",
                "5. Recommandations",
                "6. Annexes",
            ],
            "format": "Markdown + ATT&CK Navigator JSON",
        }
