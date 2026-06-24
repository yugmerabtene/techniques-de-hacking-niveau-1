"""
SupervisorAgent — Planifie et orchestre la kill chain ATT&CK.
Pattern : Supervisor (Chapitre 6, agentic-developer-craftsmanship)
"""

import uuid
from typing import Dict


class SupervisorAgent:
    KILLCHAIN_TEMPLATE = [
        {"order": 1, "tactic_id": "TA0007", "tactic_name": "Discovery",
         "technique_id": "T1046", "technique_name": "Network Service Scanning",
         "agent": "recon", "tool": "nmap"},
        {"order": 2, "tactic_id": "TA0007", "tactic_name": "Discovery",
         "technique_id": "T1595", "technique_name": "Active Scanning",
         "agent": "recon", "tool": "gobuster"},
        {"order": 3, "tactic_id": "TA0001", "tactic_name": "Initial Access",
         "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
         "agent": "exploit", "tool": "msfconsole"},
        {"order": 4, "tactic_id": "TA0001", "tactic_name": "Initial Access",
         "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
         "agent": "exploit", "tool": "sqlmap"},
        {"order": 5, "tactic_id": "TA0004", "tactic_name": "Privilege Escalation",
         "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation",
         "agent": "privesc", "tool": "LinPEAS"},
        {"order": 6, "tactic_id": "TA0003", "tactic_name": "Persistence",
         "technique_id": "T1098", "technique_name": "Account Manipulation",
         "agent": "persist", "tool": "ssh-keygen"},
        {"order": 7, "tactic_id": "TA0000", "tactic_name": "Reporting",
         "technique_id": "T0000", "technique_name": "Pentest Report",
         "agent": "report", "tool": "python"},
    ]

    def __init__(self, target: str):
        self.target = target
        self.mission_id = str(uuid.uuid4())[:8]

    def plan(self) -> Dict:
        return {
            "id": self.mission_id,
            "target": self.target,
            "killchain": self.KILLCHAIN_TEMPLATE,
        }

    def execute_step(self, step: Dict) -> Dict:
        from .recon import ReconAgent
        from .exploit import ExploitAgent
        from .privesc import PrivEscAgent
        from .persist import PersistAgent
        from .report import ReportAgent

        agents = {
            "recon": ReconAgent,
            "exploit": ExploitAgent,
            "privesc": PrivEscAgent,
            "persist": PersistAgent,
            "report": ReportAgent,
        }

        agent_class = agents.get(step["agent"])
        if not agent_class:
            step["status"] = "failed"
            step["output"] = {"error": f"Agent {step['agent']} inconnu"}
            return step

        agent = agent_class(target=self.target)
        result = agent.run()
        step["output"] = result
        step["status"] = "completed"
        return step
