"""
SupervisorAgent — Planifie et orchestre la kill chain ATT&CK.
Pattern : Supervisor (Chapitre 6, agentic-developer-craftsmanship)
"""

import uuid
from datetime import datetime
from typing import Dict, List


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

    def _get_agent(self, name: str):
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
        return agents.get(name)

    def execute(self) -> List[Dict]:
        steps = []
        context = {"target": self.target, "mission_id": self.mission_id}

        for step_template in self.KILLCHAIN_TEMPLATE:
            step = dict(step_template)
            step["status"] = "running"
            step["timestamp"] = datetime.now().isoformat()

            agent_cls = self._get_agent(step["agent"])
            if not agent_cls:
                step["status"] = "failed"
                step["output"] = {"error": f"Agent {step['agent']} inconnu"}
                steps.append(step)
                continue

            agent = agent_cls(target=self.target, context=context)
            step["output"] = agent.run()
            step["status"] = "completed"

            context[step["agent"]] = step["output"]

            steps.append(step)

        return steps

    def execute_step(self, step: Dict, context: Dict = None) -> Dict:
        step = dict(step)
        step["timestamp"] = datetime.now().isoformat()

        agent_cls = self._get_agent(step["agent"])
        if not agent_cls:
            step["status"] = "failed"
            step["output"] = {"error": f"Agent {step['agent']} inconnu"}
            return step

        agent = agent_cls(target=self.target, context=context or {})
        step["output"] = agent.run()
        step["status"] = "completed"
        return step
