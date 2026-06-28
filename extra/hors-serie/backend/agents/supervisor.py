"""
SupervisorAgent — Planifie et orchestre la kill chain ATT&CK.

Rôle dans la kill chain :
    Le SupervisorAgent est l'orchestrateur central. Il définit le plan
    d'attaque (KILLCHAIN_TEMPLATE), instancie chaque agent spécialisé dans
    l'ordre de la kill chain, collecte les résultats, et propage le contexte
    entre les étapes pour assurer la continuité de la mission.

Pattern : Supervisor (Chapitre 6, agentic-developer-craftsmanship)

Étapes de la kill chain définies dans KILLCHAIN_TEMPLATE :
    1. Reconnaissance réseau — nmap (T1046) + gobuster (T1595)
    2. Accès initial — msfconsole + sqlmap (T1190)
    3. Élévation de privilèges — LinPEAS (T1068)
    4. Persistance — SSH key, cron, systemd (T1098)
    5. Rapport — Génération automatisée
"""

import uuid
from datetime import datetime
from typing import Dict, List


class SupervisorAgent:
    # --- Kill Chain : plan d'attaque séquentiel conforme MITRE ATT&CK ---
    KILLCHAIN_TEMPLATE = [
        {
            "order": 1,
            "tactic_id": "TA0007",          # Discovery : reconnaissance
            "tactic_name": "Discovery",
            "technique_id": "T1046",         # Network Service Scanning
            "technique_name": "Network Service Scanning",
            "agent": "recon",                # Agent responsable : ReconAgent
            "tool": "nmap",                  # Outil utilisé
        },
        {
            "order": 2,
            "tactic_id": "TA0007",          # Discovery : reconnaissance (bis)
            "tactic_name": "Discovery",
            "technique_id": "T1595",         # Active Scanning (web dirs)
            "technique_name": "Active Scanning",
            "agent": "recon",
            "tool": "gobuster",
        },
        {
            "order": 3,
            "tactic_id": "TA0001",          # Initial Access : compromission
            "tactic_name": "Initial Access",
            "technique_id": "T1190",         # Exploit Public-Facing App
            "technique_name": "Exploit Public-Facing Application",
            "agent": "exploit",
            "tool": "msfconsole",
        },
        {
            "order": 4,
            "tactic_id": "TA0001",          # Initial Access (bis)
            "tactic_name": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "agent": "exploit",
            "tool": "sqlmap",
        },
        {
            "order": 5,
            "tactic_id": "TA0004",          # Privilege Escalation
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1068",         # Exploitation for PrivEsc
            "technique_name": "Exploitation for Privilege Escalation",
            "agent": "privesc",
            "tool": "LinPEAS",
        },
        {
            "order": 6,
            "tactic_id": "TA0003",          # Persistence : maintien d'accès
            "tactic_name": "Persistence",
            "technique_id": "T1098",         # Account Manipulation
            "technique_name": "Account Manipulation",
            "agent": "persist",
            "tool": "ssh-keygen",
        },
        {
            "order": 7,
            "tactic_id": "TA0000",          # T0000 : phase custom (rapport)
            "tactic_name": "Reporting",
            "technique_id": "T0000",
            "technique_name": "Pentest Report",
            "agent": "report",
            "tool": "python",
        },
    ]

    def __init__(self, target: str):
        """
        Initialise le superviseur pour une mission de pentest.

        Args:
            target (str): Adresse IP ou nom d'hôte de la cible.
        """
        self.target = target
        # Identifiant unique de mission (8 premiers caractères d'un UUID4)
        self.mission_id = str(uuid.uuid4())[:8]

    def plan(self) -> Dict:
        """
        Génère le plan de mission complet (sans exécution).

        Returns:
            Dict: Plan contenant l'ID de mission, la cible, et le template
                  de la kill chain.
        """
        return {
            "id": self.mission_id,
            "target": self.target,
            "killchain": self.KILLCHAIN_TEMPLATE,
        }

    def _get_agent(self, name: str):
        """
        Résout le nom logique d'un agent vers sa classe concrète.

        Les imports sont faits localement pour éviter les dépendances
        circulaires au chargement du module.

        Args:
            name (str): Nom logique de l'agent
                        ('recon', 'exploit', 'privesc', 'persist', 'report').

        Returns:
            type or None: La classe de l'agent si trouvée, None sinon.
        """
        # Imports locaux pour éviter les imports circulaires
        from .recon import ReconAgent
        from .exploit import ExploitAgent
        from .privesc import PrivEscAgent
        from .persist import PersistAgent
        from .report import ReportAgent

        # Mapping nom logique → classe d'agent
        agents = {
            "recon": ReconAgent,
            "exploit": ExploitAgent,
            "privesc": PrivEscAgent,
            "persist": PersistAgent,
            "report": ReportAgent,
        }
        return agents.get(name)

    def execute(self) -> List[Dict]:
        """
        Exécute l'intégralité de la kill chain, étape par étape.

        Chaque étape du template est instanciée et exécutée séquentiellement.
        Le contexte (résultats des étapes précédentes) est propagé aux agents
        suivants pour permettre des décisions éclairées.

        Returns:
            List[Dict]: Liste des étapes exécutées, chacune contenant
                        le template original enrichi du statut, timestamp
                        et des résultats (output) de l'agent.
        """
        steps = []
        # Contexte initial : cible + identifiant de mission
        context = {"target": self.target, "mission_id": self.mission_id}

        for step_template in self.KILLCHAIN_TEMPLATE:
            # Copie du template pour ne pas muter l'original
            step = dict(step_template)
            step["status"] = "running"
            step["timestamp"] = datetime.now().isoformat()

            # Résolution de l'agent via le mapping
            agent_cls = self._get_agent(step["agent"])
            if not agent_cls:
                # Agent inconnu : échec immédiat de l'étape
                step["status"] = "failed"
                step["output"] = {"error": f"Agent {step['agent']} inconnu"}
                steps.append(step)
                continue

            # Instanciation et exécution de l'agent avec le contexte cumulatif
            agent = agent_cls(target=self.target, context=context)
            step["output"] = agent.run()
            step["status"] = "completed"

            # Propagation du résultat dans le contexte pour les étapes suivantes
            context[step["agent"]] = step["output"]

            steps.append(step)

        return steps

    def execute_step(self, step: Dict, context: Dict = None) -> Dict:
        """
        Exécute une étape unique de la kill chain (mode pas-à-pas).

        Utile pour le débogage ou l'exécution manuelle d'une phase spécifique.

        Args:
            step (Dict): Template d'étape (même structure que KILLCHAIN_TEMPLATE).
            context (Dict, optional): Contexte cumulatif des étapes précédentes.

        Returns:
            Dict: Étape exécutée avec statut, timestamp, et résultats.
        """
        # Copie pour ne pas muter l'entrée originale
        step = dict(step)
        step["timestamp"] = datetime.now().isoformat()

        # Résolution de l'agent
        agent_cls = self._get_agent(step["agent"])
        if not agent_cls:
            step["status"] = "failed"
            step["output"] = {"error": f"Agent {step['agent']} inconnu"}
            return step

        # Instanciation avec le contexte fourni (ou vide)
        agent = agent_cls(target=self.target, context=context or {})
        step["output"] = agent.run()
        step["status"] = "completed"
        return step
