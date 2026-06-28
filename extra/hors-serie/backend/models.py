"""Pydantic models for KillChainAgent.

Ce module définit les modèles de données utilisés par l'API :
- Statuts des agents (énumération)
- Étapes de la kill chain
- Requête de création de mission
- Réponse après création de mission
"""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum


class AgentStatus(str, Enum):
    """Statuts possibles d'un agent lors de l'exécution d'une étape."""
    IDLE = "idle"           # Agent en attente, pas encore démarré
    RUNNING = "running"     # Agent en cours d'exécution
    COMPLETED = "completed" # Agent terminé avec succès
    FAILED = "failed"       # Agent terminé en échec


class KillChainStep(BaseModel):
    """Une étape individuelle de la kill chain ATT&CK."""

    order: int
    # Ordre d'exécution dans la séquence (1-indexé)

    tactic_id: str
    # Identifiant de la tactique MITRE ATT&CK (ex: TA0001)

    tactic_name: str
    # Nom lisible de la tactique (ex: Reconnaissance)

    technique_id: str
    # Identifiant de la technique MITRE ATT&CK (ex: T1595)

    technique_name: str
    # Nom lisible de la technique (ex: Active Scanning)

    agent: str
    # Nom de l'agent responsable de cette étape

    tool: str
    # Outil logiciel utilisé pour exécuter la technique

    status: AgentStatus = AgentStatus.IDLE
    # Statut actuel de l'exécution (défaut: IDLE)

    output: Optional[dict] = None
    # Résultat produit par l'agent après exécution (optionnel)

    timestamp: Optional[datetime] = None
    # Horodatage de la dernière mise à jour de l'étape (optionnel)


class MissionRequest(BaseModel):
    """Payload JSON attendu pour créer une nouvelle mission."""

    target: str
    # Adresse IP ou nom d'hôte de la cible à analyser

    ports: Optional[str] = "21,22,80,443,445,3306,8080"
    # Ports à scanner, séparés par des virgules (optionnel)


class MissionResponse(BaseModel):
    """Réponse renvoyée après la création d'une mission."""

    id: str
    # Identifiant unique de la mission généré par le système

    target: str
    # Cible de la mission (rappel de la requête)

    status: str
    # Statut actuel de la mission (ex: "planned", "completed")

    killchain: list
    # Liste des étapes constituant la kill chain planifiée
