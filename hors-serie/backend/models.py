"""Pydantic models for KillChainAgent."""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class KillChainStep(BaseModel):
    order: int
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    agent: str
    tool: str
    status: AgentStatus = AgentStatus.IDLE
    output: Optional[dict] = None
    timestamp: Optional[datetime] = None


class MissionRequest(BaseModel):
    target: str
    ports: Optional[str] = "21,22,80,443,445,3306,8080"


class MissionResponse(BaseModel):
    id: str
    target: str
    status: str
    killchain: list
