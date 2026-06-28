"""Agent registry for KillChainAgent."""

from .supervisor import SupervisorAgent
from .recon import ReconAgent
from .exploit import ExploitAgent
from .privesc import PrivEscAgent
from .persist import PersistAgent
from .report import ReportAgent

__all__ = [
    "SupervisorAgent",
    "ReconAgent",
    "ExploitAgent",
    "PrivEscAgent",
    "PersistAgent",
    "ReportAgent",
]
