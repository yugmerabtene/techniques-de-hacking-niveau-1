"""Unit tests for KillChainAgent Pydantic models."""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from models import MissionRequest, MissionResponse, KillChainStep, AgentStatus


class TestMissionRequest(unittest.TestCase):
    def test_valid_mission_request(self):
        req = MissionRequest(target="10.0.0.1")
        self.assertEqual(req.target, "10.0.0.1")
        self.assertEqual(req.ports, "21,22,80,443,445,3306,8080")

    def test_custom_ports(self):
        req = MissionRequest(target="10.0.0.2", ports="80,443")
        self.assertEqual(req.ports, "80,443")

    def test_target_is_required(self):
        with self.assertRaises(Exception):
            MissionRequest()


class TestKillChainStep(unittest.TestCase):
    def test_default_status_is_idle(self):
        step = KillChainStep(
            order=1, tactic_id="TA0007", tactic_name="Discovery",
            technique_id="T1046", technique_name="Network Service Scanning",
            agent="recon", tool="nmap"
        )
        self.assertEqual(step.status, AgentStatus.IDLE)

    def test_failed_status(self):
        step = KillChainStep(
            order=1, tactic_id="TA0007", tactic_name="Discovery",
            technique_id="T1046", technique_name="Network Service Scanning",
            agent="recon", tool="nmap", status=AgentStatus.FAILED
        )
        self.assertEqual(step.status, AgentStatus.FAILED)


class TestMissionResponse(unittest.TestCase):
    def test_valid_response(self):
        resp = MissionResponse(
            id="abc123", target="10.0.0.1", status="planned",
            killchain=[]
        )
        self.assertEqual(resp.id, "abc123")
        self.assertEqual(resp.target, "10.0.0.1")
        self.assertEqual(resp.status, "planned")


class TestAgentStatusEnum(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(AgentStatus.IDLE.value, "idle")
        self.assertEqual(AgentStatus.RUNNING.value, "running")
        self.assertEqual(AgentStatus.COMPLETED.value, "completed")
        self.assertEqual(AgentStatus.FAILED.value, "failed")


if __name__ == "__main__":
    unittest.main()
