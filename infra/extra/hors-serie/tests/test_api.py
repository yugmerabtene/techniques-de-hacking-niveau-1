"""Integration tests for KillChainAgent FastAPI backend."""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient


class TestHealthEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from main import app
        cls.client = TestClient(app)

    def test_health_returns_ok(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")

    def test_health_lists_agents(self):
        resp = self.client.get("/health")
        agents = resp.json()["agents"]
        self.assertIn("supervisor", agents)
        self.assertIn("recon", agents)
        self.assertEqual(len(agents), 6)


class TestMissionsAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from main import app, missions_store
        cls.client = TestClient(app)
        cls.store = missions_store

    def setUp(self):
        self.store.clear()

    def test_create_mission(self):
        resp = self.client.post("/missions", json={"target": "10.0.0.1"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "planned")
        self.assertEqual(data["target"], "10.0.0.1")
        self.assertIn("id", data)
        self.assertIn("killchain", data)

    def test_list_missions_empty(self):
        resp = self.client.get("/missions")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()["missions"]), 0)

    def test_list_missions_with_data(self):
        self.client.post("/missions", json={"target": "a"})
        self.client.post("/missions", json={"target": "b"})
        resp = self.client.get("/missions")
        self.assertEqual(len(resp.json()["missions"]), 2)

    def test_get_mission_json(self):
        create_resp = self.client.post("/missions", json={"target": "10.0.0.1"})
        mid = create_resp.json()["id"]
        resp = self.client.get(f"/missions/{mid}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["target"], "10.0.0.1")

    def test_get_mission_not_found_json(self):
        resp = self.client.get("/missions/nonexistent")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("error", resp.json())

    def test_get_mission_html(self):
        create_resp = self.client.post("/missions", json={"target": "10.0.0.1"})
        mid = create_resp.json()["id"]
        resp = self.client.get(f"/missions/{mid}", headers={"Accept": "text/html"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("<!DOCTYPE html>", resp.text)

    def test_execute_mission(self):
        create_resp = self.client.post("/missions", json={"target": "127.0.0.1"})
        mid = create_resp.json()["id"]
        resp = self.client.post(f"/missions/{mid}/execute")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "completed")

    def test_execute_mission_not_found(self):
        resp = self.client.post("/missions/fake/execute")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("error", resp.json())


class TestDashboardHTML(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from main import app
        cls.client = TestClient(app)

    def test_dashboard_returns_html(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("<!DOCTYPE html>", resp.text)
        self.assertIn("KillChainAgent", resp.text)

    def test_dashboard_has_form(self):
        resp = self.client.get("/")
        self.assertIn("mission-form", resp.text)
        self.assertIn('type="text"', resp.text)


class TestMissionExecutionFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from main import app, missions_store
        cls.client = TestClient(app)
        cls.store = missions_store

    def setUp(self):
        self.store.clear()

    def test_full_flow_plan_execute_check(self):
        resp = self.client.post("/missions", json={"target": "127.0.0.1"})
        mid = resp.json()["id"]

        exec_resp = self.client.post(f"/missions/{mid}/execute")
        self.assertEqual(exec_resp.json()["status"], "completed")
        self.assertEqual(exec_resp.json()["steps"], 7)

        get_resp = self.client.get(f"/missions/{mid}")
        mission = get_resp.json()
        self.assertEqual(mission["status"], "completed")
        self.assertEqual(len(mission["killchain"]), 7)
        for step in mission["killchain"]:
            self.assertEqual(step["status"], "completed")
            self.assertIn("output", step)

    def test_multiple_missions_independent(self):
        r1 = self.client.post("/missions", json={"target": "a"})
        r2 = self.client.post("/missions", json={"target": "b"})
        id1, id2 = r1.json()["id"], r2.json()["id"]

        self.client.post(f"/missions/{id1}/execute")
        m1 = self.client.get(f"/missions/{id1}").json()
        m2 = self.client.get(f"/missions/{id2}").json()
        self.assertEqual(m1["status"], "completed")
        self.assertEqual(m2["status"], "planned")


if __name__ == "__main__":
    unittest.main()
