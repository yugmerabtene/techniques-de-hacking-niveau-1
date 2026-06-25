"""Unit tests for KillChainAgent agents."""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from agents.supervisor import SupervisorAgent


class TestSupervisorAgent(unittest.TestCase):
    def setUp(self):
        self.supervisor = SupervisorAgent(target="192.168.1.10")

    def test_plan_returns_dict(self):
        result = self.supervisor.plan()
        self.assertIsInstance(result, dict)
        self.assertIn("id", result)
        self.assertIn("target", result)
        self.assertIn("killchain", result)

    def test_plan_has_correct_target(self):
        result = self.supervisor.plan()
        self.assertEqual(result["target"], "192.168.1.10")

    def test_plan_killchain_has_7_steps(self):
        result = self.supervisor.plan()
        self.assertEqual(len(result["killchain"]), 7)

    def test_plan_killchain_order(self):
        result = self.supervisor.plan()
        orders = [s["order"] for s in result["killchain"]]
        self.assertEqual(orders, list(range(1, 8)))

    def test_mission_id_is_unique(self):
        s1 = SupervisorAgent(target="a")
        s2 = SupervisorAgent(target="b")
        self.assertNotEqual(s1.mission_id, s2.mission_id)

    def test_killchain_template_has_required_fields(self):
        for step in self.supervisor.KILLCHAIN_TEMPLATE:
            for field in ["order", "tactic_id", "technique_id", "agent", "tool"]:
                self.assertIn(field, step, f"Missing {field} in step {step}")

    def test_get_agent_returns_class(self):
        self.assertIsNotNone(self.supervisor._get_agent("recon"))
        self.assertIsNotNone(self.supervisor._get_agent("exploit"))
        self.assertIsNotNone(self.supervisor._get_agent("privesc"))
        self.assertIsNotNone(self.supervisor._get_agent("persist"))
        self.assertIsNotNone(self.supervisor._get_agent("report"))
        self.assertIsNone(self.supervisor._get_agent("nonexistent"))


class TestPrivEscAgentParsing(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
        from agents.privesc import PrivEscAgent
        self.PrivEscAgent = PrivEscAgent

    def test_parse_empty_output(self):
        agent = self.PrivEscAgent(target="test", linpeas_output="")
        result = agent.parse_linpeas_output()
        self.assertEqual(result["total_findings"], 0)

    def test_parse_kernel_exploit(self):
        sample = """
        [*] CVE-2016-5195 DirtyCow exploit possible
        Linux kernel 3.13.0 detected
        """
        agent = self.PrivEscAgent(target="test", linpeas_output=sample)
        result = agent.parse_linpeas_output()
        self.assertGreater(len(result["kernel_exploits"]), 0)
        self.assertIn("CVE-2016-5195", result["kernel_exploits"])

    def test_parse_sudo_nopasswd(self):
        sample = """
        User www-data may run the following commands on target:
            (ALL) NOPASSWD: /usr/bin/find
        """
        agent = self.PrivEscAgent(target="test", linpeas_output=sample)
        result = agent.parse_linpeas_output()
        self.assertGreater(len(result["sudo_privileges"]), 0)

    def test_parse_credentials(self):
        sample = """
        DB_PASSWORD = super_secret_123
        mysql -u root -p admin123
        """
        agent = self.PrivEscAgent(target="test", linpeas_output=sample)
        result = agent.parse_linpeas_output()
        self.assertGreater(len(result["credentials"]), 0)

    def test_run_manual_checks_has_8_items(self):
        agent = self.PrivEscAgent(target="test")
        result = agent.run_manual_checks()
        self.assertEqual(len(result["manual_checks"]), 8)


class TestPersistAgent(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
        from agents.persist import PersistAgent
        self.PersistAgent = PersistAgent

    def test_run_returns_4_methods(self):
        agent = self.PersistAgent(target="192.168.1.10")
        result = agent.run()
        self.assertEqual(len(result["persistence_methods"]), 4)

    def test_cron_contains_target(self):
        agent = self.PersistAgent(target="10.0.0.1")
        cron = agent.generate_cron()
        self.assertIn("10.0.0.1", cron["command"])

    def test_systemd_generates_4_commands(self):
        agent = self.PersistAgent(target="10.0.0.1")
        svc = agent.generate_systemd_service()
        self.assertEqual(len(svc["commands"]), 4)
        self.assertIn("[Unit]", svc["unit_content"])

    def test_suid_backdoor_has_cleanup(self):
        agent = self.PersistAgent(target="test")
        suid = agent.generate_suid_backdoor()
        self.assertIn("cleanup", suid)
        self.assertIn(".bash", suid["command"])


class TestReportAgent(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
        from agents.report import ReportAgent
        self.ReportAgent = ReportAgent

    def test_generate_markdown_contains_sections(self):
        context = {
            "mission_id": "test123",
            "recon": {"nmap": {"ports": []}, "gobuster": {"directories_found": 0, "directories": []}},
            "exploit": {"sqlmap": {"success": False}, "msfconsole": {"success": False}},
            "privesc": {"linpeas": {"success": False}},
            "persist": {"persistence_methods": []},
        }
        agent = self.ReportAgent(target="10.0.0.1", context=context)
        md = agent.generate_markdown()
        self.assertIn("Résumé exécutif", md)
        self.assertIn("Méthodologie (PTES)", md)
        self.assertIn("Matrice MITRE ATT&CK", md)
        self.assertIn("Recommandations", md)
        self.assertIn("10.0.0.1", md)
        self.assertIn("test123", md)

    def test_generate_markdown_with_ports(self):
        context = {
            "mission_id": "test",
            "recon": {
                "nmap": {"ports": [
                    {"port": "80", "protocol": "tcp", "service": "http", "version": "Apache 2.4"},
                    {"port": "22", "protocol": "tcp", "service": "ssh", "version": "OpenSSH 7.9"}
                ], "open_ports": 2},
                "gobuster": {"directories_found": 2, "directories": ["/admin", "/backup"]},
            },
            "exploit": {"sqlmap": {"success": True}, "msfconsole": {"success": False}},
            "privesc": {"linpeas": {"success": True}},
            "persist": {"persistence_methods": [{}, {}, {}]},
        }
        agent = self.ReportAgent(target="target", context=context)
        md = agent.generate_markdown()
        self.assertIn("Apache 2.4", md)
        self.assertIn("OpenSSH 7.9", md)
        self.assertIn("/admin", md)
        self.assertIn("Succès", md)

    def test_attack_navigator_json_has_5_techniques(self):
        agent = self.ReportAgent(target="test")
        nav = agent.generate_attack_navigator_json()
        self.assertEqual(len(nav["techniques"]), 5)
        self.assertIn("gradient", nav)
        self.assertEqual(nav["domain"], "enterprise-attack")

    def test_run_returns_all_formats(self):
        agent = self.ReportAgent(target="test", context={"mission_id": "1"})
        result = agent.run()
        self.assertIn("markdown", result)
        self.assertIn("attack_navigator", result)
        self.assertIn("export_formats", result)


if __name__ == "__main__":
    unittest.main()
