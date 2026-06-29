"""Unit tests for KillChainAgent database layer."""

import sys
import os
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from database import Database


class TestDatabase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.db = Database(path=self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_init_creates_table(self):
        cursor = self.db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='missions'"
        )
        self.assertIsNotNone(cursor.fetchone())

    def test_save_and_get_mission(self):
        killchain = [{"order": 1, "agent": "recon", "status": "completed"}]
        self.db.save_mission("m1", "10.0.0.1", killchain)
        mission = self.db.get_mission("m1")
        self.assertEqual(mission["id"], "m1")
        self.assertEqual(mission["target"], "10.0.0.1")
        self.assertEqual(mission["status"], "completed")
        self.assertEqual(len(mission["killchain"]), 1)

    def test_get_nonexistent_mission(self):
        self.assertIsNone(self.db.get_mission("does_not_exist"))

    def test_list_missions_empty(self):
        missions = self.db.list_missions()
        self.assertEqual(len(missions), 0)

    def test_list_missions_multiple(self):
        self.db.save_mission("a", "1.1.1.1", [])
        self.db.save_mission("b", "2.2.2.2", [])
        self.db.save_mission("c", "3.3.3.3", [])
        missions = self.db.list_missions()
        self.assertEqual(len(missions), 3)

    def test_overwrite_mission(self):
        self.db.save_mission("x", "old", [{"step": 1}])
        self.db.save_mission("x", "new", [{"step": 2}])
        m = self.db.get_mission("x")
        self.assertEqual(m["target"], "new")
        self.assertEqual(len(m["killchain"]), 1)

    def test_save_mission_has_created_at(self):
        self.db.save_mission("t", "target", [])
        m = self.db.get_mission("t")
        self.assertIsNotNone(m["created_at"])


if __name__ == "__main__":
    unittest.main()
