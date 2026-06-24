"""SQLite database for KillChainAgent missions."""

import sqlite3
import json
from datetime import datetime


class Database:
    def __init__(self, path: str = "killchain.db"):
        self.conn = sqlite3.connect(path)
        self._init_db()

    def _init_db(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS missions (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT DEFAULT 'planned',
                killchain TEXT,
                created_at TEXT
            )
        """)
        self.conn.commit()

    def save_mission(self, mission_id: str, target: str, killchain: list):
        self.conn.execute(
            "INSERT OR REPLACE INTO missions VALUES (?, ?, ?, ?, ?)",
            (mission_id, target, "completed",
             json.dumps(killchain),
             datetime.now().isoformat())
        )
        self.conn.commit()

    def get_mission(self, mission_id: str) -> dict:
        row = self.conn.execute(
            "SELECT * FROM missions WHERE id = ?", (mission_id,)
        ).fetchone()
        if row:
            return {"id": row[0], "target": row[1], "status": row[2],
                    "killchain": json.loads(row[3]), "created_at": row[4]}
        return None

    def list_missions(self) -> list:
        rows = self.conn.execute("SELECT id, target, status, created_at FROM missions").fetchall()
        return [{"id": r[0], "target": r[1], "status": r[2], "created_at": r[3]} for r in rows]
