"""SQLite case store (one file on a volume; fine for a single-node lab)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, created REAL, mode TEXT, rule TEXT, disposition TEXT, severity TEXT,
  risk_score INTEGER, decided_by TEXT, alert TEXT, decision TEXT, lab_truth TEXT,
  analyst_verdict TEXT, analyst_note TEXT, updated REAL
);
CREATE INDEX IF NOT EXISTS cases_created ON cases(created DESC);
"""


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)

    def save(self, alert: dict, decision: dict, truth: dict | None):
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,?)",
                (decision["alert_id"], time.time(), decision["mode"], alert.get("rule", {}).get("name", ""),
                 decision["disposition"], decision["severity"], decision["risk_score"], decision["decided_by"],
                 json.dumps(alert), json.dumps(decision), json.dumps(truth) if truth else None, time.time()))
            self.db.commit()

    def list(self, limit: int = 100, disposition: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM cases", []
        if disposition:
            q, args = q + " WHERE disposition = ?", [disposition]
        with self.lock:
            rows = self.db.execute(q + " ORDER BY created DESC LIMIT ?", args + [limit]).fetchall()
        return [self._row(r) for r in rows]

    def get(self, case_id: str) -> dict | None:
        with self.lock:
            r = self.db.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        return self._row(r) if r else None

    def feedback(self, case_id: str, verdict: str, note: str) -> bool:
        with self.lock:
            cur = self.db.execute("UPDATE cases SET analyst_verdict=?, analyst_note=?, updated=? WHERE id=?",
                                  (verdict, note, time.time(), case_id))
            self.db.commit()
        return cur.rowcount == 1

    def counts(self) -> dict:
        with self.lock:
            rows = self.db.execute("SELECT disposition, decided_by, COUNT(*) n FROM cases GROUP BY 1,2").fetchall()
        return {f"{r['disposition']}/{r['decided_by']}": r["n"] for r in rows}

    @staticmethod
    def _row(r) -> dict:
        d = dict(r)
        for k in ("alert", "decision", "lab_truth"):
            d[k] = json.loads(d[k]) if d[k] else None
        return d
