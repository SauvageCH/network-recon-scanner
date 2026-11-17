"""SQLite persistence (standard library only, zero cost)."""
import json
import os
import sqlite3
from datetime import datetime

from config import Config


def _conn():
    os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
    c = sqlite3.connect(Config.DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, profile TEXT,
            status TEXT, created_at TEXT, finished_at TEXT, result TEXT, error TEXT)""")


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def create(target, profile) -> int:
    with _conn() as c:
        cur = c.execute("INSERT INTO scans (target, profile, status, created_at) VALUES (?,?,?,?)",
                        (target, profile, "queued", _now()))
        return cur.lastrowid


def set_running(scan_id):
    with _conn() as c:
        c.execute("UPDATE scans SET status='running' WHERE id=?", (scan_id,))


def finish(scan_id, result: dict):
    with _conn() as c:
        c.execute("UPDATE scans SET status='done', finished_at=?, result=? WHERE id=?",
                  (_now(), json.dumps(result), scan_id))


def fail(scan_id, error: str):
    with _conn() as c:
        c.execute("UPDATE scans SET status='error', finished_at=?, error=? WHERE id=?",
                  (_now(), error, scan_id))


def _row(r, full=True):
    d = {k: r[k] for k in ("id", "target", "profile", "status", "created_at", "finished_at", "error")}
    if full:
        d["result"] = json.loads(r["result"]) if r["result"] else None
    return d


def get(scan_id):
    with _conn() as c:
        r = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return _row(r) if r else None


def list_all():
    with _conn() as c:
        rows = c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50").fetchall()
    out = []
    for r in rows:
        d = _row(r, full=False)
        d["summary"] = (json.loads(r["result"]).get("summary") if r["result"] else None)
        out.append(d)
    return out


def delete(scan_id):
    with _conn() as c:
        c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
