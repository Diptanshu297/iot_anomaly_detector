from __future__ import annotations
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    ip          TEXT PRIMARY KEY,
    first_seen  TIMESTAMP,
    last_seen   TIMESTAMP,
    nickname    TEXT
);
CREATE TABLE IF NOT EXISTS feature_windows (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip               TEXT,
    window_start            TIMESTAMP,
    window_end              TIMESTAMP,
    packet_count            INTEGER,
    byte_count              INTEGER,
    unique_dst_ips          INTEGER,
    unique_dst_ports        INTEGER,
    avg_packet_size         REAL,
    tcp_ratio               REAL,
    udp_ratio               REAL,
    dns_count               INTEGER,
    outbound_inbound_ratio  REAL,
    anomaly_score           REAL
);
CREATE TABLE IF NOT EXISTS anomalies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip   TEXT,
    window_id   INTEGER,
    detected_at TIMESTAMP,
    score       REAL,
    severity    TEXT,
    notes       TEXT
);
CREATE TABLE IF NOT EXISTS actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip   TEXT,
    action_type TEXT,
    actor       TEXT,
    created_at  TIMESTAMP,
    expires_at  TIMESTAMP
);
CREATE TABLE IF NOT EXISTS comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    anomaly_id  INTEGER,
    author      TEXT,
    body        TEXT,
    created_at  TIMESTAMP,
    resolved    INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_windows_device ON feature_windows(device_ip, window_start);
CREATE INDEX IF NOT EXISTS idx_anomalies_det  ON anomalies(detected_at);
CREATE INDEX IF NOT EXISTS idx_anomalies_dev  ON anomalies(device_ip);
CREATE INDEX IF NOT EXISTS idx_actions_device ON actions(device_ip);
CREATE INDEX IF NOT EXISTS idx_comments_anom  ON comments(anomaly_id);
"""

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

class Database:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(self.path, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode = WAL")
        c.execute("PRAGMA synchronous = NORMAL")
        try:
            yield c
        finally:
            c.close()

    def _ensure_schema(self) -> None:
        with self._conn() as c:
            c.executescript(SCHEMA)

    def list_devices(self) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM devices ORDER BY ip").fetchall()]

    def recent_windows(self, device_ip: Optional[str] = None, limit: int = 100) -> list[dict]:
        with self._conn() as c:
            if device_ip:
                rows = c.execute(
                    "SELECT * FROM feature_windows WHERE device_ip = ? ORDER BY window_start DESC LIMIT ?",
                    (device_ip, limit)).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM feature_windows ORDER BY window_start DESC LIMIT ?",
                    (limit,)).fetchall()
            return [dict(r) for r in rows]

    def recent_anomalies(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM anomalies ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()]

    def device(self, ip: str) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute("SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()
            return dict(r) if r else None

    def device_anomalies(self, ip: str, limit: int = 200) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM anomalies WHERE device_ip = ? ORDER BY detected_at DESC LIMIT ?",
                (ip, limit)).fetchall()]

    def windows_since(self, since_iso: str, limit: int = 5000) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM feature_windows WHERE window_start >= ? ORDER BY window_start LIMIT ?",
                (since_iso, limit)).fetchall()]

    def anomalies_since(self, since_iso: str, limit: int = 5000) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM anomalies WHERE detected_at >= ? ORDER BY detected_at DESC LIMIT ?",
                (since_iso, limit)).fetchall()]

    def severity_counts(self, since_iso: Optional[str] = None) -> dict[str, int]:
        sql = "SELECT severity, COUNT(*) c FROM anomalies"
        args: tuple = ()
        if since_iso:
            sql += " WHERE detected_at >= ?"
            args = (since_iso,)
        sql += " GROUP BY severity"
        with self._conn() as c:
            return {row["severity"]: row["c"] for row in c.execute(sql, args).fetchall()}

    def total_windows(self) -> int:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM feature_windows").fetchone()[0]

    def total_anomalies(self) -> int:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]

    def add_action(self, ip: str, action_type: str, actor: str, expires_at: Optional[str] = None) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO actions (device_ip, action_type, actor, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (ip, action_type, actor, _utcnow_iso(), expires_at))

    def active_actions(self) -> dict[str, dict]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT a.* FROM actions a
                JOIN (
                    SELECT device_ip, MAX(id) AS mid FROM actions
                    WHERE (expires_at IS NULL OR expires_at > ?)
                    GROUP BY device_ip
                ) m ON a.id = m.mid
                WHERE a.action_type != 'release' AND a.action_type != 'unmute'
            """, (_utcnow_iso(),)).fetchall()
            return {r["device_ip"]: dict(r) for r in rows}

    def recent_actions(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    def add_comment(self, anomaly_id: int, author: str, body: str) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO comments (anomaly_id, author, body, created_at) VALUES (?, ?, ?, ?)",
                (anomaly_id, author, body, _utcnow_iso()))

    def set_anomaly_resolved(self, anomaly_id: int, resolved: bool) -> None:
        with self._conn() as c:
            c.execute("UPDATE comments SET resolved = ? WHERE anomaly_id = ?",
                      (1 if resolved else 0, anomaly_id))

    def comments_for(self, anomaly_id: int) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM comments WHERE anomaly_id = ? ORDER BY created_at",
                (anomaly_id,)).fetchall()]

    def comment_counts(self) -> dict[int, int]:
        with self._conn() as c:
            return {row["anomaly_id"]: row["c"] for row in c.execute(
                "SELECT anomaly_id, COUNT(*) c FROM comments GROUP BY anomaly_id").fetchall()}

    def is_resolved(self, anomaly_id: int) -> bool:
        with self._conn() as c:
            r = c.execute("SELECT MAX(resolved) FROM comments WHERE anomaly_id = ?",
                          (anomaly_id,)).fetchone()
            return bool(r[0]) if r and r[0] is not None else False