import sqlite3
import json
import os

DB_PATH = os.environ.get("DB_PATH", "threat_hunter.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                machine    TEXT,
                event_id   INTEGER,
                log        TEXT,
                time       TEXT,
                timestamp  REAL,
                source     TEXT,
                strings    TEXT,
                created_at REAL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                machine      TEXT,
                event_id     INTEGER,
                technique_id TEXT,
                technique    TEXT,
                tactic       TEXT,
                severity     TEXT,
                description  TEXT,
                details      TEXT,
                time         TEXT,
                timestamp    REAL,
                acknowledged INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_events_machine    ON events(machine);
        """)


def insert_events(events):
    with get_conn() as conn:
        conn.executemany(
            """INSERT INTO events (machine, event_id, log, time, timestamp, source, strings)
               VALUES (:machine, :event_id, :log, :time, :timestamp, :source, :strings)""",
            [
                {**e, "strings": json.dumps(e.get("strings", []))}
                for e in events
            ]
        )


def insert_alert(alert):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO alerts
               (machine, event_id, technique_id, technique, tactic, severity,
                description, details, time, timestamp)
               VALUES (:machine, :event_id, :technique_id, :technique, :tactic,
                       :severity, :description, :details, :time, :timestamp)""",
            {**alert, "details": json.dumps(alert.get("details", {}))}
        )


def get_recent_events(limit=200):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_alerts(limit=200, unacked_only=False):
    with get_conn() as conn:
        if unacked_only:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE acknowledged=0 ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


def count_recent_events(machine, event_id, since_timestamp):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM events WHERE machine=? AND event_id=? AND timestamp>=?",
            (machine, event_id, since_timestamp)
        ).fetchone()
    return row[0]


def acknowledge_alert(alert_id):
    with get_conn() as conn:
        conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))


def get_stats():
    with get_conn() as conn:
        total_events  = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_alerts  = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        critical      = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical'").fetchone()[0]
        high          = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='high'").fetchone()[0]
        unacked       = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
        machines      = conn.execute("SELECT COUNT(DISTINCT machine) FROM events").fetchone()[0]
        tactics       = conn.execute(
            "SELECT tactic, COUNT(*) as cnt FROM alerts GROUP BY tactic ORDER BY cnt DESC"
        ).fetchall()
        top_techniques = conn.execute(
            "SELECT technique, technique_id, COUNT(*) as cnt FROM alerts GROUP BY technique ORDER BY cnt DESC LIMIT 5"
        ).fetchall()

    return {
        "total_events":    total_events,
        "total_alerts":    total_alerts,
        "critical":        critical,
        "high":            high,
        "unacknowledged":  unacked,
        "machines":        machines,
        "tactics":         [dict(r) for r in tactics],
        "top_techniques":  [dict(r) for r in top_techniques],
    }
