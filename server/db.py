import os
import json
try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    from psycopg2cffi import compat
    compat.register()
    import psycopg2
    import psycopg2.extras

DATABASE_URL = os.environ.get("DATABASE_URL", "")


def get_conn():
    conn = psycopg2.connect(DATABASE_URL)
    return conn


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id         SERIAL PRIMARY KEY,
                    machine    TEXT,
                    event_id   INTEGER,
                    log        TEXT,
                    time       TEXT,
                    timestamp  REAL,
                    source     TEXT,
                    strings    TEXT,
                    created_at REAL DEFAULT EXTRACT(EPOCH FROM NOW())
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id           SERIAL PRIMARY KEY,
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

                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_machine   ON events(machine);
            """)
        conn.commit()


def insert_events(events):
    with get_conn() as conn:
        with conn.cursor() as cur:
            psycopg2.extras.execute_batch(cur, """
                INSERT INTO events (machine, event_id, log, time, timestamp, source, strings)
                VALUES (%(machine)s, %(event_id)s, %(log)s, %(time)s, %(timestamp)s, %(source)s, %(strings)s)
            """, [
                {**e, "strings": json.dumps(e.get("strings", []))}
                for e in events
            ])
        conn.commit()


def insert_alert(alert):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts
                (machine, event_id, technique_id, technique, tactic, severity,
                 description, details, time, timestamp)
                VALUES (%(machine)s, %(event_id)s, %(technique_id)s, %(technique)s, %(tactic)s,
                        %(severity)s, %(description)s, %(details)s, %(time)s, %(timestamp)s)
            """, {**alert, "details": json.dumps(alert.get("details", {}))})
        conn.commit()


def get_recent_events(limit=200):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]


def get_alerts(limit=200, unacked_only=False):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if unacked_only:
                cur.execute(
                    "SELECT * FROM alerts WHERE acknowledged=0 ORDER BY timestamp DESC LIMIT %s",
                    (limit,)
                )
            else:
                cur.execute(
                    "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT %s",
                    (limit,)
                )
            return [dict(r) for r in cur.fetchall()]


def acknowledge_alert(alert_id):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE alerts SET acknowledged=1 WHERE id=%s", (alert_id,))
        conn.commit()


def count_recent_events(machine, event_id, since_timestamp):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM events WHERE machine=%s AND event_id=%s AND timestamp>=%s",
                (machine, event_id, since_timestamp)
            )
            return cur.fetchone()[0]


def get_stats():
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) as c FROM events")
            total_events = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM alerts")
            total_alerts = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM alerts WHERE severity='critical'")
            critical = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM alerts WHERE severity='high'")
            high = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM alerts WHERE acknowledged=0")
            unacked = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(DISTINCT machine) as c FROM events")
            machines = cur.fetchone()["c"]

            cur.execute("SELECT tactic, COUNT(*) as cnt FROM alerts GROUP BY tactic ORDER BY cnt DESC")
            tactics = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT technique, technique_id, COUNT(*) as cnt FROM alerts GROUP BY technique, technique_id ORDER BY cnt DESC LIMIT 5")
            top_techniques = [dict(r) for r in cur.fetchall()]

    return {
        "total_events":   total_events,
        "total_alerts":   total_alerts,
        "critical":       critical,
        "high":           high,
        "unacknowledged": unacked,
        "machines":       machines,
        "tactics":        tactics,
        "top_techniques": top_techniques,
    }
