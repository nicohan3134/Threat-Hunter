import os
import json
from flask import Flask, request, jsonify, render_template, abort

import db
import alert_engine

app = Flask(__name__)
db.init_db()

# Optional API key auth — set INGEST_API_KEY env var to require it
API_KEY = os.environ.get("INGEST_API_KEY", "")


def _check_api_key():
    if not API_KEY:
        return
    key = request.headers.get("X-API-Key", "")
    if key != API_KEY:
        abort(401, "Invalid API key")


# ── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ── Ingest (agent → server) ──────────────────────────────────────────────────

@app.route("/api/ingest", methods=["POST"])
def ingest():
    _check_api_key()
    data = request.get_json(force=True)

    machine = data.get("machine", "unknown")
    events  = data.get("events", [])

    if not events:
        return jsonify({"status": "ok", "processed": 0})

    # Tag each event with the machine name
    for e in events:
        e["machine"] = machine

    db.insert_events(events)

    alerts = alert_engine.process_events(machine, events)
    for alert in alerts:
        db.insert_alert(alert)

    return jsonify({"status": "ok", "processed": len(events), "alerts": len(alerts)})


# ── Read APIs (dashboard → server) ──────────────────────────────────────────

@app.route("/api/events")
def get_events():
    limit = min(int(request.args.get("limit", 200)), 1000)
    return jsonify(db.get_recent_events(limit))


@app.route("/api/alerts")
def get_alerts():
    limit     = min(int(request.args.get("limit", 200)), 1000)
    unacked   = request.args.get("unacked", "false").lower() == "true"
    return jsonify(db.get_alerts(limit, unacked))


@app.route("/api/stats")
def get_stats():
    return jsonify(db.get_stats())


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def acknowledge(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({"status": "ok"})


# ── Health check ─────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ── Manual alert scan (re-runs detection against all stored events) ───────────

@app.route("/api/scan", methods=["POST"])
def scan():
    import time
    window = 300
    now = time.time()
    since = now - window

    machines = db.get_conn().execute(
        "SELECT DISTINCT machine FROM events"
    ).fetchall()

    total_alerts = 0
    for row in machines:
        machine = row["machine"]
        count = db.count_recent_events(machine, 4625, since)
        if count >= 5:
            from mitre_mapper import get_technique
            technique = get_technique(4625)
            alert = {
                "machine":      machine,
                "event_id":     4625,
                "technique_id": technique["technique_id"],
                "technique":    technique["technique"],
                "tactic":       technique["tactic"],
                "severity":     technique["severity"],
                "description":  f"Brute force detected: {count} failed logins in 5 minutes",
                "details":      {"failed_count": count, "window_seconds": window},
                "time":         db.get_conn().execute(
                    "SELECT time FROM events WHERE machine=? AND event_id=4625 ORDER BY timestamp DESC LIMIT 1",
                    (machine,)
                ).fetchone()["time"],
                "timestamp":    now,
            }
            db.insert_alert(alert)
            total_alerts += 1

    return jsonify({"status": "ok", "alerts_created": total_alerts})


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    db.init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
