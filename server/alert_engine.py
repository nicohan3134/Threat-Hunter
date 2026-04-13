"""
Alert engine — runs detection rules against incoming events.
Each rule returns an alert dict or None.
"""
import time
import collections
from mitre_mapper import get_technique

# Track recent events per machine for correlation rules
_failed_logins = collections.defaultdict(list)   # machine -> [timestamps]


def process_events(machine, events):
    """Run all rules against a batch of events. Returns list of alert dicts."""
    alerts = []
    for event in events:
        eid = event.get("event_id")
        technique = get_technique(eid)
        if not technique:
            continue

        # Single-event alerts
        alert = _single_event_alert(machine, event, technique)
        if alert:
            alerts.append(alert)

    # Correlation alerts (need full batch context)
    alerts += _brute_force_check(machine, events)

    return alerts


def _make_alert(machine, event, technique, description=None, details=None):
    return {
        "machine":      machine,
        "event_id":     event["event_id"],
        "technique_id": technique["technique_id"],
        "technique":    technique["technique"],
        "tactic":       technique["tactic"],
        "severity":     technique["severity"],
        "description":  description or technique.get("description", ""),
        "details":      details or {"strings": event.get("strings", [])},
        "time":         event["time"],
        "timestamp":    event["timestamp"],
    }


def _single_event_alert(machine, event, technique):
    eid = event["event_id"]
    strings = event.get("strings", [])

    # Always alert on these high-signal events
    HIGH_SIGNAL = {1102, 4698, 4720, 4728, 4732, 4740, 4756, 7045, 4946}
    if eid in HIGH_SIGNAL:
        details = _extract_details(eid, strings)
        return _make_alert(machine, event, technique, details=details)

    return None


def _brute_force_check(machine, events):
    """Alert if 5+ failed logins within a 5-minute window."""
    alerts = []
    window = 300  # seconds

    for event in events:
        if event["event_id"] == 4625:
            _failed_logins[machine].append(event["timestamp"])

    # Prune old entries
    now = time.time()
    _failed_logins[machine] = [
        t for t in _failed_logins[machine] if now - t < window
    ]

    count = len(_failed_logins[machine])
    if count >= 5:
        technique = get_technique(4625)
        # Build a synthetic event for the alert
        synthetic = {
            "event_id":  4625,
            "time":      events[-1]["time"] if events else "",
            "timestamp": events[-1]["timestamp"] if events else now,
            "strings":   [],
        }
        alerts.append(_make_alert(
            machine, synthetic, technique,
            description=f"Brute force detected: {count} failed logins in 5 minutes",
            details={"failed_count": count, "window_seconds": window}
        ))
        # Reset so we don't spam alerts
        _failed_logins[machine] = []

    return alerts


def _extract_details(event_id, strings):
    """Pull meaningful fields out of StringInserts for common event IDs."""
    s = strings  # shorthand

    if event_id == 4720 and len(s) >= 1:
        return {"new_account": s[0], "created_by": s[3] if len(s) > 3 else "unknown"}
    if event_id in (4728, 4732, 4756) and len(s) >= 3:
        return {"group": s[0], "member_added": s[2]}
    if event_id == 4698 and len(s) >= 4:
        return {"task_name": s[2], "task_content": s[4] if len(s) > 4 else ""}
    if event_id == 7045 and len(s) >= 2:
        return {"service_name": s[0], "service_path": s[1]}
    if event_id == 4740 and len(s) >= 1:
        return {"locked_account": s[0]}
    if event_id == 1102:
        return {"note": "Security audit log was cleared — possible cover-up"}
    if event_id == 4946 and len(s) >= 1:
        return {"rule_name": s[0]}

    return {"strings": strings}
