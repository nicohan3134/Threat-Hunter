"""
Threat Hunter Agent
───────────────────
Reads Windows Event Logs and ships them to the Threat Hunter server.

Usage:
    python agent.py --server https://your-server-url --key YOUR_API_KEY

Run as Administrator for access to the Security log.
"""
import argparse
import datetime
import json
import os
import socket
import sys
import time

try:
    import requests
except ImportError:
    print("[!] Missing dependency: pip install requests")
    sys.exit(1)

try:
    import win32evtlog
    HAS_WIN32 = True
except ImportError:
    print("[!] pywin32 not found. Install with: pip install pywin32")
    print("    Agent will run in demo mode with simulated events.")
    HAS_WIN32 = False

# ── Config ───────────────────────────────────────────────────────────────────

WATCHED_IDS = {
    4624, 4625, 4648, 4657, 4688, 4698, 4702,
    4720, 4724, 4726, 4728, 4732, 4740, 4756,
    4776, 4946, 4947, 1102, 7045
}

LOGS_TO_MONITOR = ["Security", "System", "Application"]
POLL_INTERVAL   = 60   # seconds between polls
BATCH_SIZE      = 500  # max events per request

# ── Helpers ──────────────────────────────────────────────────────────────────

def _pytime_to_dt(pytime):
    try:
        return datetime.datetime(
            pytime.year, pytime.month, pytime.day,
            pytime.hour, pytime.minute, pytime.second
        )
    except Exception:
        return datetime.datetime.now()


def read_events_since(log_name, since_timestamp):
    """Return events from log_name newer than since_timestamp."""
    if not HAS_WIN32:
        return []

    events = []
    try:
        handle = win32evtlog.OpenEventLog(None, log_name)
        flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                  win32evtlog.EVENTLOG_SEQUENTIAL_READ)

        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break
            for rec in records:
                dt = _pytime_to_dt(rec.TimeGenerated)
                ts = dt.timestamp()

                # Stop reading once we hit events older than our watermark
                if ts <= since_timestamp:
                    win32evtlog.CloseEventLog(handle)
                    return events

                event_id = rec.EventID & 0xFFFF
                if log_name == "Security" and event_id not in WATCHED_IDS:
                    continue

                strings = list(rec.StringInserts) if rec.StringInserts else []
                events.append({
                    "event_id":  event_id,
                    "log":       log_name,
                    "time":      dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "timestamp": ts,
                    "source":    rec.SourceName,
                    "strings":   strings,
                })

        win32evtlog.CloseEventLog(handle)
    except PermissionError:
        print(f"[!] Permission denied reading {log_name} log — run as Administrator")
    except Exception as e:
        print(f"[!] Error reading {log_name}: {e}")

    return events


def ship_events(server_url, api_key, machine, events):
    """Send a batch of events to the server."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    payload = {"machine": machine, "events": events}

    try:
        resp = requests.post(
            f"{server_url}/api/ingest",
            json=payload,
            headers=headers,
            timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        print(f"[+] Shipped {data['processed']} events, {data['alerts']} alerts triggered")
        return True
    except requests.exceptions.ConnectionError:
        print(f"[!] Cannot connect to server at {server_url}")
    except requests.exceptions.HTTPError as e:
        print(f"[!] Server returned error: {e}")
    except Exception as e:
        print(f"[!] Failed to ship events: {e}")

    return False


# ── Demo mode ────────────────────────────────────────────────────────────────

def generate_demo_events():
    """Return a small set of sample events when pywin32 isn't available."""
    import random
    now = datetime.datetime.now()
    samples = [
        (4625, "Security", "Microsoft-Windows-Security-Auditing",
         ["S-1-0-0","0x0","Administrator","WORKSTATION","3","NTLM","","192.168.1.105"]),
        (4625, "Security", "Microsoft-Windows-Security-Auditing",
         ["S-1-0-0","0x0","admin","WORKSTATION","3","NTLM","","192.168.1.105"]),
        (4625, "Security", "Microsoft-Windows-Security-Auditing",
         ["S-1-0-0","0x0","root","WORKSTATION","3","NTLM","","192.168.1.105"]),
        (4720, "Security", "Microsoft-Windows-Security-Auditing",
         ["backdoor","S-1-5-21-999","Administrator","WORKSTATION"]),
        (4732, "Security", "Microsoft-Windows-Security-Auditing",
         ["Administrators","S-1-5-32-544","backdoor","WORKSTATION"]),
        (1102, "Security", "Microsoft-Windows-Security-Auditing",
         ["Administrator","WORKSTATION","S-1-5-21"]),
        (7045, "System",   "Service Control Manager",
         ["EvilSvc","C:\\Temp\\malware.exe","auto start","LocalSystem"]),
    ]
    events = []
    for eid, log, src, strings in samples:
        offset = datetime.timedelta(seconds=random.randint(0, 30))
        dt = now - offset
        events.append({
            "event_id": eid, "log": log,
            "time": dt.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": dt.timestamp(),
            "source": src, "strings": strings,
        })
    return events


# ── Main loop ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Threat Hunter Agent")
    parser.add_argument("--server", required=True, help="Server URL, e.g. https://your-app.railway.app")
    parser.add_argument("--key",    default="",    help="API key (if configured on server)")
    parser.add_argument("--once",   action="store_true", help="Run once and exit (useful for testing)")
    args = parser.parse_args()

    machine = socket.gethostname()
    server  = args.server.rstrip("/")
    api_key = args.key

    print(f"[*] Threat Hunter Agent starting")
    print(f"[*] Machine : {machine}")
    print(f"[*] Server  : {server}")
    print(f"[*] Mode    : {'demo (no pywin32)' if not HAS_WIN32 else 'live Windows Event Logs'}")
    print()

    # Watermark — only ship events newer than this
    since = time.time() - 3600  # start with last hour on first run

    while True:
        print(f"[*] Collecting events since {datetime.datetime.fromtimestamp(since).strftime('%H:%M:%S')} ...")

        if HAS_WIN32:
            all_events = []
            for log in LOGS_TO_MONITOR:
                all_events.extend(read_events_since(log, since))
        else:
            all_events = generate_demo_events()

        if all_events:
            print(f"[*] Collected {len(all_events)} events, shipping to server...")
            # Ship in batches
            for i in range(0, len(all_events), BATCH_SIZE):
                batch = all_events[i:i + BATCH_SIZE]
                ship_events(server, api_key, machine, batch)
        else:
            print("[*] No new events")

        # Advance watermark
        since = time.time()

        if args.once:
            break

        print(f"[*] Sleeping {POLL_INTERVAL}s ...\n")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
