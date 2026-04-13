# Maps Windows Event IDs to MITRE ATT&CK techniques
# Reference: https://attack.mitre.org

MITRE_MAP = {
    # ── Credential Access ──────────────────────────────────────────────────
    4625: {
        "technique_id": "T1110",
        "technique":    "Brute Force",
        "tactic":       "Credential Access",
        "severity":     "medium",
        "description":  "Failed logon attempt"
    },
    4776: {
        "technique_id": "T1110",
        "technique":    "Brute Force",
        "tactic":       "Credential Access",
        "severity":     "medium",
        "description":  "Credential validation attempt"
    },
    4648: {
        "technique_id": "T1550",
        "technique":    "Use Alternate Auth Material",
        "tactic":       "Lateral Movement",
        "severity":     "medium",
        "description":  "Logon using explicit credentials"
    },

    # ── Persistence ────────────────────────────────────────────────────────
    4698: {
        "technique_id": "T1053.005",
        "technique":    "Scheduled Task",
        "tactic":       "Persistence",
        "severity":     "high",
        "description":  "Scheduled task was created"
    },
    4702: {
        "technique_id": "T1053.005",
        "technique":    "Scheduled Task",
        "tactic":       "Persistence",
        "severity":     "medium",
        "description":  "Scheduled task was updated"
    },
    7045: {
        "technique_id": "T1543.003",
        "technique":    "Windows Service",
        "tactic":       "Persistence",
        "severity":     "high",
        "description":  "New service installed on system"
    },
    4720: {
        "technique_id": "T1136.001",
        "technique":    "Create Local Account",
        "tactic":       "Persistence",
        "severity":     "high",
        "description":  "New user account was created"
    },

    # ── Privilege Escalation ───────────────────────────────────────────────
    4728: {
        "technique_id": "T1098",
        "technique":    "Account Manipulation",
        "tactic":       "Privilege Escalation",
        "severity":     "high",
        "description":  "Member added to security-enabled global group"
    },
    4732: {
        "technique_id": "T1098",
        "technique":    "Account Manipulation",
        "tactic":       "Privilege Escalation",
        "severity":     "high",
        "description":  "Member added to security-enabled local group"
    },
    4756: {
        "technique_id": "T1098",
        "technique":    "Account Manipulation",
        "tactic":       "Privilege Escalation",
        "severity":     "high",
        "description":  "Member added to security-enabled universal group"
    },
    4724: {
        "technique_id": "T1098",
        "technique":    "Account Manipulation",
        "tactic":       "Privilege Escalation",
        "severity":     "medium",
        "description":  "Password reset attempt"
    },

    # ── Defense Evasion ────────────────────────────────────────────────────
    1102: {
        "technique_id": "T1070.001",
        "technique":    "Clear Windows Event Logs",
        "tactic":       "Defense Evasion",
        "severity":     "critical",
        "description":  "Audit log was cleared"
    },
    4657: {
        "technique_id": "T1112",
        "technique":    "Modify Registry",
        "tactic":       "Defense Evasion",
        "severity":     "medium",
        "description":  "Registry value was modified"
    },
    4946: {
        "technique_id": "T1562.004",
        "technique":    "Disable or Modify System Firewall",
        "tactic":       "Defense Evasion",
        "severity":     "high",
        "description":  "Windows Firewall exception added"
    },
    4947: {
        "technique_id": "T1562.004",
        "technique":    "Disable or Modify System Firewall",
        "tactic":       "Defense Evasion",
        "severity":     "medium",
        "description":  "Windows Firewall exception modified"
    },

    # ── Execution ──────────────────────────────────────────────────────────
    4688: {
        "technique_id": "T1059",
        "technique":    "Command and Scripting Interpreter",
        "tactic":       "Execution",
        "severity":     "low",
        "description":  "New process was created"
    },

    # ── Impact ─────────────────────────────────────────────────────────────
    4726: {
        "technique_id": "T1531",
        "technique":    "Account Access Removal",
        "tactic":       "Impact",
        "severity":     "medium",
        "description":  "User account was deleted"
    },

    # ── Initial Access ─────────────────────────────────────────────────────
    4624: {
        "technique_id": "T1078",
        "technique":    "Valid Accounts",
        "tactic":       "Initial Access",
        "severity":     "low",
        "description":  "Successful logon"
    },
    4740: {
        "technique_id": "T1110",
        "technique":    "Brute Force",
        "tactic":       "Credential Access",
        "severity":     "high",
        "description":  "User account was locked out"
    },
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

def get_technique(event_id):
    return MITRE_MAP.get(event_id)

def get_all_techniques():
    return MITRE_MAP
