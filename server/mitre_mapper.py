MITRE_MAP = {
    # Credential Access
    4625: {"technique_id": "T1110",     "technique": "Brute Force",                       "tactic": "Credential Access",    "severity": "medium"},
    4776: {"technique_id": "T1110",     "technique": "Brute Force",                       "tactic": "Credential Access",    "severity": "medium"},
    4740: {"technique_id": "T1110",     "technique": "Brute Force",                       "tactic": "Credential Access",    "severity": "high"},
    4648: {"technique_id": "T1550",     "technique": "Use Alternate Auth Material",        "tactic": "Lateral Movement",     "severity": "medium"},
    # Persistence
    4698: {"technique_id": "T1053.005", "technique": "Scheduled Task",                    "tactic": "Persistence",          "severity": "high"},
    4702: {"technique_id": "T1053.005", "technique": "Scheduled Task Modified",           "tactic": "Persistence",          "severity": "medium"},
    4720: {"technique_id": "T1136.001", "technique": "Create Local Account",              "tactic": "Persistence",          "severity": "high"},
    7045: {"technique_id": "T1543.003", "technique": "Windows Service",                   "tactic": "Persistence",          "severity": "high"},
    # Privilege Escalation
    4728: {"technique_id": "T1098",     "technique": "Account Manipulation",              "tactic": "Privilege Escalation", "severity": "high"},
    4732: {"technique_id": "T1098",     "technique": "Account Manipulation",              "tactic": "Privilege Escalation", "severity": "high"},
    4756: {"technique_id": "T1098",     "technique": "Account Manipulation",              "tactic": "Privilege Escalation", "severity": "high"},
    4724: {"technique_id": "T1098",     "technique": "Account Manipulation",              "tactic": "Privilege Escalation", "severity": "medium"},
    # Defense Evasion
    1102: {"technique_id": "T1070.001", "technique": "Clear Windows Event Logs",          "tactic": "Defense Evasion",      "severity": "critical"},
    4657: {"technique_id": "T1112",     "technique": "Modify Registry",                   "tactic": "Defense Evasion",      "severity": "medium"},
    4946: {"technique_id": "T1562.004", "technique": "Disable or Modify Firewall",        "tactic": "Defense Evasion",      "severity": "high"},
    4947: {"technique_id": "T1562.004", "technique": "Disable or Modify Firewall",        "tactic": "Defense Evasion",      "severity": "medium"},
    # Execution
    4688: {"technique_id": "T1059",     "technique": "Command and Scripting Interpreter", "tactic": "Execution",            "severity": "low"},
    # Impact
    4726: {"technique_id": "T1531",     "technique": "Account Access Removal",            "tactic": "Impact",               "severity": "medium"},
    # Initial Access
    4624: {"technique_id": "T1078",     "technique": "Valid Accounts",                    "tactic": "Initial Access",       "severity": "low"},
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

def get_technique(event_id):
    return MITRE_MAP.get(int(event_id))
