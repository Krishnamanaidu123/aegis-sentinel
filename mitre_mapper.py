import json
import os

MITRE_CACHE_FILE = "mitre_attack.json"

# Full MITRE ATT&CK mapping (Enterprise) - most common techniques included
FULL_MITRE_DATA = {
    "T1078": {"tactic": "Initial Access", "technique": "Valid Accounts"},
    "T1133": {"tactic": "Initial Access", "technique": "External Remote Services"},
    "T1190": {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application"},
    "T1059": {"tactic": "Execution", "technique": "Command and Scripting Interpreter"},
    "T1204": {"tactic": "Execution", "technique": "User Execution"},
    "T1003": {"tactic": "Credential Access", "technique": "OS Credential Dumping"},
    "T1021": {"tactic": "Lateral Movement", "technique": "Remote Services"},
    "T1040": {"tactic": "Discovery", "technique": "Network Sniffing"},
    "T1046": {"tactic": "Discovery", "technique": "Network Service Scanning"},
    "T1071": {"tactic": "Command and Control", "technique": "Application Layer Protocol"},
    "T1498": {"tactic": "Impact", "technique": "Network Denial of Service"},
    "T1566": {"tactic": "Initial Access", "technique": "Phishing"},
    "T1548": {"tactic": "Privilege Escalation", "technique": "Abuse Elevation Control Mechanism"},
    "T1110": {"tactic": "Credential Access", "technique": "Brute Force"},
    "T1005": {"tactic": "Collection", "technique": "Data from Local System"},
    "T1048": {"tactic": "Exfiltration", "technique": "Exfiltration Over Alternative Protocol"},
    "T1203": {"tactic": "Execution", "technique": "Exploitation for Client Execution"},
    "T1210": {"tactic": "Lateral Movement", "technique": "Exploitation of Remote Services"},
    "T1486": {"tactic": "Impact", "technique": "Data Encrypted for Impact"},
    "T1539": {"tactic": "Credential Access", "technique": "Steal Web Session Cookie"}
}

def load_mitre_data():
    """Load MITRE data from cache. If missing, create a full cache file."""
    if not os.path.exists(MITRE_CACHE_FILE):
        with open(MITRE_CACHE_FILE, "w") as f:
            json.dump(FULL_MITRE_DATA, f, indent=2)
        return FULL_MITRE_DATA

    try:
        with open(MITRE_CACHE_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        # If corrupted, re-create
        with open(MITRE_CACHE_FILE, "w") as f:
            json.dump(FULL_MITRE_DATA, f, indent=2)
        return FULL_MITRE_DATA

MITRE_DATA = load_mitre_data()

def get_technique_details(technique_id: str) -> dict:
    """Return tactic and technique name for a given MITRE ID."""
    tid = technique_id.upper()
    return MITRE_DATA.get(tid, {
        "tactic": "Unknown",
        "technique": "Unmapped Technique"
    })

def enrich_with_mitre(analysis: dict) -> dict:
    """Replace plain MITRE IDs with full details (ID + Tactic + Technique)."""
    enriched = []
    for tid in analysis.get("mitre_ids", []):
        details = get_technique_details(tid)
        enriched.append({
            "id": tid,
            "tactic": details["tactic"],
            "technique": details["technique"]
        })
    analysis["mitre_details"] = enriched
    return analysis
