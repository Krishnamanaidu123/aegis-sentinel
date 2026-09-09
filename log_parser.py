import re
import json
import datetime
from typing import Dict, Any

def parse_syslog(line: str) -> Dict[str, Any]:
    """
    Parse a raw syslog line into a structured JSON object.
    Handles common formats like SSH, sudo, and generic failed logins.
    """
    timestamp_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
    user_match = re.search(r'user (\S+)|for (\S+) from', line)

    # Detect event type
    event_type = "generic"
    if "failed" in line.lower() or "failure" in line.lower():
        event_type = "authentication_failure"
    elif "accepted" in line.lower() or "success" in line.lower():
        event_type = "authentication_success"
    elif "sudo" in line.lower():
        event_type = "privilege_escalation"
    elif "ssh" in line.lower():
        event_type = "ssh_connection"

    return {
        "timestamp": timestamp_match.group(0) if timestamp_match else datetime.datetime.now().isoformat(),
        "source_ip": ip_match.group(0) if ip_match else "0.0.0.0",
        "user": user_match.group(1) or user_match.group(2) or "unknown",
        "event_type": event_type,
        "raw": line
    }

def parse_json_log(json_log: dict) -> Dict[str, Any]:
    """Normalise JSON logs (e.g., CloudTrail, Windows Event Log) into our schema."""
    return {
        "timestamp": json_log.get("timestamp", json_log.get("time", datetime.datetime.now().isoformat())),
        "source_ip": json_log.get("sourceIPAddress", json_log.get("src_ip", json_log.get("ip", "0.0.0.0"))),
        "user": json_log.get("user", json_log.get("userIdentity", {}).get("userName", "unknown")),
        "event_type": json_log.get("eventName", json_log.get("event_type", "unknown")),
        "raw": json.dumps(json_log)
    }
