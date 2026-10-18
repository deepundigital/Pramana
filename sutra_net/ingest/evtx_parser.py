"""
System & Event Log Parser: Normalizes Windows Security Event Logs (.evtx representation)
and Linux Syslogs into unified timeline records.
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import datetime


class LogParser:
    """
    Parses Windows Event logs (JSON/EVTX representations) and standard Linux Syslogs.
    """

    WINDOWS_EVENT_DESCRIPTIONS = {
        4624: "Successful Logon",
        4625: "Failed Logon Attempt (Brute-Force Indicator)",
        4688: "New Process Created",
        4720: "User Account Created",
        7045: "New Service Installed (Persistence Indicator)",
        1102: "Audit Log Cleared (Tampering Indicator)",
        4104: "PowerShell Script Block Execution"
    }

    @staticmethod
    def parse_syslog(file_path: str | Path) -> List[Dict[str, Any]]:
        """
        Parses standard Linux syslog lines.
        Example: Oct 19 01:05:22 server sshd[1234]: Failed password for root from 192.168.1.50 port 44322 ssh2
        """
        path = Path(file_path)
        records: List[Dict[str, Any]] = []

        syslog_regex = re.compile(
            r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w\.\-]+)\s+([\w\.\-]+)(?:\[(\d+)\])?:\s+(.*)$'
        )

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue

                m = syslog_regex.match(line)
                if m:
                    timestamp_str, hostname, process, pid, message = m.groups()
                    # Extract any IPv4 addresses in message
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', message)
                    extracted_ip = ip_match.group(0) if ip_match else None

                    # Check for failed authentication
                    is_suspicious = bool(re.search(r'(failed|invalid|unauthorized|denied|exploit|error)', message, re.I))

                    records.append({
                        "event_index": idx,
                        "artifact_type": "linux_syslog",
                        "timestamp_raw": timestamp_str,
                        "hostname": hostname,
                        "process": process,
                        "pid": int(pid) if pid else None,
                        "message": message,
                        "extracted_ip": extracted_ip,
                        "is_suspicious": is_suspicious
                    })
                else:
                    records.append({
                        "event_index": idx,
                        "artifact_type": "generic_log",
                        "raw_line": line
                    })

        return records

    @staticmethod
    def parse_windows_events(json_or_log_path: str | Path) -> List[Dict[str, Any]]:
        """
        Parses structured Windows Event log extracts (JSON format or lines).
        """
        path = Path(json_or_log_path)
        records: List[Dict[str, Any]] = []

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    event_id = int(obj.get("event_id", 0))
                    obj["description"] = LogParser.WINDOWS_EVENT_DESCRIPTIONS.get(event_id, "Generic Event")
                    obj["artifact_type"] = "windows_event"
                    records.append(obj)
                except Exception:
                    # Treat as plaintext log
                    records.append({
                        "event_index": idx,
                        "artifact_type": "raw_event",
                        "raw_text": line
                    })

        return records
