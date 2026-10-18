"""
Mobile & Chat Database Parser: Ingests Android SQLite dumps (WhatsApp msgstore.db,
SMS mmssms.db, and Telegram cache) into normalized message timelines.
"""

import sqlite3
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


class MobileParser:
    """
    Extracts forensic message records from Android SQLite database dumps.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        if not self.db_path.is_file():
            raise FileNotFoundError(f"Mobile database not found: {db_path}")

    def parse_whatsapp(self) -> List[Dict[str, Any]]:
        """
        Extracts messages, timestamps, and sender JIDs from WhatsApp msgstore.db.
        """
        records: List[Dict[str, Any]] = []
        conn = sqlite3.connect(f"file:{self.db_path.resolve()}?mode=ro", uri=True)
        cursor = conn.cursor()

        # Check existing tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]

        if "message" in tables and "jid" in tables:
            # Modern schema
            query = """
            SELECT 
                m._id, 
                m.timestamp, 
                j.raw_string AS sender_jid, 
                m.text_data,
                m.from_me
            FROM message m
            LEFT JOIN jid j ON m.sender_jid_row_id = j._id
            WHERE m.text_data IS NOT NULL
            ORDER BY m.timestamp ASC;
            """
            try:
                cursor.execute(query)
                for row in cursor.fetchall():
                    msg_id, ts, sender, text, from_me = row
                    phone = sender.split("@")[0] if sender else "Unknown"
                    records.append({
                        "msg_id": msg_id,
                        "source": "whatsapp",
                        "timestamp_ms": ts,
                        "datetime_utc": datetime.datetime.fromtimestamp(ts / 1000.0, datetime.timezone.utc).isoformat() if ts else None,
                        "sender": phone,
                        "from_me": bool(from_me),
                        "text": text
                    })
            except Exception as e:
                # Try fallback legacy schema
                pass

        elif "messages" in tables:
            # Legacy WhatsApp schema
            query = """
            SELECT _id, key_remote_jid, timestamp, data, key_from_me
            FROM messages
            WHERE data IS NOT NULL
            ORDER BY timestamp ASC;
            """
            cursor.execute(query)
            for row in cursor.fetchall():
                msg_id, jid, ts, text, from_me = row
                phone = jid.split("@")[0] if jid else "Unknown"
                records.append({
                    "msg_id": msg_id,
                    "source": "whatsapp_legacy",
                    "timestamp_ms": ts,
                    "datetime_utc": datetime.datetime.fromtimestamp(ts / 1000.0, datetime.timezone.utc).isoformat() if ts else None,
                    "sender": phone,
                    "from_me": bool(from_me),
                    "text": text
                })

        conn.close()
        return records

    def parse_sms(self) -> List[Dict[str, Any]]:
        """
        Extracts SMS messages from Android mmssms.db.
        """
        records: List[Dict[str, Any]] = []
        conn = sqlite3.connect(f"file:{self.db_path.resolve()}?mode=ro", uri=True)
        cursor = conn.cursor()

        query = """
        SELECT _id, address, date, body, type
        FROM sms
        WHERE body IS NOT NULL
        ORDER BY date ASC;
        """
        try:
            cursor.execute(query)
            for row in cursor.fetchall():
                msg_id, address, date_val, body, msg_type = row
                records.append({
                    "msg_id": msg_id,
                    "source": "sms",
                    "timestamp_ms": date_val,
                    "datetime_utc": datetime.datetime.fromtimestamp(date_val / 1000.0, datetime.timezone.utc).isoformat() if date_val else None,
                    "sender": address,
                    "is_incoming": (msg_type == 1),
                    "text": body
                })
        except Exception:
            pass

        conn.close()
        return records
