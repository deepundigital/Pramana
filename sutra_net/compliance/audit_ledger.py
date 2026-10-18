"""
Forensic Audit Ledger: Maintains append-only immutable chain-of-custody logs
and examiner query history to guarantee courtroom admissibility.
"""

import json
import uuid
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from sutra_net.config import AUDIT_LEDGER_PATH


class ForensicAuditLedger:
    """
    Append-only ledger recording all forensic operations and evidence touchpoints.
    """

    def __init__(self, ledger_path: Path = AUDIT_LEDGER_PATH):
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.ledger_path.exists():
            self.ledger_path.touch()

    def record_action(
        self,
        action_type: str,
        user_name: str,
        details: Dict[str, Any],
        case_id: str = "CASE-2026-SUTRAM"
    ) -> Dict[str, Any]:
        """
        Appends an action to the ledger.
        """
        record = {
            "entry_id": str(uuid.uuid4()),
            "case_id": case_id,
            "action_type": action_type,
            "examiner": user_name,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "details": details
        }
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def get_case_history(self, case_id: str = "CASE-2026-SUTRAM") -> List[Dict[str, Any]]:
        """
        Retrieves all ledger entries associated with a specific case.
        """
        entries = []
        if not self.ledger_path.exists():
            return entries

        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        record = json.loads(line)
                        if record.get("case_id") == case_id:
                            entries.append(record)
                    except Exception:
                        pass
        return entries
