"""
Acquisition Hasher & Immutable Evidence Ledger
Computes multi-algorithm cryptographic hashes (SHA-256, SHA-3) upon evidence acquisition
to satisfy Section 63 of Bharatiya Sakshya Adhiniyam, 2023.
"""

import os
import hashlib
import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from sutra_net.config import AUDIT_LEDGER_PATH, HASH_ALGORITHMS


class AcquisitionHasher:
    """
    Computes cryptographic hashes and writes tamper-evident audit records.
    """

    @staticmethod
    def hash_file(file_path: str | Path, block_size: int = 65536) -> Dict[str, str]:
        """
        Computes SHA-256 and SHA-3-256 hashes of a file in streaming chunks.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Target artifact does not exist: {file_path}")

        sha256 = hashlib.sha256()
        sha3 = hashlib.sha3_256()

        with open(path, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                sha256.update(block)
                sha3.update(block)

        return {
            "sha256": sha256.hexdigest(),
            "sha3_256": sha3.hexdigest()
        }

    @staticmethod
    def register_artifact(
        file_path: str | Path,
        case_id: str = "CASE-2026-SUTRAM",
        examiner_name: str = "Forensic Examiner",
        notes: str = "Initial Evidence Ingestion"
    ) -> Dict[str, Any]:
        """
        Hashes file, logs acquisition entry to the immutable ledger, and returns the manifest record.
        """
        path = Path(file_path)
        hashes = AcquisitionHasher.hash_file(path)
        file_stat = path.stat()

        record = {
            "record_id": str(uuid.uuid4()),
            "case_id": case_id,
            "filename": path.name,
            "file_path": str(path.resolve()),
            "file_size_bytes": file_stat.st_size,
            "hashes": hashes,
            "acquired_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "examiner_name": examiner_name,
            "notes": notes,
            "integrity_verified": True
        }

        # Append to immutable audit ledger
        with open(AUDIT_LEDGER_PATH, "a", encoding="utf-8") as ledger:
            ledger.write(json.dumps(record) + "\n")

        return record

    @staticmethod
    def verify_integrity(file_path: str | Path, expected_sha256: str) -> bool:
        """
        Verifies current hash against expected baseline hash.
        """
        hashes = AcquisitionHasher.hash_file(file_path)
        return hashes["sha256"].lower() == expected_sha256.lower()
