"""Append-only JSONL audit ledger with a legacy-prefix checkpoint and SHA-256 chain."""

import datetime
import fcntl
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

from sutra_net.config import AUDIT_LEDGER_PATH


def _canonical_hash(record: dict[str, Any]) -> str:
    """Hash a record deterministically, excluding its own entry_hash field."""
    payload = {key: value for key, value in record.items() if key != "entry_hash"}
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _parse_lines(raw: bytes) -> tuple[list[bytes], list[tuple[int, dict[str, Any]]]]:
    lines = raw.splitlines(keepends=True)
    records: list[tuple[int, dict[str, Any]]] = []

    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            record = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Malformed JSONL record at line {index + 1}: {exc}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"Ledger line {index + 1} is not a JSON object")
        records.append((index, record))

    return lines, records


def _verify_bytes(raw: bytes) -> dict[str, Any]:
    """Verify the ledger without modifying it."""
    try:
        lines, records = _parse_lines(raw)
    except ValueError as exc:
        return {
            "valid": False,
            "checkpointed": False,
            "legacy_record_count": 0,
            "chained_record_count": 0,
            "last_hash": None,
            "errors": [str(exc)],
        }

    checkpoint_position = next(
        (
            position
            for position, (_, record) in enumerate(records)
            if record.get("_ledger_record_type") == "checkpoint"
        ),
        None,
    )

    if checkpoint_position is None:
        if any("entry_hash" in record or "previous_hash" in record for _, record in records):
            errors = ["Hash-chain fields exist but no ledger checkpoint was found."]
            valid = False
        else:
            errors = []
            valid = True
        return {
            "valid": valid,
            "checkpointed": False,
            "legacy_record_count": len(records),
            "chained_record_count": 0,
            "last_hash": None,
            "errors": errors,
        }

    checkpoint_line_index, checkpoint = records[checkpoint_position]
    prefix_length = checkpoint.get("legacy_prefix_bytes")

    if (
        isinstance(prefix_length, int)
        and not isinstance(prefix_length, bool)
        and 0 <= prefix_length <= len(raw)
    ):
        prefix = raw[:prefix_length]
    else:
        # Backward compatibility with checkpoints created by the older format.
        prefix = b"".join(lines[:checkpoint_line_index])

    legacy_records = records[:checkpoint_position]
    chained_records = records[checkpoint_position + 1:]
    errors: list[str] = []

    if checkpoint.get("legacy_record_count") != len(legacy_records):
        errors.append("Legacy record count does not match the checkpoint.")

    expected_prefix_hash = hashlib.sha256(prefix).hexdigest()
    if checkpoint.get("legacy_prefix_sha256") != expected_prefix_hash:
        errors.append("Legacy prefix SHA-256 does not match the checkpoint.")

    if checkpoint.get("previous_hash") is not None:
        errors.append("Checkpoint previous_hash must be null.")

    checkpoint_hash = checkpoint.get("entry_hash")
    if not isinstance(checkpoint_hash, str) or checkpoint_hash != _canonical_hash(checkpoint):
        errors.append("Checkpoint entry_hash is missing or invalid.")

    expected_previous = checkpoint_hash if isinstance(checkpoint_hash, str) else None

    for line_index, record in chained_records:
        line_number = line_index + 1

        if record.get("_ledger_record_type") == "checkpoint":
            errors.append(f"Unexpected additional checkpoint at line {line_number}.")
            continue

        if record.get("previous_hash") != expected_previous:
            errors.append(f"Broken previous_hash link at line {line_number}.")

        actual_hash = record.get("entry_hash")
        if not isinstance(actual_hash, str) or actual_hash != _canonical_hash(record):
            errors.append(f"Invalid entry_hash at line {line_number}.")

        expected_previous = actual_hash if isinstance(actual_hash, str) else None

    return {
        "valid": not errors,
        "checkpointed": True,
        "legacy_record_count": len(legacy_records),
        "chained_record_count": len(chained_records),
        "last_hash": expected_previous,
        "errors": errors,
    }


class ForensicAuditLedger:
    """Append-only ledger for acquisitions and examiner actions."""

    def __init__(self, ledger_path: Path = AUDIT_LEDGER_PATH):
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)

    def verify_integrity(self) -> dict[str, Any]:
        """Read-only verification of legacy prefix, checkpoint and hash chain."""
        if not self.ledger_path.exists():
            return {
                "valid": True,
                "checkpointed": False,
                "legacy_record_count": 0,
                "chained_record_count": 0,
                "last_hash": None,
                "errors": [],
            }

        with self.ledger_path.open("rb") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            try:
                return _verify_bytes(stream.read())
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def append_record(self, record: dict[str, Any]) -> dict[str, Any]:
        """Append a record and checkpoint exact legacy bytes."""
        if not isinstance(record, dict):
            raise TypeError("Ledger record must be a dictionary")
        if record.get("_ledger_record_type") == "checkpoint":
            raise ValueError("Checkpoint records are managed internally")

        new_record = dict(record)
        new_record.pop("entry_hash", None)
        new_record.pop("previous_hash", None)
        json.dumps(new_record, ensure_ascii=False)

        with self.ledger_path.open("a+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                stream.seek(0)
                raw = stream.read()
                status = _verify_bytes(raw)
                if not status["valid"]:
                    raise ValueError(
                        "Refusing to append to an invalid audit ledger: "
                        + "; ".join(status["errors"])
                    )

                stream.seek(0, 2)
                if not status["checkpointed"]:
                    checkpoint = {
                        "_ledger_record_type": "checkpoint",
                        "ledger_version": 1,
                        "timestamp_utc": datetime.datetime.now(
                            datetime.timezone.utc
                        ).isoformat(),
                        "legacy_record_count": status["legacy_record_count"],
                        "legacy_prefix_bytes": len(raw),
                        "legacy_prefix_sha256": hashlib.sha256(raw).hexdigest(),
                        "previous_hash": None,
                    }
                    checkpoint["entry_hash"] = _canonical_hash(checkpoint)

                    if raw and not raw.endswith(b"\n"):
                        stream.write(b"\n")

                    stream.write(
                        (json.dumps(checkpoint, ensure_ascii=False) + "\n").encode("utf-8")
                    )
                    stream.flush()
                    os.fsync(stream.fileno())
                    previous_hash = checkpoint["entry_hash"]
                else:
                    previous_hash = status["last_hash"]

                new_record["previous_hash"] = previous_hash
                new_record["entry_hash"] = _canonical_hash(new_record)
                stream.write(
                    (json.dumps(new_record, ensure_ascii=False) + "\n").encode("utf-8")
                )
                stream.flush()
                os.fsync(stream.fileno())
                return new_record
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def record_action(
        self,
        action_type: str,
        user_name: str,
        details: dict[str, Any],
        case_id: str = "CASE-2026-SUTRAM",
    ) -> dict[str, Any]:
        record = {
            "entry_id": str(uuid.uuid4()),
            "case_id": case_id,
            "action_type": action_type,
            "examiner": user_name,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "details": details,
        }
        return self.append_record(record)

    def get_case_history(
        self, case_id: str = "CASE-2026-SUTRAM"
    ) -> list[dict[str, Any]]:
        """Read verified case history under a single shared file lock."""
        if not self.ledger_path.exists():
            return []

        with self.ledger_path.open("rb") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            try:
                raw = stream.read()
                status = _verify_bytes(raw)

                if not status["valid"]:
                    raise ValueError(
                        "Audit ledger integrity check failed: "
                        + "; ".join(status["errors"])
                    )

                entries: list[dict[str, Any]] = []

                for line in raw.splitlines():
                    if not line.strip():
                        continue

                    record = json.loads(line.decode("utf-8"))

                    if record.get("_ledger_record_type") == "checkpoint":
                        continue

                    if record.get("case_id") == case_id:
                        entries.append(record)

                return entries

            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
