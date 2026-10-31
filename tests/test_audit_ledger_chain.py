import os
import json
import tempfile
import unittest
from pathlib import Path

from sutra_net.compliance.audit_ledger import ForensicAuditLedger
from sutra_net.ingest.hasher import AcquisitionHasher


class TestAuditLedgerChain(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.path = self.root / "audit_ledger.jsonl"

    def test_legacy_records_are_preserved_and_checkpointed(self):
        legacy = {
            "record_id": "legacy-1",
            "case_id": "CASE-1",
            "filename": "evidence.pcap",
        }
        original_line = (json.dumps(legacy) + "\n").encode("utf-8")
        self.path.write_bytes(original_line)

        ledger = ForensicAuditLedger(self.path)
        ledger.record_action("TEST_ACTION", "examiner", {}, "CASE-1")

        content = self.path.read_bytes()
        self.assertTrue(content.startswith(original_line))
        self.assertTrue(ledger.verify_integrity()["valid"])

        records = [
            json.loads(line)
            for line in content.decode("utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(records[0], legacy)
        self.assertEqual(records[1]["_ledger_record_type"], "checkpoint")
        self.assertEqual(records[1]["legacy_record_count"], 1)

    def test_new_records_have_valid_hash_links(self):
        ledger = ForensicAuditLedger(self.path)
        first = ledger.record_action("ACTION_ONE", "examiner", {}, "CASE-1")
        second = ledger.record_action("ACTION_TWO", "examiner", {}, "CASE-1")

        self.assertIn("entry_hash", first)
        self.assertIn("previous_hash", first)
        self.assertEqual(second["previous_hash"], first["entry_hash"])

        result = ledger.verify_integrity()
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["chained_record_count"], 2)

    def test_history_filters_by_case(self):
        ledger = ForensicAuditLedger(self.path)
        ledger.record_action("ACTION", "examiner", {}, "CASE-1")
        ledger.record_action("ACTION", "examiner", {}, "CASE-2")

        history = ledger.get_case_history("CASE-1")
        self.assertTrue(history)
        self.assertTrue(all(row.get("case_id") == "CASE-1" for row in history))

    def test_modified_record_is_detected(self):
        ledger = ForensicAuditLedger(self.path)
        ledger.record_action("ACTION", "examiner", {"value": 1}, "CASE-1")

        lines = self.path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[-1])
        record["details"]["value"] = 999
        lines[-1] = json.dumps(record)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = ledger.verify_integrity()
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])

        with self.assertRaises(ValueError):
            ledger.record_action("SHOULD_FAIL", "examiner", {}, "CASE-1")

    def test_malformed_json_is_reported(self):
        self.path.write_text("{bad json}\n", encoding="utf-8")
        result = ForensicAuditLedger(self.path).verify_integrity()
        self.assertFalse(result["valid"])
        self.assertTrue(any("Malformed JSONL" in error for error in result["errors"]))

    def test_acquisition_uses_shared_hash_chain(self):
        artifact = self.root / "evidence.bin"
        artifact.write_bytes(b"sample evidence")

        record = AcquisitionHasher.register_artifact(
            artifact,
            case_id="CASE-ACQ",
            ledger_path=self.path,
        )

        self.assertIn("sha256", record["hashes"])
        self.assertIn("sha3_256", record["hashes"])
        self.assertIn("entry_hash", record)
        self.assertTrue(ForensicAuditLedger(self.path).verify_integrity()["valid"])

        history = ForensicAuditLedger(self.path).get_case_history("CASE-ACQ")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["filename"], "evidence.bin")

    def test_legacy_file_without_trailing_newline(self):
        legacy = {
            "record_id": "legacy-no-newline",
            "case_id": "CASE-1",
    }
        original_bytes = json.dumps(legacy).encode("utf-8")
        self.path.write_bytes(original_bytes)

        ledger = ForensicAuditLedger(self.path)
        ledger.record_action("TEST_ACTION", "examiner", {}, "CASE-1")

        content = self.path.read_bytes()
        self.assertTrue(content.startswith(original_bytes + b"\n"))

        status = ledger.verify_integrity()
        self.assertTrue(status["valid"], status["errors"])

        records = [
            json.loads(line)
            for line in content.splitlines()
            if line.strip()
        ]
        checkpoint = records[1]

        self.assertEqual(
            checkpoint["legacy_prefix_bytes"],
            len(original_bytes),
        )
        self.assertEqual(
            checkpoint["legacy_prefix_sha256"],
            __import__("hashlib").sha256(original_bytes).hexdigest(),
        )

    def test_concurrent_appends_preserve_hash_chain(self):
        from concurrent.futures import ThreadPoolExecutor

        ledger = ForensicAuditLedger(self.path)
        total = 20

        def append_one(i):
            return ledger.record_action(
                "CONCURRENT",
                "examiner",
                {"index": i},
                "CASE-CONCURRENT",
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(append_one, range(total)))

        status = ledger.verify_integrity()
        self.assertTrue(status["valid"], status["errors"])

        history = ledger.get_case_history("CASE-CONCURRENT")
        self.assertEqual(len(history), total)
        self.assertEqual(
            len({row["entry_id"] for row in history}),
            total,
        )
if __name__ == "__main__":
    unittest.main()
