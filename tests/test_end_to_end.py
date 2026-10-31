"""
Comprehensive End-to-End Test Suite for Sutra-Net Forensics Engine
Tests all 4 architectural layers:
- Layer 1: Ingestion & Cryptographic Hashes (SHA-256, SHA-3)
- Layer 2: Columnar Parquet Storage & DuckDB Queries
- Layer 3: AI Threat Triage (NetSpectra ML + Chitra NLP + Knowledge Graph)
- Layer 4: Judicial Admissibility (BSA Section 63 Certificate & Audit Ledger)
"""

import unittest
from pathlib import Path
import os
import tempfile
import json

from sutra_net.config import SAMPLE_DATA_DIR, DATA_DIR, CERTIFICATES_DIR
from sutra_net.ingest.hasher import AcquisitionHasher
from sutra_net.ingest.pcap_parser import PcapParser
from sutra_net.ingest.mobile_parser import MobileParser
from sutra_net.ingest.evtx_parser import LogParser
from sutra_net.storage.parquet_engine import ParquetEngine
from sutra_net.storage.query_engine import ForensicQueryEngine
from sutra_net.storage.inverted_index import InvertedIndex
from sutra_net.ai.netspectra_ml import NetSpectraML
from sutra_net.ai.chitra_nlp import ChitraNLP
from sutra_net.ai.graph_builder import ForensicKnowledgeGraph
from sutra_net.compliance.bsa_section63 import BSASection63Certificate
from sutra_net.compliance.audit_ledger import ForensicAuditLedger


class TestSutraNetPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pcap_file = SAMPLE_DATA_DIR / "sample_network.pcap"
        cls.mobile_file = SAMPLE_DATA_DIR / "sample_msgstore.db"
        cls.log_file = SAMPLE_DATA_DIR / "sample_syslog.log"

    def test_01_acquisition_hasher(self):
        """Validates Layer 1 cryptographic hashing and ledger recording."""
        with tempfile.TemporaryDirectory() as temp_dir:
            record = AcquisitionHasher.register_artifact(
                self.pcap_file,
                case_id="TEST-CASE-01",
                notes="Unit Test PCAP",
                ledger_path=Path(temp_dir) / "audit_ledger.jsonl",
            )
        self.assertIn("sha256", record["hashes"])
        self.assertIn("sha3_256", record["hashes"])
        self.assertEqual(len(record["hashes"]["sha256"]), 64)
        self.assertEqual(len(record["hashes"]["sha3_256"]), 64)

        # Integrity check
        is_valid = AcquisitionHasher.verify_integrity(self.pcap_file, record["hashes"]["sha256"])
        self.assertTrue(is_valid)

    def test_02_pcap_parsing(self):
        """Validates PCAP packet and flow extraction."""
        parser = PcapParser(self.pcap_file)
        result = parser.parse()
        self.assertGreater(result["total_packets"], 0)
        self.assertGreater(result["total_flows"], 0)
        self.assertIn("flows", result)
        self.assertIn("packets", result)

    def test_03_mobile_database_parsing(self):
        """Validates WhatsApp SQLite extraction."""
        parser = MobileParser(self.mobile_file)
        messages = parser.parse_whatsapp()
        self.assertGreater(len(messages), 0)
        self.assertTrue(any("loan" in m["text"].lower() for m in messages))

    def test_04_parquet_storage_and_duckdb(self):
        """Validate Parquet queries using isolated temporary storage."""
        parser = PcapParser(self.pcap_file)
        flows = parser.parse()["flows"]

        with tempfile.TemporaryDirectory() as temp_dir:
            store = Path(temp_dir)

            engine = ParquetEngine(base_dir=store)
            pq_path = engine.write_records(
                flows, "flows", case_id="TEST-CASE-01"
            )
            self.assertTrue(pq_path.exists())

            query_engine = ForensicQueryEngine(base_dir=store)
            result = query_engine.query_flows(limit=10)

            self.assertTrue(result["success"], result)
            self.assertGreater(result["row_count"], 0)
            self.assertLess(result["execution_ms"], 500.0)

            # Confirm this test wrote exactly one temporary Parquet shard.
            shards = list((store / "flows").glob("*.parquet"))
            self.assertEqual(len(shards), 1)


    def test_05_netspectra_ml_triage(self):
        """Validates Layer 3A Encrypted C2 beacon detection."""
        parser = PcapParser(self.pcap_file)
        flows = parser.parse()["flows"]

        ml = NetSpectraML()
        triaged = ml.triage_flows(flows)
        self.assertGreater(len(triaged), 0)

        # Ensure the periodic C2 beacon was flagged
        malicious_flows = [f for f in triaged if f["is_malicious"]]
        self.assertGreater(len(malicious_flows), 0)
        c2 = malicious_flows[0]
        self.assertIn("C2", c2["threat_type"])

    def test_06_chitra_nlp_fraud_and_entities(self):
        """Validates Layer 3B Hinglish fraud classification and UPI extraction."""
        parser = MobileParser(self.mobile_file)
        messages = parser.parse_whatsapp()

        nlp = ChitraNLP()
        triaged = nlp.triage_messages(messages)
        flagged = [m for m in triaged if m["is_flagged"]]
        self.assertGreater(len(flagged), 0)

        # Check extracted UPI VPAs
        all_upis = []
        for m in triaged:
            all_upis.extend(m["entities"]["upi_vpas"])
        self.assertTrue(any("oksbi" in u or "paytm" in u for u in all_upis))

    def test_07_forensic_knowledge_graph(self):
        """Validates Knowledge Graph construction and mule account detection."""
        parser = MobileParser(self.mobile_file)
        messages = parser.parse_whatsapp()
        nlp = ChitraNLP()
        triaged_msgs = nlp.triage_messages(messages)

        kg = ForensicKnowledgeGraph()
        kg.ingest_mobile_entities(triaged_msgs)

        mules = kg.find_mule_accounts()
        self.assertGreater(len(mules), 0)

        cy_json = kg.to_cytoscape_json()
        self.assertGreater(cy_json["node_count"], 0)
        self.assertGreater(cy_json["edge_count"], 0)

    def test_08_bsa_section63_certification(self):
        """Validates Layer 4 BSA Section 63 PDF & JSON certificate generation."""
        cert_gen = BSASection63Certificate()
        manifest = {
            "filename": "sample_network.pcap",
            "file_size_bytes": 10240,
            "hashes": {
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "sha3_256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            },
            "acquired_utc": "2026-10-18T22:30:00Z"
        }
        res = cert_gen.generate_certificate(
            case_id="TEST-CERT-01",
            evidence_manifest=manifest,
            examiner_name="Inspector Rajesh Kumar",
            agency_name="State Forensic Science Laboratory",
            key_findings=["Confirmed Cobalt Strike C2 beacon on port 8443."]
        )
        self.assertTrue(Path(res["pdf_path"]).exists())
        self.assertTrue(Path(res["json_path"]).exists())
        self.assertGreater(Path(res["pdf_path"]).stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
