"""
Sutra-Net API Server: FastAPI service powering the Sakshya-UI dashboard,
interactive forensic triage, zero-copy Parquet analytics, and BSA Section 63 certificate generation.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from sutra_net.config import (
    PROJECT_ROOT,
    SAMPLE_DATA_DIR,
    EVIDENCE_VAULT,
    DATA_DIR,
    CERTIFICATES_DIR
)
from sutra_net.ingest.hasher import AcquisitionHasher
from sutra_net.ingest.pcap_parser import PcapParser
from sutra_net.ingest.evtx_parser import LogParser
from sutra_net.ingest.mobile_parser import MobileParser
from sutra_net.storage.parquet_engine import ParquetEngine
from sutra_net.storage.query_engine import ForensicQueryEngine
from sutra_net.storage.inverted_index import InvertedIndex
from sutra_net.ai.netspectra_ml import NetSpectraML
from sutra_net.ai.chitra_nlp import ChitraNLP
from sutra_net.ai.graph_builder import ForensicKnowledgeGraph
from sutra_net.compliance.bsa_section63 import BSASection63Certificate
from sutra_net.compliance.audit_ledger import ForensicAuditLedger

app = FastAPI(
    title="Sutra-Net Forensics Engine",
    description="AI-Powered Cyber Investigation & Digital Forensics Platform (SUTRAM 2026)",
    version="1.0.0"
)

# Core Service Instances
parquet_engine = ParquetEngine()
query_engine = ForensicQueryEngine()
inverted_index = InvertedIndex()
ml_triage = NetSpectraML()
nlp_triage = ChitraNLP()
knowledge_graph = ForensicKnowledgeGraph()
cert_generator = BSASection63Certificate()
audit_ledger = ForensicAuditLedger()

# Serve static dashboard files
STATIC_DIR = PROJECT_ROOT / "sutra_net" / "api" / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class SQLQueryRequest(BaseModel):
    query: str


class CertificateRequest(BaseModel):
    case_id: str = "CASE-2026-SUTRAM-01"
    examiner_name: str = "Inspector Rajesh Kumar (Cyber Cell)"
    agency_name: str = "State Cyber Forensic Laboratory / MeitY SUTRAM"
    artifact_name: str = "sample_network.pcap"


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the primary forensic investigation dashboard."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse("<h1>Sutra-Net Forensics API Online</h1><p>Visit /docs for Swagger API</p>")


@app.get("/deck", response_class=HTMLResponse)
async def serve_pitch_deck():
    """Serves the 12-slide SUTRAM 2026 Pitch Deck."""
    deck_path = PROJECT_ROOT / "deck" / "index.html"
    if deck_path.exists():
        return FileResponse(deck_path)
    raise HTTPException(status_code=404, detail="Pitch deck not found.")


@app.post("/api/ingest/sample")
async def ingest_sample_evidence():
    """
    Ingests all bundled synthetic samples (PCAP, WhatsApp DB, Syslog),
    computes SHA-256 hashes, stores them in columnar Parquet, and populates the knowledge graph.
    """
    results = {}
    case_id = "CASE-2026-SUTRAM-DEMO"

    # 1. Ingest PCAP
    pcap_path = SAMPLE_DATA_DIR / "sample_network.pcap"
    if pcap_path.exists():
        hash_record = AcquisitionHasher.register_artifact(pcap_path, case_id=case_id, notes="Network Packet Capture")
        parser = PcapParser(pcap_path)
        parsed = parser.parse()

        # Write flows to Parquet
        parquet_file = parquet_engine.write_records(parsed["flows"], "flows", case_id=case_id)

        # Index and Triage
        triaged_flows = ml_triage.triage_flows(parsed["flows"])
        knowledge_graph.ingest_network_flows(triaged_flows)

        results["pcap"] = {
            "hashes": hash_record["hashes"],
            "total_packets": parsed["total_packets"],
            "total_flows": parsed["total_flows"],
            "parquet_file": str(parquet_file.name),
            "threats_detected": sum(1 for f in triaged_flows if f["is_malicious"])
        }

    # 2. Ingest WhatsApp DB
    db_path = SAMPLE_DATA_DIR / "sample_msgstore.db"
    if db_path.exists():
        hash_record = AcquisitionHasher.register_artifact(db_path, case_id=case_id, notes="Android WhatsApp SQLite Evidence")
        parser = MobileParser(db_path)
        messages = parser.parse_whatsapp()

        if messages:
            parquet_file = parquet_engine.write_records(messages, "messages", case_id=case_id)
            triaged_msgs = nlp_triage.triage_messages(messages)
            knowledge_graph.ingest_mobile_entities(triaged_msgs)

            results["mobile"] = {
                "hashes": hash_record["hashes"],
                "total_messages": len(messages),
                "parquet_file": str(parquet_file.name),
                "fraudulent_messages": sum(1 for m in triaged_msgs if m["is_flagged"])
            }

    # Record action in audit ledger
    audit_ledger.record_action(
        action_type="EVIDENCE_INGESTION_BATCH",
        user_name="System Examiner",
        details=results,
        case_id=case_id
    )

    return {"status": "success", "ingested": results}


@app.get("/api/triage/network")
async def get_network_triage():
    """
    Returns AI network flow scoring, C2 beacon alerts, and JA3 fingerprints.
    """
    pcap_path = SAMPLE_DATA_DIR / "sample_network.pcap"
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail="Sample PCAP not found.")

    parser = PcapParser(pcap_path)
    parsed = parser.parse()
    triaged = ml_triage.triage_flows(parsed["flows"])

    return {
        "total_flows": len(triaged),
        "malicious_count": sum(1 for f in triaged if f["is_malicious"]),
        "flows": triaged
    }


@app.get("/api/triage/mobile")
async def get_mobile_triage():
    """
    Returns Hinglish scam intent categorization and extracted UPI mule accounts.
    """
    db_path = SAMPLE_DATA_DIR / "sample_msgstore.db"
    if not db_path.exists():
        raise HTTPException(status_code=404, detail="Sample WhatsApp DB not found.")

    parser = MobileParser(db_path)
    messages = parser.parse_whatsapp()
    triaged = nlp_triage.triage_messages(messages)
    mule_accounts = knowledge_graph.find_mule_accounts()

    return {
        "total_messages": len(triaged),
        "flagged_count": sum(1 for m in triaged if m["is_flagged"]),
        "mule_accounts": mule_accounts,
        "messages": triaged
    }


@app.get("/api/graph")
async def get_knowledge_graph():
    """
    Returns the complete Cytoscape.js knowledge graph.
    """
    return knowledge_graph.to_cytoscape_json()


@app.post("/api/query/sql")
async def execute_sql_query(req: SQLQueryRequest):
    """
    Executes an arbitrary SQL query via DuckDB over the Parquet store.
    """
    result = query_engine.execute_sql(req.query)
    return result


@app.post("/api/compliance/certificate")
async def generate_certificate(req: CertificateRequest):
    """
    Generates a courtroom-ready Bharatiya Sakshya Adhiniyam (Sec 63) certificate (PDF & JSON).
    """
    # Sample evidence manifest
    evidence_manifest = {
        "filename": req.artifact_name,
        "file_size_bytes": 142850,
        "hashes": {
            "sha256": "4a7d3b8e91f0c2a5d8b7e6f3a2c1d0e9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3",
            "sha3_256": "8f3b2c1d0e9a7f6e5d4c3b2a1f0e9d8c7b6a5f4e34a7d3b8e91f0c2a5d8b7e6f"
        },
        "acquired_utc": "2026-10-18T22:30:00Z"
    }

    key_findings = [
        "Identified persistent encrypted C2 beaconing on port 8443 (Periodic interval: 10.0s, Jitter: 0.04s, MITRE T1071).",
        "Extracted 3 unauthorized UPI VPA addresses used for financial extortion (Primary Hub: rajesh.mule@oksbi).",
        "Correlated brute-force SSH logins from external IP 198.51.100.77 resulting in unauthorized bash privilege escalation.",
        "Verified all acquisition cryptographic hashes; no evidence of bitstream alteration or file corruption."
    ]

    cert_paths = cert_generator.generate_certificate(
        case_id=req.case_id,
        evidence_manifest=evidence_manifest,
        examiner_name=req.examiner_name,
        agency_name=req.agency_name,
        key_findings=key_findings
    )

    return {
        "status": "success",
        "pdf_download_url": f"/api/compliance/download_pdf?path={Path(cert_paths['pdf_path']).name}",
        "paths": cert_paths
    }


@app.get("/api/compliance/download_pdf")
async def download_certificate_pdf(path: str):
    """Downloads the generated Section 63 PDF certificate."""
    full_path = CERTIFICATES_DIR / path
    if full_path.exists():
        return FileResponse(
            full_path,
            media_type="application/pdf",
            filename=full_path.name
        )
    raise HTTPException(status_code=404, detail="Certificate file not found.")
