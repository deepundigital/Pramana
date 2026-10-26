"""
Sutra-Net API Server: FastAPI service powering the Sakshya-UI dashboard,
interactive forensic triage, zero-copy Parquet analytics, and BSA Section 63 certificate generation.
"""

import base64
import binascii
import hmac
import os
from pathlib import Path
from typing import Dict, Any, Optional, List, Literal
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

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

_AUTH_REALM = "Sutra-Net Forensics"


@app.middleware("http")
async def require_authentication(request, call_next):
    """Require environment-configured HTTP Basic Authentication on every route."""

    expected_username = os.environ.get("SUTRA_AUTH_USERNAME")
    expected_password = os.environ.get("SUTRA_AUTH_PASSWORD")

    # Fail closed: never silently run without configured credentials.
    if not expected_username or not expected_password:
        return JSONResponse(
            status_code=503,
            content={"detail": "Server authentication is not configured."},
        )

    # Static assets contain no evidence or credentials.
    # Keep all API endpoints protected by authentication.
    if request.url.path.startswith("/static/"):
        return await call_next(request)

    def unauthorized():
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required."},
            headers={
                "WWW-Authenticate":
                    f'Basic realm="{_AUTH_REALM}", charset="UTF-8"'
            },
        )

    header = request.headers.get("authorization", "")
    scheme, separator, encoded = header.partition(" ")

    if scheme.lower() != "basic" or not separator or not encoded:
        return unauthorized()

    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return unauthorized()

    if ":" not in decoded:
        return unauthorized()

    supplied_username, supplied_password = decoded.split(":", 1)
    username_matches = hmac.compare_digest(
        supplied_username, expected_username
    )
    password_matches = hmac.compare_digest(
        supplied_password, expected_password
    )

    if not (username_matches and password_matches):
        return unauthorized()

    return await call_next(request)


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
    model_config = ConfigDict(extra="forbid")

    query_id: str = Field(min_length=1, max_length=64)
    limit: int = Field(default=20, ge=1, le=100)


class CertificateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    case_id: str = Field(
        default="CASE-2026-SUTRAM-DEMO",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
    )
    examiner_name: str = Field(min_length=1, max_length=120)
    agency_name: str = Field(min_length=1, max_length=160)
    artifact_name: Literal[
        "sample_network.pcap",
        "sample_msgstore.db",
    ] = "sample_network.pcap"


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
    """Runs an approved, bounded forensic query."""
    return query_engine.run_saved_query(req.query_id, req.limit)


@app.post("/api/compliance/certificate")
async def generate_certificate(req: CertificateRequest):
    """Generate a certificate draft from a recorded, verified acquisition."""

    sample_root = SAMPLE_DATA_DIR.resolve()
    artifact_path = (sample_root / req.artifact_name).resolve()

    # Only the explicitly supported sample evidence files are accepted.
    if artifact_path.parent != sample_root or not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence artifact not found.")

    # Require a prior acquisition record for this exact case and artifact.
    records = audit_ledger.get_case_history(req.case_id)
    acquisition = None

    for record in records:
        if record.get("filename") != req.artifact_name:
            continue
        if not record.get("file_path") or not record.get("hashes"):
            continue
        try:
            recorded_path = Path(record["file_path"]).resolve()
        except (OSError, TypeError, ValueError):
            continue

        if recorded_path == artifact_path and record.get("acquired_utc"):
            acquisition = record
            break

    if acquisition is None:
        raise HTTPException(
            status_code=409,
            detail=(
                "No matching acquisition record exists for this case and artifact. "
                "Ingest the evidence first and use the corresponding case ID."
            ),
        )

    try:
        current_hashes = AcquisitionHasher.hash_file(artifact_path)
    except OSError:
        raise HTTPException(status_code=500, detail="Could not verify evidence integrity.")

    recorded_hashes = acquisition["hashes"]
    algorithms = ("sha256", "sha3_256")

    if any(
        not recorded_hashes.get(name)
        or current_hashes.get(name) != recorded_hashes.get(name)
        for name in algorithms
    ):
        raise HTTPException(
            status_code=409,
            detail="Evidence hash mismatch. Certificate generation was refused.",
        )

    evidence_manifest = {
        "filename": artifact_path.name,
        "file_size_bytes": artifact_path.stat().st_size,
        "hashes": recorded_hashes,
        "acquired_utc": acquisition["acquired_utc"],
        "integrity_verified_at_generation": True,
        "integrity_verified_hashes": current_hashes,
        "acquisition_examiner": acquisition.get("examiner_name"),
    }

    # Do not insert fabricated findings into a forensic certificate.
    cert_paths = cert_generator.generate_certificate(
        case_id=req.case_id,
        evidence_manifest=evidence_manifest,
        examiner_name=req.examiner_name,
        agency_name=req.agency_name,
        key_findings=[],
    )

    return {
        "status": "success",
        "pdf_download_url": (
            f"/api/compliance/download_pdf?path="
            f"{Path(cert_paths['pdf_path']).name}"
        ),
        # Return names, not internal filesystem paths.
        "paths": {
            "pdf_path": Path(cert_paths["pdf_path"]).name,
            "json_path": Path(cert_paths["json_path"]).name,
        },
    }


@app.get("/api/compliance/download_pdf")
async def download_certificate_pdf(path: str):
    """Download a PDF located directly in the certificate directory."""

    base_dir = CERTIFICATES_DIR.resolve()

    # Reject directory components, absolute paths and traversal attempts.
    if not path or Path(path).name != path or path in {".", ".."}:
        raise HTTPException(status_code=404, detail="Certificate file not found.")

    full_path = (base_dir / path).resolve()

    # Resolve symlinks before checking containment.
    if (
        full_path.parent != base_dir
        or full_path.suffix.lower() != ".pdf"
        or not full_path.is_file()
    ):
        raise HTTPException(status_code=404, detail="Certificate file not found.")

    return FileResponse(
        full_path,
        media_type="application/pdf",
        filename=full_path.name,
    )
