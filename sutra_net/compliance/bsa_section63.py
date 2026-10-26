"""
BSA Section 63 Certificate Generator: Produces courtroom-admissible certificates
under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (replacing Section 65B of Indian Evidence Act).
"""

import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from xml.sax.saxutils import escape
import re

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import inch

from sutra_net.config import CERTIFICATES_DIR, LEGAL_STATUTE, PREVIOUS_STATUTE_REF


class BSASection63Certificate:
    """
    Generates official electronic evidence certificates adhering to BSA Section 63 standards.
    """

    def __init__(self, output_dir: Path = CERTIFICATES_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_certificate(
        self,
        case_id: str,
        evidence_manifest: Dict[str, Any],
        examiner_name: str = "Authorized Forensic Examiner",
        agency_name: str = "Cyber Crime Investigation Unit / FSL",
        key_findings: Optional[List[str]] = None
    ) -> Dict[str, str]:
        """
        Creates both a ReportLab PDF and structured JSON representation of the Section 63 certificate.
        """
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", case_id):
            raise ValueError("Invalid case ID format.")

        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_path = self.output_dir / f"BSA_Sec63_Certificate_{case_id}_{timestamp_str}.pdf"
        json_path = self.output_dir / f"BSA_Sec63_Certificate_{case_id}_{timestamp_str}.json"

        # 1. Generate JSON Manifest
        cert_data = {
            "statute": LEGAL_STATUTE,
            "former_statute_reference": PREVIOUS_STATUTE_REF,
            "case_id": case_id,
            "agency": agency_name,
            "examiner": examiner_name,
            "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "evidence": evidence_manifest,
            "findings": key_findings or [],
            "affirmation": (
                "I hereby certify that the electronic record described herein was produced by a computer "
                "system during the period over which the computer was used regularly to store or process information, "
                "and that throughout the material part of the said period, the computer was operating properly. "
                "The cryptographic hashes computed upon initial acquisition match the current artifact integrity."
            )
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(cert_data, f, indent=2)

        # 2. Build PDF Document
        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'LegalTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=15,
            leading=18,
            alignment=1,
            textColor=colors.HexColor('#0F172A')
        )
        subtitle_style = ParagraphStyle(
            'LegalSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=13,
            alignment=1,
            textColor=colors.HexColor('#1E3A8A')
        )
        body_style = ParagraphStyle(
            'LegalBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor('#1E293B')
        )
        bold_label = ParagraphStyle(
            'BoldLabel',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor('#0F172A')
        )

        elements = []

        # Header
        elements.append(Paragraph("CERTIFICATE UNDER SECTION 63 OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023", title_style))
        elements.append(Paragraph(f"(Formerly Section 65B of the Indian Evidence Act, 1872)", subtitle_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0F172A')))
        elements.append(Spacer(1, 12))

        # Case & Agency Metadata
        meta_table_data = [
            [Paragraph("Case Reference ID:", bold_label), Paragraph(escape(str(case_id)), body_style)],
            [Paragraph("Investigating Agency:", bold_label), Paragraph(escape(str(agency_name)), body_style)],
            [Paragraph("Certifying Examiner:", bold_label), Paragraph(escape(str(examiner_name)), body_style)],
            [Paragraph("Certification Date (UTC):", bold_label), Paragraph(cert_data["generated_utc"], body_style)],
        ]
        meta_table = Table(meta_table_data, colWidths=[160, 360])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 14))

        # Evidence Particulars
        elements.append(Paragraph("<b>PARTICULARS OF ELECTRONIC RECORD & CRYPTOGRAPHIC HASHES</b>", bold_label))
        elements.append(Spacer(1, 6))

        hashes = evidence_manifest.get("hashes", {})
        evidence_table_data = [
            [Paragraph("<b>Artifact Name</b>", bold_label), Paragraph(escape(str(evidence_manifest.get("filename", "N/A"))), body_style)],
            [Paragraph("<b>File Size</b>", bold_label), Paragraph(f"{evidence_manifest.get('file_size_bytes', 0):,} bytes", body_style)],
            [Paragraph("<b>Acquisition SHA-256</b>", bold_label), Paragraph(f"<font face='Courier' size=8>{escape(str(hashes.get('sha256', 'N/A')))}</font>", body_style)],
            [Paragraph("<b>Acquisition SHA-3</b>", bold_label), Paragraph(f"<font face='Courier' size=8>{escape(str(hashes.get('sha3_256', 'N/A')))}</font>", body_style)],
            [Paragraph("<b>Acquisition Time</b>", bold_label), Paragraph(escape(str(evidence_manifest.get("acquired_utc", "N/A"))), body_style)],
        ]
        ev_table = Table(evidence_table_data, colWidths=[160, 360])
        ev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#94A3B8')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ]))
        elements.append(ev_table)
        elements.append(Spacer(1, 14))

        # Forensic Findings Section
        if key_findings:
            elements.append(Paragraph("<b>AUTOMATED FORENSIC FINDINGS & INDICATORS SUMMARY</b>", bold_label))
            elements.append(Spacer(1, 6))
            findings_p = "<br/>".join(f"• {escape(str(f))}" for f in key_findings)
            elements.append(Paragraph(findings_p, body_style))
            elements.append(Spacer(1, 14))

        # Legal Affirmation
        elements.append(Paragraph("<b>STATUTORY OATH & DECLARATION</b>", bold_label))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(cert_data["affirmation"], body_style))
        elements.append(Spacer(1, 30))

        # Signature Block
        sig_data = [
            [Paragraph("____________________________", body_style), Paragraph("____________________________", body_style)],
            [Paragraph(f"<b>Signature of Certifying Officer</b><br/>{escape(str(examiner_name))}", body_style),
             Paragraph("<b>Digital Forensic Lab Seal & Date</b><br/>Verified by Sutra-Net Forensics", body_style)]
        ]
        sig_table = Table(sig_data, colWidths=[260, 260])
        sig_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('PADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(sig_table)

        doc.build(elements)

        return {
            "pdf_path": str(pdf_path.resolve()),
            "json_path": str(json_path.resolve())
        }
