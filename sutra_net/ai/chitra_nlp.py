"""
Chitra-NLP: Indigenous Mobile Forensics & Hinglish Fraud Classifier
Specialized for Indian LEA scenarios: extracts UPI VPAs, phone numbers, IFSC codes,
and scores Hinglish transliterated chat/SMS dumps for financial coercion and OTP scams.
"""

import re
from typing import List, Dict, Any, Set
from collections import Counter

from sutra_net.config import (
    UPI_VPA_REGEX,
    INDIAN_PHONE_REGEX,
    IFSC_REGEX,
    BANK_REF_REGEX,
    HINGLISH_SCAM_PATTERNS
)


class ChitraNLP:
    """
    NLP engine for Indian mobile chat artifacts, supporting Hinglish scam categorization
    and forensic entity extraction.
    """

    def __init__(self):
        self.upi_pattern = re.compile(UPI_VPA_REGEX, re.IGNORECASE)
        self.phone_pattern = re.compile(INDIAN_PHONE_REGEX)
        self.ifsc_pattern = re.compile(IFSC_REGEX)
        self.bank_ref_pattern = re.compile(BANK_REF_REGEX, re.IGNORECASE)
        self.amount_pattern = re.compile(r'(?:₹|Rs\.?|INR)\s*([0-9,]+(?:\.[0-9]{2})?)', re.IGNORECASE)

    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        """
        Extracts key financial and communication identifiers from raw text.
        """
        if not text:
            return {
                "upi_vpas": [],
                "phone_numbers": [],
                "ifsc_codes": [],
                "bank_references": [],
                "amounts": []
            }

        # UPI VPAs
        raw_upis = self.upi_pattern.findall(text)
        upis = sorted(list(set(u.strip().lower() for u in raw_upis)))

        # Phones (normalize +91)
        raw_phones = self.phone_pattern.findall(text)
        phones = []
        for p in raw_phones:
            cleaned = re.sub(r'[\s\-+]', '', p)
            if cleaned.startswith("91") and len(cleaned) == 12:
                cleaned = cleaned[2:]
            if len(cleaned) == 10:
                phones.append(cleaned)
        phones = sorted(list(set(phones)))

        # IFSC
        ifscs = sorted(list(set(self.ifsc_pattern.findall(text))))

        # Bank Ref / UTR
        bank_refs = sorted(list(set(self.bank_ref_pattern.findall(text))))

        # Amounts
        amounts = sorted(list(set(self.amount_pattern.findall(text))))

        return {
            "upi_vpas": upis,
            "phone_numbers": phones,
            "ifsc_codes": ifscs,
            "bank_references": bank_refs,
            "amounts": amounts
        }

    def classify_hinglish_intent(self, text: str) -> Dict[str, Any]:
        """
        Scores message for fraud and extortion categories in Hinglish.
        """
        if not text:
            return {
                "fraud_score": 0.0,
                "primary_category": "BENIGN",
                "matched_indicators": [],
                "is_fraudulent": False
            }

        lower_text = text.lower()
        matched = []
        category_counts = Counter()

        for category, keywords in HINGLISH_SCAM_PATTERNS.items():
            for kw in keywords:
                if kw in lower_text:
                    matched.append(kw)
                    category_counts[category] += 1

        total_matches = len(matched)
        fraud_score = min(1.0, round(total_matches * 0.35, 2))

        primary_cat = category_counts.most_common(1)[0][0] if category_counts else "BENIGN"

        return {
            "fraud_score": fraud_score,
            "primary_category": primary_cat,
            "matched_indicators": matched,
            "is_fraudulent": (fraud_score >= 0.35)
        }

    def analyze_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Combines entity extraction and fraud categorization for an ingested chat/SMS record.
        """
        text = message.get("text", "")
        entities = self.extract_entities(text)
        intent = self.classify_hinglish_intent(text)

        return {
            "msg_id": message.get("msg_id"),
            "sender": message.get("sender"),
            "timestamp": message.get("datetime_utc") or message.get("timestamp_ms"),
            "text": text,
            "entities": entities,
            "fraud_analysis": intent,
            "is_flagged": intent["is_fraudulent"] or bool(entities["upi_vpas"])
        }

    def triage_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs batch analysis and sorts by fraud severity.
        """
        results = [self.analyze_message(m) for m in messages]
        results.sort(key=lambda x: x["fraud_analysis"]["fraud_score"], reverse=True)
        return results
