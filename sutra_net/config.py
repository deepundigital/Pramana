"""
Sutra-Net Forensics: Configuration & Global Constants
"""

import os
from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
EVIDENCE_VAULT = DATA_DIR / "evidence_vault"
PARQUET_STORE = DATA_DIR / "parquet_store"
AUDIT_LEDGER_PATH = DATA_DIR / "audit_ledger.jsonl"
CERTIFICATES_DIR = DATA_DIR / "certificates"
MODELS_DIR = PROJECT_ROOT / "sutra_net" / "ai" / "models"
SAMPLE_DATA_DIR = PROJECT_ROOT / "sample_data"

for path in [DATA_DIR, EVIDENCE_VAULT, PARQUET_STORE, CERTIFICATES_DIR, MODELS_DIR, SAMPLE_DATA_DIR]:
    path.mkdir(parents=True, exist_ok=True)

# Cryptographic Integrity
HASH_ALGORITHMS = ["sha256", "sha3_256"]

# Legal & Compliance Standards
LEGAL_STATUTE = "Bharatiya Sakshya Adhiniyam, 2023 (Section 63)"
PREVIOUS_STATUTE_REF = "Indian Evidence Act, 1872 (Section 65B)"
COMPLIANCE_ORGANIZATION = "Ministry of Electronics and Information Technology (MeitY) / NFSU"

# AI / ML Thresholds
ANOMALY_PERCENTILE_THRESHOLD = 95.0
C2_BEACONING_JITTER_THRESHOLD_SEC = 2.5
DNS_QUERY_ENTROPY_THRESHOLD = 3.8

# Indian UPI Ecosystem Patterns
COMMON_UPI_DOMAINS = [
    "okaxis", "okhdfcbank", "oksbi", "okicici", "paytm", "ybl", "ibl",
    "axl", "apl", "upi", "postbank", "federal", "airtel", "kotak"
]
UPI_VPA_REGEX = r'[a-zA-Z0-9.\-_]{2,256}@(?!gmail|yahoo|hotmail|outlook|proton)[a-zA-Z]{2,64}'
INDIAN_PHONE_REGEX = r'(?:\+91[\-\s]?)?[6789]\d{9}\b'
IFSC_REGEX = r'[A-Z]{4}0[A-Z0-9]{6}'
BANK_REF_REGEX = r'\b(?:UPI\/CR\/|IMPS\/|NEFT\/|UTR:?[\s]?|Txn:?[\s]?)\d{9,16}\b'

# Hinglish Scam Keywords & Indicators
HINGLISH_SCAM_PATTERNS = {
    "financial_coercion": [
        "police case hoga", "fir darj", "police complaint", "arrest warrant",
        "court notice", "jail bhejenge", "legal action", "cyber cell report",
        "account freeze", "giraftari", "police aayegi", "thana", "daroga"
    ],
    "urgency_otp": [
        "otp jaldi bhejo", "otp share karo", "turant payment karo", "warna block hoga",
        "last warning", "khatra hai", "abhi transfer karo", "jaldi karo", "pan card update karo",
        "sim block hoga", "kyc expire", "electricity cut", "bijli kat jayegi"
    ],
    "lottery_job_fraud": [
        "lottery jeeta", "lucky draw", "kaun banega crorepati", "kbc award",
        "part time job daily profit", "telegram task", "youtube like earn money",
        "ghar baithe kamaye", "bonus credit", "double paise", "crypto investment return"
    ]
}
