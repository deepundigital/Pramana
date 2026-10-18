"""
Inverted Index Engine: Indexes forensic entities (IPs, JA3s, UPI VPAs, Phone Numbers)
to provide O(1) multi-artifact cross-referencing and correlation.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Set
from collections import defaultdict

from sutra_net.config import DATA_DIR


class InvertedIndex:
    """
    Maintains an inverted index mapping forensic indicators to evidence locations.
    """

    def __init__(self, index_file: Path = DATA_DIR / "inverted_index.json"):
        self.index_file = Path(index_file)
        self.index: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
            "ip": defaultdict(list),
            "ja3": defaultdict(list),
            "upi_vpa": defaultdict(list),
            "phone": defaultdict(list),
            "domain": defaultdict(list)
        }
        self.load()

    def add_entry(
        self,
        entity_type: str,
        entity_val: str,
        artifact_type: str,
        parquet_file: str,
        record_id: Any,
        timestamp: Any
    ):
        """
        Adds a pointer for an entity to its exact location in Parquet shards.
        """
        if not entity_val or entity_type not in self.index:
            return

        normalized_val = entity_val.strip().lower()
        entry = {
            "artifact_type": artifact_type,
            "parquet_file": str(parquet_file),
            "record_id": record_id,
            "timestamp": timestamp
        }
        self.index[entity_type][normalized_val].append(entry)

    def lookup(self, entity_val: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Looks up an entity across all indexed types.
        """
        normalized = entity_val.strip().lower()
        results = {}
        for entity_type, mapping in self.index.items():
            if normalized in mapping:
                results[entity_type] = mapping[normalized]
        return results

    def save(self):
        """Persists the inverted index to disk."""
        serializable = {
            k: {v_key: v_val for v_key, v_val in v.items()}
            for k, v in self.index.items()
        }
        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)

    def load(self):
        """Loads index from disk if present."""
        if self.index_file.exists():
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k in self.index:
                        if k in data:
                            self.index[k] = defaultdict(list, data[k])
            except Exception:
                pass
