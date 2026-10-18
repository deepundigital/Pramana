"""
Parquet Columnar Storage Engine: Converts heterogeneous normalized evidence into
compressed, partitioned Apache Parquet files using PyArrow.
"""

import os
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

import pyarrow as pa
import pyarrow.parquet as pq
import pandas as pd

from sutra_net.config import PARQUET_STORE


class ParquetEngine:
    """
    Manages high-speed ingestion and serialization into columnar Apache Parquet format.
    """

    def __init__(self, base_dir: Path = PARQUET_STORE):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def write_records(
        self,
        records: List[Dict[str, Any]],
        artifact_type: str,
        case_id: str = "CASE-2026-SUTRAM"
    ) -> Path:
        """
        Serializes a list of dictionaries into a partitioned Parquet file.
        """
        if not records:
            raise ValueError("Cannot write empty records to Parquet.")

        df = pd.DataFrame(records)
        df["case_id"] = case_id
        df["ingested_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Target directory partitioned by artifact_type
        target_dir = self.base_dir / artifact_type
        target_dir.mkdir(parents=True, exist_ok=True)

        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        target_file = target_dir / f"{case_id}_{timestamp_str}.parquet"

        table = pa.Table.from_pandas(df)
        pq.write_table(table, target_file, compression="snappy")

        return target_file

    def get_parquet_files(self, artifact_type: Optional[str] = None) -> List[str]:
        """
        Returns all Parquet file paths for a specific artifact type or across all types.
        """
        if artifact_type:
            pattern = self.base_dir / artifact_type / "*.parquet"
            return [str(p) for p in self.base_dir.glob(f"{artifact_type}/*.parquet")]
        else:
            return [str(p) for p in self.base_dir.glob("**/*.parquet")]
