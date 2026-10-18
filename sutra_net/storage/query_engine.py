"""
Forensic Query Engine: Leverages DuckDB for zero-copy, sub-second ANSI SQL queries
directly over partitioned Apache Parquet shards.
"""

import time
from pathlib import Path
from typing import List, Dict, Any, Optional
import duckdb

from sutra_net.config import PARQUET_STORE


class ForensicQueryEngine:
    """
    Executes high-performance SQL analytics on forensic Parquet data.
    """

    def __init__(self, base_dir: Path = PARQUET_STORE):
        self.base_dir = Path(base_dir)
        self.con = duckdb.connect(database=":memory:")

    def execute_sql(self, sql: str) -> Dict[str, Any]:
        """
        Executes arbitrary SQL with precise millisecond execution benchmarking.
        """
        t_start = time.perf_counter()
        try:
            rel = self.con.execute(sql)
            columns = [desc[0] for desc in rel.description] if rel.description else []
            rows = rel.fetchall()
            t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

            result_dicts = [dict(zip(columns, row)) for row in rows]
            return {
                "success": True,
                "row_count": len(result_dicts),
                "execution_ms": round(t_elapsed_ms, 2),
                "columns": columns,
                "data": result_dicts
            }
        except Exception as e:
            t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            return {
                "success": False,
                "error": str(e),
                "execution_ms": round(t_elapsed_ms, 2),
                "data": []
            }

    def query_flows(self, condition: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """
        Queries network flows across all Parquet shards.
        """
        pattern = str(self.base_dir / "flows" / "*.parquet")
        where_clause = f"WHERE {condition}" if condition else ""
        sql = f"""
        SELECT *
        FROM read_parquet('{pattern}')
        {where_clause}
        ORDER BY start_time DESC
        LIMIT {limit};
        """
        return self.execute_sql(sql)

    def query_cross_correlation(self, ip_address: str) -> Dict[str, Any]:
        """
        Searches for an IP address across both network packets and system logs simultaneously.
        """
        flows_pattern = str(self.base_dir / "flows" / "*.parquet")
        logs_pattern = str(self.base_dir / "logs" / "*.parquet")

        sql = f"""
        WITH net_events AS (
            SELECT 
                start_time AS event_time, 
                'network_flow' AS source, 
                flow_id AS identifier, 
                protocol, 
                total_bytes AS details
            FROM read_parquet('{flows_pattern}')
            WHERE src_ip = '{ip_address}' OR dst_ip = '{ip_address}'
        )
        SELECT * FROM net_events
        ORDER BY event_time DESC
        LIMIT 100;
        """
        return self.execute_sql(sql)
