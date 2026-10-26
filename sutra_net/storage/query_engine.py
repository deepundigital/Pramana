"""
Restricted forensic query engine for DuckDB-backed Parquet evidence.
Only predefined, read-only queries are exposed to the API.
"""

import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import duckdb

from sutra_net.config import PARQUET_STORE


class ForensicQueryEngine:
    """Executes predefined queries over the configured Parquet store."""

    MAX_ROWS = 100

    def __init__(self, base_dir: Path = PARQUET_STORE):
        self.base_dir = Path(base_dir).resolve()
        self.con = duckdb.connect(database=":memory:")

    @staticmethod
    def _failure(message: str, elapsed_ms: float = 0.0) -> Dict[str, Any]:
        return {
            "success": False,
            "error": message,
            "execution_ms": round(elapsed_ms, 2),
            "row_count": 0,
            "columns": [],
            "data": [],
        }

    def _flows_pattern(self) -> str:
        # This path comes from trusted server configuration, not the request.
        pattern = (self.base_dir / "flows" / "*.parquet").as_posix()
        return pattern.replace("'", "''")

    def _run_trusted_query(
        self,
        sql: str,
        params: Sequence[Any] = (),
    ) -> Dict[str, Any]:
        started = time.perf_counter()

        try:
            cursor = self.con.execute(sql, list(params))
            columns = (
                [description[0] for description in cursor.description]
                if cursor.description
                else []
            )

            # All exposed queries have a bounded SQL LIMIT as well.
            rows = cursor.fetchmany(self.MAX_ROWS)
            data = [dict(zip(columns, row)) for row in rows]

            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return {
                "success": True,
                "row_count": len(data),
                "execution_ms": round(elapsed_ms, 2),
                "columns": columns,
                "data": data,
            }
        except Exception:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            # Avoid returning internal paths or raw database errors to clients.
            return self._failure(
                "Query failed. Verify that evidence has been ingested "
                "and the expected Parquet fields exist.",
                elapsed_ms,
            )

    def run_saved_query(
        self,
        query_id: str,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Run one of the explicitly approved query templates."""

        if query_id not in {"top_flows", "recent_flows"}:
            return self._failure("Unsupported query ID.")

        try:
            limit = int(limit)
        except (TypeError, ValueError):
            return self._failure("Limit must be an integer.")

        limit = max(1, min(limit, self.MAX_ROWS))
        pattern = self._flows_pattern()

        if query_id == "top_flows":
            sql = f"""
                SELECT flow_id, total_bytes, duration_sec,
                       mean_delta_sec, jitter_sec
                FROM read_parquet('{pattern}')
                ORDER BY total_bytes DESC NULLS LAST
                LIMIT ?
            """
        else:
            sql = f"""
                SELECT flow_id, src_ip, dst_ip, protocol,
                       total_bytes, duration_sec, start_time
                FROM read_parquet('{pattern}')
                ORDER BY start_time DESC NULLS LAST
                LIMIT ?
            """

        return self._run_trusted_query(sql, (limit,))

    def execute_sql(self, sql: str) -> Dict[str, Any]:
        """Reject arbitrary SQL, including calls from future API routes."""
        return self._failure(
            "Arbitrary SQL execution is disabled. Use run_saved_query()."
        )

    def query_flows(
        self,
        condition: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Return recent flows; caller-supplied SQL conditions are disabled."""

        if condition:
            return self._failure(
                "Custom SQL conditions are disabled. Use an approved query."
            )

        return self.run_saved_query("recent_flows", limit)

    def query_cross_correlation(
        self,
        ip_address: str,
    ) -> Dict[str, Any]:
        """Search flow endpoints using a parameterized IP address."""

        pattern = self._flows_pattern()
        sql = f"""
            SELECT start_time AS event_time,
                   'network_flow' AS source,
                   flow_id AS identifier,
                   protocol,
                   total_bytes AS details
            FROM read_parquet('{pattern}')
            WHERE src_ip = ? OR dst_ip = ?
            ORDER BY event_time DESC
            LIMIT 100
        """

        return self._run_trusted_query(
            sql,
            (ip_address, ip_address),
        )
